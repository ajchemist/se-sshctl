import Darwin
import Foundation

public struct IdentityCreateReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 2
    public let status = "created"
    public let hashType = CTKIdentityHashType.sha256
    public let hashEncoding = CTKIdentityHashEncoding.hex
    public let identity: CTKIdentity
}

public enum IdentityLifecycleError: Error, LocalizedError, Equatable {
    case invalidLabel
    case unsupportedKeyType
    case invalidProtection
    case invalidHash
    case unattendedSigningNotAcknowledged
    case operationBusy
    case commandFailed(String)
    case creationNotIdentified(Int)
    case createdIdentityMismatch
    case confirmationMismatch
    case deletionNotVerified

    public var errorDescription: String? {
        switch self {
        case .invalidLabel:
            "label must contain 1...128 characters and no control characters"
        case .unsupportedKeyType:
            "-k must be p-256-ne for an OpenSSH-compatible non-exportable Secure Enclave identity"
        case .invalidProtection:
            "-t must be bio or none"
        case .invalidHash:
            "CTK SHA-256 hash must be exactly 64 hexadecimal characters"
        case .unattendedSigningNotAcknowledged:
            "-t none requires --allow-unattended-signing"
        case .operationBusy:
            "another se-sshctl identity operation is running"
        case let .commandFailed(detail):
            "sc_auth failed" + (detail.isEmpty ? "" : ": \(detail)")
        case let .creationNotIdentified(count):
            "creation returned success but discovered \(count) new identities; no rollback was performed"
        case .createdIdentityMismatch:
            "new identity does not match the requested label, key type, and protection; no rollback was performed"
        case .confirmationMismatch:
            "--confirm must exactly match the selected CTK SHA-256 hash"
        case .deletionNotVerified:
            "sc_auth reported success but the identity is still present"
        }
    }
}

public struct IdentityCreator {
    private let executor: any SubprocessExecuting
    private let lockDirectory: URL

    public init(executor: any SubprocessExecuting, lockDirectory: URL? = nil) {
        self.executor = executor
        self.lockDirectory = lockDirectory ?? defaultLockDirectory
    }

    public func create(
        label: String,
        keyType: String,
        protection: String,
        allowUnattendedSigning: Bool
    ) throws -> IdentityCreateReport {
        try validateLabel(label)
        // sc_auth values arrive as argv strings; decode them once here so the
        // rest of the flow reasons about the concept, not the spelling.
        guard let keyType = CTKKeyType(rawValue: keyType), keyType.isOpenSSHCompatible else {
            throw IdentityLifecycleError.unsupportedKeyType
        }
        guard let protection = CTKProtection(rawValue: protection) else {
            throw IdentityLifecycleError.invalidProtection
        }
        guard protection != .none || allowUnattendedSigning else {
            throw IdentityLifecycleError.unattendedSigningNotAcknowledged
        }

        let lock = try OperationLock(directory: lockDirectory)
        defer { withExtendedLifetime(lock) {} }
        let before = try IdentityLister(executor: executor).list().identities
        try requireSuccess(executor.run(SubprocessRequest(
            executable: .scAuth,
            arguments: [
                "create-ctk-identity", "-l", label,
                "-k", keyType.rawValue, "-t", protection.rawValue,
            ],
            timeout: protection.creationTimeout
        )))
        let after = try IdentityLister(executor: executor).list().identities
        let oldHashes = Set(before.map { $0.ctkPublicKeyHash.uppercased() })
        let created = after.filter { !oldHashes.contains($0.ctkPublicKeyHash.uppercased()) }

        guard created.count == 1 else {
            throw IdentityLifecycleError.creationNotIdentified(created.count)
        }
        guard created[0].label == label,
              created[0].keyType == keyType,
              created[0].protection == protection else {
            throw IdentityLifecycleError.createdIdentityMismatch
        }
        return IdentityCreateReport(identity: created[0])
    }
}

/// What `identity delete` will destroy, shown before anything is destroyed.
///
/// The handoff requires the exact SSH fingerprint and the CTK SHA-256 selector
/// to be displayed and then approved, in that order. Running the command
/// without `--confirm` produces this and stops, so the operator approves
/// something they have actually seen rather than a hash they pasted.
public struct IdentityDeletionPlan: Encodable, Equatable, Sendable {
    public let schemaVersion = 1
    public let status = "planned"
    /// The stable selector. This is what `--confirm` must repeat.
    public let ctkSHA256: String
    /// sc_auth's own deletion locator, resolved here so the operator never has
    /// to pass a hash whose format differs from the one they selected with.
    public let ctkSHA1: String
    /// What a server sees. The only identifier that ties this key to an
    /// authorized_keys entry.
    public let sshFingerprint: String
    public let label: String
    public let keyType: CTKKeyType
    public let protection: CTKProtection
    /// Identity files this tool recorded for the key, which deletion also
    /// removes because they become handles to nothing.
    public let identityFiles: [String]
}

public struct IdentityDeleteReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 3
    public let status = "deleted"
    public let ctkSHA256: String
    public let ctkSHA1: String
    public let sshFingerprint: String
    public let removedFiles: [String]
    public let removedRecords: Int
    /// Recorded identity files left in place because the path no longer holds
    /// this key. Reported so nothing disappears silently and nothing unrelated
    /// is destroyed.
    public let keptFiles: [String]
}

/// Deletes one CTK identity and everything this tool knows that depended on it.
///
/// The plumbing underneath is exactly `sc_auth delete-ctk-identity -h SHA1`.
/// What this adds is the part `sc_auth` cannot do: select by the stable SHA-256
/// hash and resolve sc_auth's SHA-1 locator internally, refuse when the
/// metadata is ambiguous, show the SSH fingerprint before approval, confirm
/// absence afterwards in both hash formats, and then remove the identity file,
/// its `.pub`, and the verification record — which are handles and claims about
/// a key that no longer exists.
public struct IdentityDeleter {
    private let executor: any SubprocessExecuting
    private let manifestStore: VerificationManifestStore
    private let lockDirectory: URL

    public init(
        executor: any SubprocessExecuting,
        manifestStore: VerificationManifestStore,
        lockDirectory: URL? = nil
    ) {
        self.executor = executor
        self.manifestStore = manifestStore
        self.lockDirectory = lockDirectory ?? defaultLockDirectory
    }

    /// Resolves the identity and reports what deletion would destroy, without
    /// touching anything.
    public func plan(ctkSHA256 hash: String) throws -> IdentityDeletionPlan {
        let normalized = try normalizedCTKSHA256(hash)
        let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)
        return IdentityDeletionPlan(
            ctkSHA256: normalized,
            ctkSHA1: resolved.ctkSHA1Hash,
            sshFingerprint: resolved.sshFingerprint,
            label: resolved.identity.label,
            keyType: resolved.identity.keyType,
            protection: resolved.protection,
            identityFiles: try recordedIdentityFiles(for: normalized)
        )
    }

    public func delete(ctkSHA256 hash: String, confirmation: String) throws -> IdentityDeleteReport {
        let normalized = try normalizedCTKSHA256(hash)
        guard try normalizedCTKSHA256(confirmation) == normalized else {
            throw IdentityLifecycleError.confirmationMismatch
        }

        let lock = try OperationLock(directory: lockDirectory)
        defer { withExtendedLifetime(lock) {} }
        // Resolved under the lock: a concurrent create could otherwise shift
        // which row the SHA-1 locator refers to between plan and delete.
        let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)
        try requireSuccess(executor.run(SubprocessRequest(
            executable: .scAuth,
            arguments: ["delete-ctk-identity", "-h", resolved.ctkSHA1Hash],
            timeout: 30
        )))

        let remainingSHA1 = try IdentityLister(
            executor: executor, hashType: .sha1, hashEncoding: .hex
        ).list().identities
        let remainingSHA256 = try IdentityLister(executor: executor).list().identities
        guard !remainingSHA1.contains(where: { $0.ctkPublicKeyHash.uppercased() == resolved.ctkSHA1Hash }),
              !remainingSHA256.contains(where: { $0.ctkPublicKeyHash.uppercased() == normalized }) else {
            throw IdentityLifecycleError.deletionNotVerified
        }

        // The key is gone, so its records and identity files are now stale by
        // construction. Pruning here is what makes deletion complete rather
        // than a first step the operator has to remember to finish.
        let outcome = try manifestStore.prune(
            knownIdentityHashes: Set(remainingSHA256.map { $0.ctkPublicKeyHash.uppercased() })
        ) { entry in
            (try? readFingerprint(executor: executor, publicKeyPath: entry.identityFile + ".pub"))
                .flatMap { $0 } == entry.sshFingerprint
        }
        return IdentityDeleteReport(
            ctkSHA256: normalized,
            ctkSHA1: resolved.ctkSHA1Hash,
            sshFingerprint: resolved.sshFingerprint,
            removedFiles: outcome.removedFiles,
            removedRecords: outcome.removedRecords.count,
            keptFiles: outcome.keptFiles
        )
    }

    private func recordedIdentityFiles(for ctkSHA256: String) throws -> [String] {
        try manifestStore.load().identities
            .filter { $0.ctkSHA256 == ctkSHA256 }
            .map(\.identityFile)
    }
}

func sameIdentityMetadata(_ lhs: CTKIdentity, _ rhs: CTKIdentity) -> Bool {
    lhs.keyType == rhs.keyType
        && lhs.protection == rhs.protection
        && lhs.label == rhs.label
        && lhs.commonName == rhs.commonName
        && lhs.emailAddress == rhs.emailAddress
        && lhs.validTo == rhs.validTo
        && lhs.certificateValid == rhs.certificateValid
}

let defaultLockDirectory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("se-sshctl", isDirectory: true)

func normalizedCTKSHA256(_ hash: String) throws -> String {
    guard hash.range(of: #"^[0-9A-Fa-f]{64}$"#, options: .regularExpression) != nil else {
        throw IdentityLifecycleError.invalidHash
    }
    return hash.uppercased()
}

private func validateLabel(_ label: String) throws {
    guard (1...128).contains(label.count),
          !label.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
        throw IdentityLifecycleError.invalidLabel
    }
}

private func requireSuccess(_ result: SubprocessResult) throws {
    guard result.succeeded else {
        let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        throw IdentityLifecycleError.commandFailed(detail)
    }
}

private final class OperationLock {
    private let descriptor: Int32

    init(directory: URL) throws {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let path = directory.appendingPathComponent("operation.lock").path
        descriptor = Darwin.open(path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw IdentityLifecycleError.operationBusy }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            Darwin.close(descriptor)
            throw IdentityLifecycleError.operationBusy
        }
    }

    deinit {
        flock(descriptor, LOCK_UN)
        Darwin.close(descriptor)
    }
}

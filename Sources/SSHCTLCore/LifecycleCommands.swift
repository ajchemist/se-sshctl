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

import Foundation

/// Apple's OpenSSH security-key provider. Fixed, never user-configurable: a
/// caller-supplied provider path would defeat the signature checks below.
let providerPath = "/usr/lib/ssh-keychain.dylib"

public enum OperationalCommandError: Error, LocalizedError, Equatable {
    case invalidPath
    case invalidHostPattern
    case invalidSSHOption
    case invalidTag
    case identityFileExists
    case insecureDirectory
    case commandFailed(String)
    case identityFileNotFound
    case fingerprintMismatch
    case malformedPublicKey
    case signatureNotCreated
    case identityNotFound
    case identityMetadataAmbiguous
    case providerUntrusted
    case invalidPassphrase
    case malformedIdentityFile

    public var errorDescription: String? {
        switch self {
        case .invalidPath: "path must be non-empty and contain no control characters"
        case .invalidHostPattern: "host pattern must be non-empty and contain no control characters"
        case .invalidSSHOption: "--ssh-option must be non-empty and contain no control characters"
        case .invalidTag: "tag must be one word with no whitespace or control characters"
        case .identityFileExists: "identity file or its .pub file already exists"
        case .insecureDirectory: "identity-file directory must not be writable by group or other users"
        case let .commandFailed(detail): "OpenSSH command failed" + (detail.isEmpty ? "" : ": \(detail)")
        case .identityFileNotFound: "ssh-keygen did not produce a matching identity file"
        case .fingerprintMismatch: "identity file fingerprint does not match the selected CTK SHA-256 hash"
        case .malformedPublicKey: "identity file public key is malformed or has an unexpected key type"
        case .signatureNotCreated: "ssh-keygen returned success without creating a signature"
        case .identityNotFound: "identity was not found"
        case .identityMetadataAmbiguous: "identity metadata is duplicated; refusing to guess its CTK SHA-1 hash or SSH fingerprint"
        case .providerUntrusted: "Apple ssh-keychain provider is missing or failed signature verification"
        case .invalidPassphrase: "identity file passphrase must not contain NUL or line-break bytes"
        case .malformedIdentityFile: "identity file is not an OpenSSH private key container"
        }
    }
}

/// One CTK identity seen through all three identifier formats at once.
///
/// `sc_auth` prints only one format per invocation, so selecting by SHA-256
/// while addressing the provider by SHA-1 and matching an identity file by SSH
/// fingerprint means correlating three separate listings.
struct ResolvedIdentity {
    /// The CTK SHA-1/hex hash: `sc_auth`'s own deletion and provider-selection
    /// locator, passed to the provider through `KEYCHAIN_CERTIFICATES`.
    let ctkSHA1Hash: String
    let sshFingerprint: String
    let identityCount: Int
    /// The SHA-256 inventory row this resolution started from, so callers that
    /// must show the operator what they are about to act on have the label and
    /// parameters without a second listing.
    let identity: CTKIdentity

    var protection: CTKProtection { identity.protection }
}

struct IdentityResolver {
    let executor: any SubprocessExecuting

    func resolve(ctkSHA256: String) throws -> ResolvedIdentity {
        let sha256 = try IdentityLister(executor: executor, hashType: .sha256).list().identities
        guard let target = sha256.first(where: { $0.ctkPublicKeyHash.uppercased() == ctkSHA256 }) else {
            throw OperationalCommandError.identityNotFound
        }
        let sha1 = try IdentityLister(executor: executor, hashType: .sha1).list().identities
            .filter { sameIdentityMetadata($0, target) }
        let ssh = try IdentityLister(executor: executor, hashType: .ssh, hashEncoding: .b64).list().identities
            .filter { sameIdentityMetadata($0, target) }
        guard sha1.count == 1, ssh.count == 1 else {
            throw OperationalCommandError.identityMetadataAmbiguous
        }
        return ResolvedIdentity(
            ctkSHA1Hash: sha1[0].ctkPublicKeyHash.uppercased(),
            sshFingerprint: ssh[0].ctkPublicKeyHash,
            identityCount: sha256.count,
            identity: target
        )
    }
}

/// Everything both verifiers must establish before invoking OpenSSH: the CTK
/// hash is well formed, the identity file and its `.pub` are present, Apple's
/// provider is trusted, the CTK identity resolves unambiguously across all
/// three identifier formats, and the installed public key carries the SSH
/// fingerprint that identity advertises.
///
/// The provider is checked before the identity is resolved so that a tampered
/// provider is reported as untrusted rather than surfacing as a lookup miss.
func verificationPreflight(
    executor: any SubprocessExecuting,
    fileManager: FileManager,
    ctkSHA256 hash: String,
    identityFile path: String,
    checks: inout VerificationChecks
) throws -> (normalizedHash: String, resolved: ResolvedIdentity, publicKeyPath: String) {
    let normalized = try normalizedCTKSHA256(hash)
    try validatePath(path)
    let publicKeyPath = path + ".pub"
    guard fileManager.fileExists(atPath: path), fileManager.fileExists(atPath: publicKeyPath) else {
        throw OperationalCommandError.identityFileNotFound
    }
    do {
        try requireTrustedProvider(executor: executor, fileManager: fileManager)
        checks.providerLoad = .passed
    } catch {
        checks.providerLoad = .failed
        throw error
    }
    let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)
    try requireMatchingFingerprint(
        executor: executor,
        publicKeyPath: publicKeyPath,
        expected: resolved.sshFingerprint
    )
    return (normalized, resolved, publicKeyPath)
}

/// Reads the SSH fingerprint of an on-disk public key and refuses anything but
/// an exact match. Used by both verifiers and, per candidate file, by install.
func requireMatchingFingerprint(
    executor: any SubprocessExecuting,
    publicKeyPath: String,
    expected: String
) throws {
    guard try readFingerprint(executor: executor, publicKeyPath: publicKeyPath) == expected else {
        throw OperationalCommandError.fingerprintMismatch
    }
}

func readFingerprint(executor: any SubprocessExecuting, publicKeyPath: String) throws -> String? {
    let result = try executor.run(SubprocessRequest(
        executable: .sshKeygen,
        arguments: ["-l", "-E", "sha256", "-f", publicKeyPath]
    ))
    try requireOperationalSuccess(result)
    return result.stdout
        .split(whereSeparator: \Character.isWhitespace)
        .first { $0.hasPrefix("SHA256:") }
        .map(String.init)
}

func providerEnvironment(ctkSHA1Hash: String) -> [String: String] {
    ["KEYCHAIN_CERTIFICATES": ctkSHA1Hash, "SSH_SK_PROVIDER": providerPath]
}

func requireTrustedProvider(executor: any SubprocessExecuting, fileManager: FileManager) throws {
    let report = try ProviderInspector(
        executor: executor,
        pathExists: fileManager.fileExists(atPath:)
    ).report()
    guard report.available, report.signatureValid, report.appleAnchored,
          report.identifier == "com.apple.ssh-keychain" else {
        throw OperationalCommandError.providerUntrusted
    }
}

func validatePath(_ path: String) throws {
    guard !path.isEmpty,
          !path.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
        throw OperationalCommandError.invalidPath
    }
}

func validatedPublicKey(at url: URL) throws -> String {
    let text = try String(contentsOf: url, encoding: .utf8)
    let lines = text.split(whereSeparator: \Character.isNewline)
    guard lines.count == 1 else { throw OperationalCommandError.malformedPublicKey }
    let fields = lines[0].split(whereSeparator: \Character.isWhitespace)
    guard fields.count >= 2,
          fields[0] == "sk-ecdsa-sha2-nistp256@openssh.com",
          fields[1].range(of: #"^[A-Za-z0-9+/]+={0,2}$"#, options: .regularExpression) != nil else {
        throw OperationalCommandError.malformedPublicKey
    }
    return "\(fields[0]) \(fields[1])"
}

func requireOperationalSuccess(_ result: SubprocessResult) throws {
    guard result.succeeded else {
        if result.timedOut { throw OperationalCommandError.commandFailed("timed out") }
        let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        throw OperationalCommandError.commandFailed(detail)
    }
}

/// Whether the OpenSSH private key container at `path` is passphrase-encrypted.
///
/// Reads the container's cipher name rather than probing with `ssh-keygen -y`:
/// a probe cannot separate "encrypted" from "unreadable for some other
/// reason", and guessing wrong means prompting for a passphrase that does not
/// exist, which is exactly the hang this tool is supposed to avoid.
func identityFileIsEncrypted(at path: String) throws -> Bool {
    let text = try String(contentsOfFile: path, encoding: .utf8)
    guard let start = text.range(of: "-----BEGIN OPENSSH PRIVATE KEY-----"),
          let end = text.range(of: "-----END OPENSSH PRIVATE KEY-----"),
          start.upperBound <= end.lowerBound else {
        throw OperationalCommandError.malformedIdentityFile
    }
    let body = text[start.upperBound..<end.lowerBound]
        .split(whereSeparator: \Character.isNewline)
        .joined()
    guard let decoded = Data(base64Encoded: body) else {
        throw OperationalCommandError.malformedIdentityFile
    }
    // openssh-key-v1\0, then a length-prefixed cipher name. "none" is the
    // spelling OpenSSH uses for an unencrypted key.
    let bytes = [UInt8](decoded)
    let magic = [UInt8]("openssh-key-v1\0".utf8)
    guard bytes.count > magic.count + 4, Array(bytes.prefix(magic.count)) == magic else {
        throw OperationalCommandError.malformedIdentityFile
    }
    let lengthStart = magic.count
    let length = bytes[lengthStart..<(lengthStart + 4)].reduce(0) { $0 << 8 | Int($1) }
    let nameStart = lengthStart + 4
    guard length > 0, bytes.count >= nameStart + length else {
        throw OperationalCommandError.malformedIdentityFile
    }
    return String(decoding: bytes[nameStart..<(nameStart + length)], as: UTF8.self) != "none"
}

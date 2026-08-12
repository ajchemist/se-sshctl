import Foundation

private let providerPath = "/usr/lib/ssh-keychain.dylib"

public enum OperationalCommandError: Error, LocalizedError, Equatable {
    case invalidPath
    case invalidHostPattern
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

    public var errorDescription: String? {
        switch self {
        case .invalidPath: "path must be non-empty and contain no control characters"
        case .invalidHostPattern: "host pattern must be non-empty and contain no control characters"
        case .identityFileExists: "identity file or its .pub file already exists"
        case .insecureDirectory: "identity-file directory must not be accessible by group or other users"
        case let .commandFailed(detail): "OpenSSH command failed" + (detail.isEmpty ? "" : ": \(detail)")
        case .identityFileNotFound: "ssh-keygen did not produce a matching identity file"
        case .fingerprintMismatch: "identity file fingerprint does not match the selected CTK SHA-256 hash"
        case .malformedPublicKey: "identity file public key is malformed or has an unexpected key type"
        case .signatureNotCreated: "ssh-keygen returned success without creating a signature"
        case .identityNotFound: "identity was not found"
        case .identityMetadataAmbiguous: "identity metadata is duplicated; refusing to guess its provider hash or SSH fingerprint"
        case .providerUntrusted: "Apple ssh-keychain provider is missing or failed signature verification"
        case .invalidPassphrase: "identity file passphrase must not contain NUL or line-break bytes"
        }
    }
}

public struct IdentityFileInstallReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 2
    public let status = "installed"
    public let hashType = CTKIdentityHashType.sha256
    public let hashEncoding = CTKIdentityHashEncoding.hex
    public let ctkPublicKeyHash: String
    public let sshFingerprint: String
    public let identityFile: String
    public let publicKeyFile: String
    public let publicKey: String
}

public struct IdentityFileInstaller {
    private let executor: any SubprocessExecuting
    private let fileManager: FileManager

    public init(executor: any SubprocessExecuting, fileManager: FileManager = .default) {
        self.executor = executor
        self.fileManager = fileManager
    }

    public func install(
        ctkSHA256 hash: String,
        identityFile: URL,
        passphrase: Data
    ) throws -> IdentityFileInstallReport {
        let normalized = try normalizedCTKSHA256(hash)
        guard !passphrase.contains(0), !passphrase.contains(10), !passphrase.contains(13) else {
            throw OperationalCommandError.invalidPassphrase
        }
        let identityFile = identityFile.standardizedFileURL
        try validatePath(identityFile.path)
        let publicKeyFile = URL(fileURLWithPath: identityFile.path + ".pub")
        guard !fileManager.fileExists(atPath: identityFile.path),
              !fileManager.fileExists(atPath: publicKeyFile.path) else {
            throw OperationalCommandError.identityFileExists
        }
        try requireTrustedProvider(executor: executor, fileManager: fileManager)
        let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)

        let parent = identityFile.deletingLastPathComponent()
        try preparePrivateDirectory(parent)
        let temporary = parent.appendingPathComponent(".se-sshctl-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? fileManager.removeItem(at: temporary) }
        guard let askPass = Bundle.main.executableURL, askPass.path.hasPrefix("/") else {
            throw OperationalCommandError.commandFailed("unable to resolve native askpass executable")
        }

        var match: (identityFile: URL, publicKey: URL, line: String)?
        var fullDownloadResult: SubprocessResult?
        // ponytail: -K ignores the provider filter on macOS 26.6.1, so retry by
        // overwrite position; replace with one PTY capture if large inventories make this slow.
        let attempts = [resolved.identityCount] + Array(1..<resolved.identityCount)
        for identityIndex in attempts {
            let attempt = temporary.appendingPathComponent("attempt-\(identityIndex)", isDirectory: true)
            try fileManager.createDirectory(
                at: attempt,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let result = try executor.run(SubprocessRequest(
                executable: .sshKeygen,
                arguments: ["-K", "-w", providerPath],
                environment: [
                    "KEYCHAIN_CERTIFICATES": resolved.providerHash,
                    "SSH_ASKPASS": askPass.path,
                    "SSH_ASKPASS_REQUIRE": "force",
                    "SE_SSHCTL_ASKPASS_MODE": "1",
                ],
                currentDirectoryURL: attempt,
                standardInput: downloadInput(
                    selecting: identityIndex,
                    count: resolved.identityCount,
                    protection: resolved.protection,
                    passphrase: passphrase
                ),
                timeout: 120
            ))
            if result.timedOut { throw OperationalCommandError.commandFailed("timed out") }
            let askPassLines = result.stderr.split(separator: "\n")
            let passphraseMarker = Substring(
                "\(AskPassResponder.successMarker):\(AskPassResponder.ResponseKind.passphrase.rawValue)"
            )
            let pinMarker = Substring(
                "\(AskPassResponder.successMarker):\(AskPassResponder.ResponseKind.pin.rawValue)"
            )
            guard !askPassLines.contains(Substring(AskPassResponder.failureMarker)),
                  askPassLines.count(where: { $0 == passphraseMarker }) == 2,
                  askPassLines.count(where: { $0 == pinMarker }) <= 1 else {
                throw OperationalCommandError.commandFailed("native askpass rejected an unexpected OpenSSH prompt")
            }
            if identityIndex == resolved.identityCount { fullDownloadResult = result }

            let files = try fileManager.contentsOfDirectory(
                at: attempt,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            )
            var attemptMatch: (identityFile: URL, publicKey: URL, line: String)?
            for publicKeyURL in files where publicKeyURL.pathExtension == "pub" {
                let identityFileURL = publicKeyURL.deletingPathExtension()
                guard fileManager.fileExists(atPath: identityFileURL.path) else { continue }
                let fingerprintResult = try executor.run(SubprocessRequest(
                    executable: .sshKeygen,
                    arguments: ["-l", "-E", "sha256", "-f", publicKeyURL.path]
                ))
                try requireOperationalSuccess(fingerprintResult)
                guard fingerprint(in: fingerprintResult.stdout) == resolved.sshFingerprint else { continue }
                let line = try validatedPublicKey(at: publicKeyURL)
                guard attemptMatch == nil else { throw OperationalCommandError.identityFileNotFound }
                attemptMatch = (identityFileURL, publicKeyURL, line)
            }
            if let attemptMatch {
                match = attemptMatch
                break
            }
        }
        if match == nil, let fullDownloadResult {
            try requireOperationalSuccess(fullDownloadResult)
        }
        guard let match else { throw OperationalCommandError.identityFileNotFound }

        var installedIdentityFile = false
        var installedPublicKey = false
        do {
            try fileManager.moveItem(at: match.identityFile, to: identityFile)
            installedIdentityFile = true
            try fileManager.setAttributes([.posixPermissions: 0o400], ofItemAtPath: identityFile.path)
            try fileManager.moveItem(at: match.publicKey, to: publicKeyFile)
            installedPublicKey = true
            try fileManager.setAttributes([.posixPermissions: 0o444], ofItemAtPath: publicKeyFile.path)
        } catch {
            if installedIdentityFile { try? fileManager.removeItem(at: identityFile) }
            if installedPublicKey { try? fileManager.removeItem(at: publicKeyFile) }
            throw error
        }

        return IdentityFileInstallReport(
            ctkPublicKeyHash: normalized,
            sshFingerprint: resolved.sshFingerprint,
            identityFile: identityFile.path,
            publicKeyFile: publicKeyFile.path,
            publicKey: match.line
        )
    }

    private func preparePrivateDirectory(_ directory: URL) throws {
        if !fileManager.fileExists(atPath: directory.path) {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        let attributes = try fileManager.attributesOfItem(atPath: directory.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
        guard permissions & 0o077 == 0 else { throw OperationalCommandError.insecureDirectory }
    }
}

public struct ConfigRenderReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 1
    public let config: String
}

public struct SSHConfigRenderer {
    public init() {}

    public func render(identityFile: String, hostPattern: String) throws -> ConfigRenderReport {
        try validatePath(identityFile)
        guard !hostPattern.isEmpty,
              !hostPattern.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw OperationalCommandError.invalidHostPattern
        }
        let quotedPath = identityFile
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return ConfigRenderReport(config: """
        Host \(hostPattern)
            IdentityFile "\(quotedPath)"
            SecurityKeyProvider \(providerPath)
            IdentitiesOnly yes
            ForwardAgent no
        """)
    }
}

public struct VerificationReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 2
    public let status = "passed"
    public let kind: String
    public let ctkSHA256: String
    public let target: String?
}

public struct LocalVerifier {
    private let executor: any SubprocessExecuting
    private let fileManager: FileManager

    public init(executor: any SubprocessExecuting, fileManager: FileManager = .default) {
        self.executor = executor
        self.fileManager = fileManager
    }

    public func verify(ctkSHA256 hash: String, identityFile: URL) throws -> VerificationReport {
        let normalized = try normalizedCTKSHA256(hash)
        let identityFile = identityFile.standardizedFileURL
        try validatePath(identityFile.path)
        let publicKeyURL = URL(fileURLWithPath: identityFile.path + ".pub")
        guard fileManager.fileExists(atPath: identityFile.path),
              fileManager.fileExists(atPath: publicKeyURL.path) else {
            throw OperationalCommandError.identityFileNotFound
        }
        try requireTrustedProvider(executor: executor, fileManager: fileManager)
        let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)
        let fingerprintResult = try executor.run(SubprocessRequest(
            executable: .sshKeygen,
            arguments: ["-l", "-E", "sha256", "-f", publicKeyURL.path]
        ))
        try requireOperationalSuccess(fingerprintResult)
        guard fingerprint(in: fingerprintResult.stdout) == resolved.sshFingerprint else {
            throw OperationalCommandError.fingerprintMismatch
        }
        let publicKey = try validatedPublicKey(at: publicKeyURL)
        let temporary = fileManager.temporaryDirectory
            .appendingPathComponent("se-sshctl-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(
            at: temporary,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? fileManager.removeItem(at: temporary) }

        let challenge = temporary.appendingPathComponent("challenge")
        let challengeData = Data("se-sshctl local signing verification\n".utf8)
        try challengeData.write(to: challenge, options: .atomic)
        let environment = providerEnvironment(hash: resolved.providerHash)
        try requireOperationalSuccess(executor.run(SubprocessRequest(
            executable: .sshKeygen,
            arguments: ["-Y", "sign", "-f", identityFile.path, "-n", "se-sshctl", challenge.path],
            environment: environment,
            timeout: 120
        )))
        let signature = URL(fileURLWithPath: challenge.path + ".sig")
        guard fileManager.fileExists(atPath: signature.path) else {
            throw OperationalCommandError.signatureNotCreated
        }

        let allowedSigners = temporary.appendingPathComponent("allowed_signers")
        try Data("se-sshctl \(publicKey)\n".utf8).write(to: allowedSigners, options: .atomic)
        try requireOperationalSuccess(executor.run(SubprocessRequest(
            executable: .sshKeygen,
            arguments: [
                "-Y", "verify", "-f", allowedSigners.path,
                "-I", "se-sshctl", "-n", "se-sshctl", "-s", signature.path,
            ],
            environment: environment,
            standardInput: challengeData,
            timeout: 30
        )))
        return VerificationReport(kind: "local", ctkSHA256: normalized, target: nil)
    }
}

public struct RemoteVerifier {
    private let executor: any SubprocessExecuting
    private let fileManager: FileManager

    public init(executor: any SubprocessExecuting, fileManager: FileManager = .default) {
        self.executor = executor
        self.fileManager = fileManager
    }

    public func verify(ctkSHA256 hash: String, identityFile: String, target: String) throws -> VerificationReport {
        let normalized = try normalizedCTKSHA256(hash)
        try validatePath(identityFile)
        guard !target.isEmpty, !target.hasPrefix("-"),
              !target.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
            throw OperationalCommandError.invalidHostPattern
        }
        let publicKeyPath = identityFile + ".pub"
        guard fileManager.fileExists(atPath: identityFile), fileManager.fileExists(atPath: publicKeyPath) else {
            throw OperationalCommandError.identityFileNotFound
        }
        try requireTrustedProvider(executor: executor, fileManager: fileManager)
        let resolved = try IdentityResolver(executor: executor).resolve(ctkSHA256: normalized)
        let fingerprintResult = try executor.run(SubprocessRequest(
            executable: .sshKeygen,
            arguments: ["-l", "-E", "sha256", "-f", publicKeyPath]
        ))
        try requireOperationalSuccess(fingerprintResult)
        guard fingerprint(in: fingerprintResult.stdout) == resolved.sshFingerprint else {
            throw OperationalCommandError.fingerprintMismatch
        }
        try requireOperationalSuccess(executor.run(SubprocessRequest(
            executable: .ssh,
            arguments: [
                "-F", "none",
                "-S", "none",
                "-o", "BatchMode=yes",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "IdentitiesOnly=yes",
                "-o", "IdentityAgent=none",
                "-o", "ForwardAgent=no",
                "-o", "GSSAPIAuthentication=no",
                "-o", "HostbasedAuthentication=no",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "PreferredAuthentications=publickey",
                "-o", "PubkeyAuthentication=yes",
                "-o", "SecurityKeyProvider=\(providerPath)",
                "-o", "IdentityFile=\(identityFile)",
                "--", target, "true",
            ],
            environment: providerEnvironment(hash: resolved.providerHash),
            timeout: 30
        )))
        return VerificationReport(kind: "remote", ctkSHA256: normalized, target: target)
    }
}

private struct ResolvedIdentity {
    let providerHash: String
    let sshFingerprint: String
    let identityCount: Int
    let protection: String
}

private struct IdentityResolver {
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
            providerHash: sha1[0].ctkPublicKeyHash.uppercased(),
            sshFingerprint: ssh[0].ctkPublicKeyHash,
            identityCount: sha256.count,
            protection: target.protection
        )
    }
}

private func providerEnvironment(hash: String) -> [String: String] {
    ["KEYCHAIN_CERTIFICATES": hash, "SSH_SK_PROVIDER": providerPath]
}

private func downloadInput(selecting index: Int, count: Int, protection: String, passphrase: Data) -> Data {
    var input = AskPassResponder.pinReply(protection == "bio" ? Data() : Data("0".utf8))
    input.append(AskPassResponder.passphraseReply(passphrase))
    input.append(AskPassResponder.passphraseReply(passphrase))
    if index > 1 { input.append(Data(String(repeating: "y\n", count: index - 1).utf8)) }
    if index < count { input.append(Data("n\n".utf8)) }
    return input
}

private func requireTrustedProvider(executor: any SubprocessExecuting, fileManager: FileManager) throws {
    let report = try ProviderInspector(
        executor: executor,
        pathExists: fileManager.fileExists(atPath:)
    ).report()
    guard report.available, report.signatureValid, report.appleAnchored,
          report.identifier == "com.apple.ssh-keychain" else {
        throw OperationalCommandError.providerUntrusted
    }
}

private func validatePath(_ path: String) throws {
    guard !path.isEmpty,
          !path.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
        throw OperationalCommandError.invalidPath
    }
}

private func fingerprint(in output: String) -> String? {
    output.split(whereSeparator: \Character.isWhitespace).first { $0.hasPrefix("SHA256:") }.map(String.init)
}

private func validatedPublicKey(at url: URL) throws -> String {
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

private func requireOperationalSuccess(_ result: SubprocessResult) throws {
    guard !result.timedOut, result.terminationReason == .exit, result.exitStatus == 0 else {
        if result.timedOut { throw OperationalCommandError.commandFailed("timed out") }
        let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        throw OperationalCommandError.commandFailed(detail)
    }
}

import Foundation

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
        let identityFile = identityFile.standardizedFileURL
        let preflight = try verificationPreflight(
            executor: executor,
            fileManager: fileManager,
            ctkSHA256: hash,
            identityFile: identityFile.path
        )
        let publicKey = try validatedPublicKey(at: URL(fileURLWithPath: preflight.publicKeyPath))
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
        let environment = providerEnvironment(ctkSHA1Hash: preflight.resolved.ctkSHA1Hash)
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
        return VerificationReport(kind: "local", ctkSHA256: preflight.normalizedHash, target: nil)
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
        guard !target.isEmpty, !target.hasPrefix("-"),
              !target.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
            throw OperationalCommandError.invalidHostPattern
        }
        let preflight = try verificationPreflight(
            executor: executor,
            fileManager: fileManager,
            ctkSHA256: hash,
            identityFile: identityFile
        )
        try requireOperationalSuccess(executor.run(SubprocessRequest(
            executable: .ssh,
            arguments: isolatedSSHArguments(identityFile: identityFile, target: target),
            environment: providerEnvironment(ctkSHA1Hash: preflight.resolved.ctkSHA1Hash),
            timeout: 30
        )))
        return VerificationReport(kind: "remote", ctkSHA256: preflight.normalizedHash, target: target)
    }
}

/// Every ambient source of SSH identity and authentication is disabled, so a
/// pass proves the selected identity file alone authenticated: no agent, no
/// user config, no multiplexed connection, no password fallback.
private func isolatedSSHArguments(identityFile: String, target: String) -> [String] {
    [
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
    ]
}

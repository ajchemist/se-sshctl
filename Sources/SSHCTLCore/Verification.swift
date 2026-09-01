import Foundation

/// The originating specification is explicit that these stay three distinct
/// values: "Represent `passed`, `failed`, and `not-run` separately. Never turn
/// 'not tested' into success."
public enum VerificationOutcome: String, Codable, Equatable, Sendable {
    case passed
    case failed
    case notRun = "not-run"
}

/// Every check the tool can make, always all of them, so a command that did
/// not attempt a check says so rather than omitting the field. `verify local`
/// reports `remoteAuthentication: not-run`; it does not leave a reader to
/// infer it.
public struct VerificationChecks: Codable, Equatable, Sendable {
    public var providerLoad: VerificationOutcome
    public var localSigning: VerificationOutcome
    public var remoteAuthentication: VerificationOutcome

    public init(
        providerLoad: VerificationOutcome = .notRun,
        localSigning: VerificationOutcome = .notRun,
        remoteAuthentication: VerificationOutcome = .notRun
    ) {
        self.providerLoad = providerLoad
        self.localSigning = localSigning
        self.remoteAuthentication = remoteAuthentication
    }
}

public struct VerificationReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 3
    public let status: VerificationOutcome
    public let kind: String
    public let ctkSHA256: String
    public let target: String?
    public let checks: VerificationChecks
    public let detail: String?
    /// OpenSSH client verbose output from `verify remote`, on both pass and
    /// fail. Server authentication logs are not here: reading them needs
    /// privileged access on the target, which is outside this tool's boundary.
    public let clientLog: String?

    init(
        status: VerificationOutcome,
        kind: String,
        ctkSHA256: String,
        target: String?,
        checks: VerificationChecks,
        detail: String? = nil,
        clientLog: String? = nil
    ) {
        self.status = status
        self.kind = kind
        self.ctkSHA256 = ctkSHA256
        self.target = target
        self.checks = checks
        self.detail = detail
        self.clientLog = clientLog
    }
}

/// A verification that ran and did not pass, carrying the partial manifest.
///
/// Without this the failed run would surface only as a generic CLI error, and
/// the checks that did pass before the failure would be lost — which is the
/// "never turn not-tested into success" rule failing in the other direction.
public struct VerificationFailed: Error, LocalizedError {
    public let report: VerificationReport
    public let underlying: any Error

    public var errorDescription: String? {
        (underlying as? LocalizedError)?.errorDescription ?? String(describing: underlying)
    }
}

/// Builds the failed manifest for whatever had been established when `error`
/// was thrown. Checks never reached stay `not-run`.
private func failure(
    _ error: any Error,
    kind: String,
    ctkSHA256: String,
    target: String?,
    checks: VerificationChecks,
    clientLog: String? = nil
) -> VerificationFailed {
    VerificationFailed(
        report: VerificationReport(
            status: .failed,
            kind: kind,
            ctkSHA256: ctkSHA256,
            target: target,
            checks: checks,
            detail: (error as? LocalizedError)?.errorDescription ?? String(describing: error),
            clientLog: clientLog
        ),
        underlying: error
    )
}

/// Keeps the tail of the client log, which is where the authentication
/// outcome is, and bounds it so a chatty or hostile server cannot make the
/// report unbounded.
private func boundedClientLog(_ stderr: String) -> String? {
    let lines = stderr.split(whereSeparator: \Character.isNewline)
    guard !lines.isEmpty else { return nil }
    let limit = 100
    guard lines.count > limit else { return lines.joined(separator: "\n") }
    return (["[\(lines.count - limit) earlier lines omitted]"]
        + lines.suffix(limit)).joined(separator: "\n")
}

public struct LocalVerifier {
    private let executor: any SubprocessExecuting
    private let fileManager: FileManager

    public init(executor: any SubprocessExecuting, fileManager: FileManager = .default) {
        self.executor = executor
        self.fileManager = fileManager
    }

    public func verify(ctkSHA256 hash: String, identityFile: URL) throws -> VerificationReport {
        var checks = VerificationChecks()
        do {
            let identityFile = identityFile.standardizedFileURL
            let preflight = try verificationPreflight(
                executor: executor,
                fileManager: fileManager,
                ctkSHA256: hash,
                identityFile: identityFile.path,
                checks: &checks
            )
            do {
                try sign(identityFile: identityFile, preflight: preflight)
                checks.localSigning = .passed
            } catch {
                checks.localSigning = .failed
                throw error
            }
            return VerificationReport(
                status: .passed,
                kind: "local",
                ctkSHA256: preflight.normalizedHash,
                target: nil,
                checks: checks
            )
        } catch {
            throw failure(
                error, kind: "local", ctkSHA256: hash.uppercased(), target: nil, checks: checks
            )
        }
    }

    /// Signs a throwaway challenge through Apple's provider and verifies the
    /// resulting signature against the installed public key, so a pass means
    /// the Secure Enclave key actually produced a usable SSH signature.
    private func sign(
        identityFile: URL,
        preflight: (normalizedHash: String, resolved: ResolvedIdentity, publicKeyPath: String)
    ) throws {
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
        var checks = VerificationChecks()
        var clientLog: String?
        do {
            guard !target.isEmpty, !target.hasPrefix("-"),
                  !target.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
                throw OperationalCommandError.invalidHostPattern
            }
            let preflight = try verificationPreflight(
                executor: executor,
                fileManager: fileManager,
                ctkSHA256: hash,
                identityFile: identityFile,
                checks: &checks
            )
            do {
                let result = try executor.run(SubprocessRequest(
                    executable: .ssh,
                    arguments: isolatedSSHArguments(identityFile: identityFile, target: target),
                    environment: providerEnvironment(ctkSHA1Hash: preflight.resolved.ctkSHA1Hash),
                    timeout: 30
                ))
                // Captured before the success check: a failed authentication is
                // exactly when the log is worth having.
                clientLog = boundedClientLog(result.stderr)
                try requireOperationalSuccess(result)
                checks.remoteAuthentication = .passed
            } catch {
                checks.remoteAuthentication = .failed
                throw error
            }
            return VerificationReport(
                status: .passed,
                kind: "remote",
                ctkSHA256: preflight.normalizedHash,
                target: target,
                checks: checks,
                clientLog: clientLog
            )
        } catch {
            throw failure(
                error,
                kind: "remote",
                ctkSHA256: hash.uppercased(),
                target: target,
                checks: checks,
                clientLog: clientLog
            )
        }
    }
}

/// Every ambient source of SSH identity and authentication is disabled, so a
/// pass proves the selected identity file alone authenticated: no agent, no
/// user config, no multiplexed connection, no password fallback.
private func isolatedSSHArguments(identityFile: String, target: String) -> [String] {
    [
        // -v records the authentication method progression, which is the only
        // client-side evidence of why a public-key attempt was refused.
        "-v",
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

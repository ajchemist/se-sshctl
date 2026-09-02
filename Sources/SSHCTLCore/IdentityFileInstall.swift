import Foundation

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
        // FIXME: ssh-keygen -K ignores the KEYCHAIN_CERTIFICATES provider filter
        // on macOS 26.6.1 and downloads every resident identity, so the wanted
        // one is selected by overwrite position and confirmed by fingerprint.
        // Replace with a single PTY capture if large inventories make this slow.
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
                    "KEYCHAIN_CERTIFICATES": resolved.ctkSHA1Hash,
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
            do {
                try requireExpectedAskPassTraffic(in: result.stderr)
            } catch where !result.succeeded {
                // OpenSSH gave up before the prompts could complete (a provider
                // that cannot load the identity, for one); its own message is
                // the finding, not the prompt count it never reached.
                throw OperationalCommandError.commandFailed(openSSHDetail(in: result.stderr))
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
                let found = try readFingerprint(executor: executor, publicKeyPath: publicKeyURL.path)
                guard found == resolved.sshFingerprint else { continue }
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
        // The file itself is installed 0400 and holds a handle, not key
        // material, so the threat in its directory is a swap, not a read:
        // refuse group- or world-writable, accept a common 755 ~/.ssh/identities.
        let attributes = try fileManager.attributesOfItem(atPath: directory.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777
        guard permissions & 0o022 == 0 else { throw OperationalCommandError.insecureDirectory }
    }
}

/// OpenSSH's stderr without the askpass responder's marker lines.
private func openSSHDetail(in stderr: String) -> String {
    stderr.split(separator: "\n")
        .filter { !$0.hasPrefix(AskPassResponder.successMarker) && $0 != Substring(AskPassResponder.failureMarker) }
        .joined(separator: "\n")
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

/// Fails closed on anything but the exact prompt traffic this download expects:
/// two passphrase prompts, at most one provider PIN, and no prompt the native
/// askpass responder could not classify.
private func requireExpectedAskPassTraffic(in stderr: String) throws {
    let lines = stderr.split(separator: "\n")
    let passphraseMarker = Substring(
        "\(AskPassResponder.successMarker):\(AskPassResponder.ResponseKind.passphrase.rawValue)"
    )
    let pinMarker = Substring(
        "\(AskPassResponder.successMarker):\(AskPassResponder.ResponseKind.pin.rawValue)"
    )
    guard !lines.contains(Substring(AskPassResponder.failureMarker)),
          lines.count(where: { $0 == passphraseMarker }) == 2,
          lines.count(where: { $0 == pinMarker }) <= 1 else {
        throw OperationalCommandError.commandFailed("native askpass rejected an unexpected OpenSSH prompt")
    }
}

/// `ssh-keygen -K` walks every resident identity, asking whether to overwrite
/// each one. Answering "y" for the first `index - 1` and then "n" leaves the
/// wanted identity as the last file written.
private func downloadInput(selecting index: Int, count: Int, protection: CTKProtection, passphrase: Data) -> Data {
    var input = AskPassResponder.pinReply(protection.providerPIN)
    input.append(AskPassResponder.passphraseReply(passphrase))
    input.append(AskPassResponder.passphraseReply(passphrase))
    if index > 1 { input.append(Data(String(repeating: "y\n", count: index - 1).utf8)) }
    if index < count { input.append(Data("n\n".utf8)) }
    return input
}

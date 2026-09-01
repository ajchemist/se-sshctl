import Foundation
import Testing
@testable import SSHCTLCore

@Test func identityFileInstallMatchesFingerprintAndRefusesImplicitOverwrite() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let destination = root.appendingPathComponent("identity")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor()

    let report = try IdentityFileInstaller(executor: executor).install(
        ctkSHA256: hash, identityFile: destination, passphrase: Data()
    )

    #expect(report.identityFile == destination.path)
    #expect(report.publicKey == "sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ==")
    #expect(FileManager.default.fileExists(atPath: destination.path))
    #expect(FileManager.default.fileExists(atPath: destination.path + ".pub"))
    let identityFileMode = try #require(
        FileManager.default.attributesOfItem(atPath: destination.path)[.posixPermissions] as? NSNumber
    )
    let publicKeyMode = try #require(
        FileManager.default.attributesOfItem(atPath: destination.path + ".pub")[.posixPermissions] as? NSNumber
    )
    #expect(identityFileMode.intValue == 0o400)
    #expect(publicKeyMode.intValue == 0o444)
    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.arguments == ["-K", "-w", "/usr/lib/ssh-keychain.dylib"])
    #expect(download.environment["KEYCHAIN_CERTIFICATES"] == String(repeating: "B", count: 40))
    #expect(download.environment["SSH_ASKPASS_REQUIRE"] == "force")
    #expect(download.environment["SSH_ASKPASS"] == Bundle.main.executableURL!.path)
    #expect(download.environment["SE_SSHCTL_ASKPASS_MODE"] == "1")
    #expect(download.standardInput == taggedDownloadInput(pin: Data("0".utf8), passphrase: Data()))
    #expect(throws: OperationalCommandError.identityFileExists) {
        try IdentityFileInstaller(executor: executor).install(
            ctkSHA256: hash, identityFile: destination, passphrase: Data()
        )
    }
}

@Test func identityFileInstallRefusesAmbiguousCrossFormatIdentityMetadata() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(duplicateMetadata: true)

    #expect(throws: OperationalCommandError.identityMetadataAmbiguous) {
        try IdentityFileInstaller(executor: executor).install(
            ctkSHA256: hash,
            identityFile: root.appendingPathComponent("identity"),
            passphrase: Data()
        )
    }
    #expect(!executor.requests.contains { $0.arguments.first == "-K" })
}

@Test func identityFileInstallSuppliesNonEmptyPassphraseTwice() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor()

    _ = try IdentityFileInstaller(executor: executor).install(
        ctkSHA256: hash,
        identityFile: root.appendingPathComponent("identity"),
        passphrase: Data("test passphrase".utf8)
    )

    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.standardInput == taggedDownloadInput(
        pin: Data("0".utf8),
        passphrase: Data("test passphrase".utf8)
    ))
    // The passphrase must reach OpenSSH only over the stdin pipe. Substring
    // checks, not equality: an environment value or argument that merely
    // embeds it is the same disclosure.
    #expect(!download.environment.values.contains { $0.contains("test passphrase") })
    #expect(!download.arguments.contains { $0.contains("test passphrase") })
    for request in executor.requests {
        #expect(!request.environment.values.contains { $0.contains("test passphrase") })
        #expect(!request.arguments.contains { $0.contains("test passphrase") })
    }
}

@Test func bioIdentityFileInstallSuppliesEmptyProviderPIN() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(protection: "bio")

    _ = try IdentityFileInstaller(executor: executor).install(
        ctkSHA256: hash,
        identityFile: root.appendingPathComponent("identity"),
        passphrase: Data()
    )

    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.standardInput == taggedDownloadInput(pin: Data(), passphrase: Data()))
}

@Test func identityFileInstallReportsOpenSSHTimeout() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(throws: OperationalCommandError.commandFailed("timed out")) {
        try IdentityFileInstaller(executor: OperationalExecutor(downloadTimedOut: true)).install(
            ctkSHA256: hash,
            identityFile: root.appendingPathComponent("identity"),
            passphrase: Data()
        )
    }
}

@Test func identityFileInstallRejectsAskPassProtocolFailureEvenWhenOpenSSHSucceeds() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(throws: OperationalCommandError.commandFailed(
        "native askpass rejected an unexpected OpenSSH prompt"
    )) {
        try IdentityFileInstaller(executor: OperationalExecutor(askPassFailed: true)).install(
            ctkSHA256: hash,
            identityFile: root.appendingPathComponent("identity"),
            passphrase: Data("expected passphrase".utf8)
        )
    }
}

@Test func identityFileInstallRejectsMissingPassphrasePrompt() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    #expect(throws: OperationalCommandError.commandFailed(
        "native askpass rejected an unexpected OpenSSH prompt"
    )) {
        try IdentityFileInstaller(executor: OperationalExecutor(passphrasePromptCount: 1)).install(
            ctkSHA256: hash,
            identityFile: root.appendingPathComponent("identity"),
            passphrase: Data("expected passphrase".utf8)
        )
    }
}

@Test func identityFileInstallRetriesOverwritePositionsUntilFingerprintMatches() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(identityCount: 2, matchingDownloadAttempt: 2)

    _ = try IdentityFileInstaller(executor: executor).install(
        ctkSHA256: hash,
        identityFile: root.appendingPathComponent("identity"),
        passphrase: Data()
    )

    let downloads = executor.requests.filter { $0.arguments.first == "-K" }
    #expect(downloads.count == 2)
    var lastIdentityInput = taggedDownloadInput(pin: Data("0".utf8), passphrase: Data())
    lastIdentityInput.append(Data("y\n".utf8))
    var firstIdentityInput = taggedDownloadInput(pin: Data("0".utf8), passphrase: Data())
    firstIdentityInput.append(Data("n\n".utf8))
    #expect(downloads[0].standardInput == lastIdentityInput)
    #expect(downloads[1].standardInput == firstIdentityInput)
}

@Test func failedIdentityFileInstallDoesNotDeleteACompetitorInstall() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let destination = root.appendingPathComponent("identity")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(racingDestination: destination)

    #expect(throws: (any Error).self) {
        try IdentityFileInstaller(executor: executor).install(
            ctkSHA256: hash, identityFile: destination, passphrase: Data()
        )
    }
    #expect(FileManager.default.fileExists(atPath: destination.path))
    #expect(FileManager.default.fileExists(atPath: destination.path + ".pub"))
}

@Test func configRenderingEscapesPathsAndRejectsLineInjection() throws {
    let report = try SSHConfigRenderer().render(
        identityFile: "/tmp/key \"one\"",
        hostPattern: "prod-*"
    )

    #expect(report.config.contains(#"IdentityFile "/tmp/key \"one\"""#))
    #expect(report.config.contains("ForwardAgent no"))
    #expect(throws: OperationalCommandError.invalidHostPattern) {
        try SSHConfigRenderer().render(identityFile: "/tmp/key", hostPattern: "host\nProxyCommand bad")
    }
}

@Test func localVerificationSignsAndVerifiesATemporaryChallenge() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let identityFile = root.appendingPathComponent("identity")
    try Data("identityFile".utf8).write(to: identityFile)
    try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
        .write(to: URL(fileURLWithPath: identityFile.path + ".pub"))
    let executor = OperationalExecutor()

    let report = try LocalVerifier(executor: executor).verify(ctkSHA256: hash, identityFile: identityFile)

    #expect(report.status == "passed")
    let sign = executor.requests.first { $0.arguments.prefix(2) == ["-Y", "sign"] }
    let verify = executor.requests.first { $0.arguments.prefix(2) == ["-Y", "verify"] }
    #expect(sign != nil)
    #expect(verify?.standardInput == Data("se-sshctl local signing verification\n".utf8))
}

@Test func remoteVerificationUsesOnlyTheSelectedIdentityAndBatchMode() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let identityFile = root.appendingPathComponent("identity")
    try Data("identityFile".utf8).write(to: identityFile)
    try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
        .write(to: URL(fileURLWithPath: identityFile.path + ".pub"))
    let executor = OperationalExecutor()

    let report = try RemoteVerifier(executor: executor).verify(
        ctkSHA256: hash,
        identityFile: identityFile.path,
        target: "deploy@example.test"
    )

    #expect(report.target == "deploy@example.test")
    let ssh = executor.requests.first { $0.executable == .ssh }!
    #expect(ssh.arguments.contains("BatchMode=yes"))
    #expect(ssh.arguments.contains("IdentitiesOnly=yes"))
    #expect(ssh.arguments.contains("none"))
    #expect(ssh.arguments.contains("ControlMaster=no"))
    #expect(ssh.arguments.contains("ControlPath=none"))
    #expect(ssh.arguments.contains("GSSAPIAuthentication=no"))
    #expect(ssh.arguments.contains("HostbasedAuthentication=no"))
    #expect(ssh.arguments.contains("PreferredAuthentications=publickey"))
    #expect(ssh.arguments.contains("PubkeyAuthentication=yes"))
    #expect(ssh.environment["KEYCHAIN_CERTIFICATES"] == String(repeating: "B", count: 40))
}

private final class OperationalExecutor: SubprocessExecuting {
    private(set) var requests: [SubprocessRequest] = []
    private let duplicateMetadata: Bool
    private let racingDestination: URL?
    private let protection: String
    private let downloadTimedOut: Bool
    private let askPassFailed: Bool
    private let passphrasePromptCount: Int
    private let identityCount: Int
    private let matchingDownloadAttempt: Int
    private var downloadAttempt = 0

    init(
        duplicateMetadata: Bool = false,
        racingDestination: URL? = nil,
        protection: String = "none",
        downloadTimedOut: Bool = false,
        askPassFailed: Bool = false,
        passphrasePromptCount: Int = 2,
        identityCount: Int = 1,
        matchingDownloadAttempt: Int = 1
    ) {
        self.duplicateMetadata = duplicateMetadata
        self.racingDestination = racingDestination
        self.protection = protection
        self.downloadTimedOut = downloadTimedOut
        self.askPassFailed = askPassFailed
        self.passphrasePromptCount = passphrasePromptCount
        self.identityCount = identityCount
        self.matchingDownloadAttempt = matchingDownloadAttempt
    }

    func run(_ request: SubprocessRequest) throws -> SubprocessResult {
        requests.append(request)
        if request.executable == .codesign {
            return request.arguments.first == "-dr"
                ? operationalResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")
                : operationalResult()
        }
        if request.executable == .scAuth {
            let typeIndex = request.arguments.firstIndex(of: "-t")!
            return operationalResult(stdout: identityTable(
                hashType: request.arguments[typeIndex + 1],
                duplicateMetadata: duplicateMetadata,
                protection: protection,
                identityCount: identityCount
            ))
        }
        if request.arguments.first == "-K" {
            downloadAttempt += 1
            if downloadTimedOut {
                return SubprocessResult(
                    stdout: "", stderr: "", exitStatus: 15, terminationReason: .uncaughtSignal, timedOut: true
                )
            }
            let directory = request.currentDirectoryURL!
            try Data("identityFile".utf8).write(to: directory.appendingPathComponent("id_test"))
            try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
                .write(to: directory.appendingPathComponent("id_test.pub"))
            let askPassResult = askPassFailed
                ? AskPassResponder.failureMarker
                : (["\(AskPassResponder.successMarker):pin"] + Array(
                    repeating: "\(AskPassResponder.successMarker):passphrase",
                    count: passphrasePromptCount
                )).joined(separator: "\n")
            return operationalResult(stderr: askPassResult)
        }
        if request.arguments.first == "-l" {
            if let racingDestination {
                try Data("competitor identityFile".utf8).write(to: racingDestination)
                try Data("competitor public key".utf8)
                    .write(to: URL(fileURLWithPath: racingDestination.path + ".pub"))
            }
            let fingerprint = matchingDownloadAttempt == 1 || downloadAttempt >= matchingDownloadAttempt
                ? sshFingerprint
                : "SHA256:" + String(repeating: "D", count: 43)
            return operationalResult(stdout: "256 \(fingerprint) test (ECDSA-SK)\n")
        }
        if request.arguments.prefix(2) == ["-Y", "sign"] {
            let challenge = request.arguments.last!
            try Data("signature".utf8).write(to: URL(fileURLWithPath: challenge + ".sig"))
        }
        return operationalResult()
    }
}

private let sshFingerprint = "SHA256:" + String(repeating: "C", count: 43)

private func taggedDownloadInput(pin: Data, passphrase: Data) -> Data {
    var input = AskPassResponder.pinReply(pin)
    input.append(AskPassResponder.passphraseReply(passphrase))
    input.append(AskPassResponder.passphraseReply(passphrase))
    return input
}

private func identityTable(
    hashType: String,
    duplicateMetadata: Bool,
    protection: String,
    identityCount: Int
) -> String {
    let text = try! String(
        contentsOf: Bundle.module.url(
            forResource: "identities-multiple",
            withExtension: "txt",
            subdirectory: "Fixtures"
        )!,
        encoding: .utf8
    )
    let lines = text.split(whereSeparator: \Character.isNewline).map(String.init)
    let hash = switch hashType {
    case "sha1": String(repeating: "B", count: 40)
    case "ssh": sshFingerprint
    default: String(repeating: "A", count: 64)
    }
    let paddedHash = hash + String(repeating: " ", count: 64 - hash.count)
    let paddedProtection = protection.padding(toLength: 4, withPad: " ", startingAt: 0)
    let row = lines[1]
        .replacingOccurrences(of: String(repeating: "A", count: 64), with: paddedHash)
        .replacingOccurrences(of: "  none  ", with: "  \(paddedProtection)  ")
    if identityCount == 2, hashType == "sha256" {
        return lines[0] + "\n" + row + "\n" + lines[2] + "\n"
    }
    guard duplicateMetadata, hashType != "sha256" else { return lines[0] + "\n" + row + "\n" }
    let otherHash = hashType == "sha1"
        ? String(repeating: "D", count: 40)
        : "SHA256:" + String(repeating: "E", count: 43)
    let otherRow = row.replacingOccurrences(of: hash, with: otherHash)
    return lines[0] + "\n" + row + "\n" + otherRow + "\n"
}

private func operationalResult(stdout: String = "", stderr: String = "") -> SubprocessResult {
    SubprocessResult(
        stdout: stdout,
        stderr: stderr,
        exitStatus: 0,
        terminationReason: .exit,
        timedOut: false
    )
}

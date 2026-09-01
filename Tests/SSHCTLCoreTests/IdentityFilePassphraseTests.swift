import Foundation
import Testing
@testable import SSHCTLCore

@Test func encryptionIsReadFromRealOpenSSHContainers() throws {
    // Checked against ssh-keygen's own output rather than a hand-built fixture:
    // the whole point of parsing the container is to agree with OpenSSH about
    // whether a passphrase exists.
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let plain = root.appendingPathComponent("plain").path
    let locked = root.appendingPathComponent("locked").path

    try generateKey(at: plain, passphrase: "")
    try generateKey(at: locked, passphrase: "test passphrase")

    #expect(try identityFileIsEncrypted(at: plain) == false)
    #expect(try identityFileIsEncrypted(at: locked) == true)
}

@Test func aFileThatIsNotAnOpenSSHContainerIsRejectedRatherThanGuessed() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("not-a-key").path
    try Data("hello\n".utf8).write(to: URL(fileURLWithPath: path))

    // Guessing "unencrypted" here would send an empty passphrase to OpenSSH and
    // report a confusing downstream failure instead of the real problem.
    #expect(throws: OperationalCommandError.malformedIdentityFile) {
        _ = try identityFileIsEncrypted(at: path)
    }
}

@Test func installWithoutAPassphraseNeedsNoTerminal() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = PassphraseExecutor()

    // No reader supplied: this is the non-interactive remote session the
    // handoff's verification matrix requires.
    let output = try CLI.run(
        arguments: [
            "install", "--ctk-sha256", hash,
            "--identity-file", root.appendingPathComponent("identity").path,
            "--no-passphrase",
        ],
        executor: executor,
        fileManager: .default
    )

    #expect(output.contains("Installed"))
    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.standardInput == AskPassResponder.pinReply(Data("0".utf8))
        + AskPassResponder.passphraseReply(Data())
        + AskPassResponder.passphraseReply(Data()))
}

@Test func installWithoutATerminalOrTheFlagSaysHowToProceed() {
    let executor = PassphraseExecutor()

    #expect(throws: CLIError.usage(
        "install needs a controlling terminal to read a passphrase; "
            + "pass --no-passphrase to install without one"
    )) {
        try CLI.run(
            arguments: ["install", "--ctk-sha256", String(repeating: "A", count: 64)],
            executor: executor
        )
    }
    #expect(executor.requests.isEmpty)
}

@Test func anEncryptedIdentityFileIsUnlockedOverAPipeNotArgvOrEnvironment() throws {
    let hash = String(repeating: "A", count: 64)
    let root = try verificationFixture(cipher: "aes256-ctr")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = PassphraseExecutor()

    _ = try CLI.run(
        arguments: [
            "verify", "remote", "--ctk-sha256", hash,
            "--identity-file", root.appendingPathComponent("identity").path,
            "--target", "deploy@example.test",
        ],
        executor: executor,
        identityFileUnlockReader: { Data("test passphrase".utf8) }
    )

    let ssh = executor.requests.first { $0.executable == .ssh }!
    #expect(ssh.standardInput?.contains(Data("test passphrase".utf8)) == true)
    for request in executor.requests {
        #expect(!request.arguments.contains { $0.contains("test passphrase") })
        #expect(!request.environment.values.contains { $0.contains("test passphrase") })
    }
    // BatchMode also suppresses OpenSSH's passphrase prompt, so it has to go
    // for an encrypted key. Nothing else may be relaxed with it.
    #expect(!ssh.arguments.contains("BatchMode=yes"))
    #expect(ssh.arguments.contains("PasswordAuthentication=no"))
    #expect(ssh.arguments.contains("KbdInteractiveAuthentication=no"))
    #expect(ssh.arguments.contains("IdentityAgent=none"))
    #expect(ssh.environment["SSH_ASKPASS_REQUIRE"] == "force")
}

@Test func anUnencryptedIdentityFileVerifiesWithNoPromptAndKeepsBatchMode() throws {
    let hash = String(repeating: "A", count: 64)
    let root = try verificationFixture(cipher: "none")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = PassphraseExecutor()
    var prompted = false

    _ = try CLI.run(
        arguments: [
            "verify", "remote", "--ctk-sha256", hash,
            "--identity-file", root.appendingPathComponent("identity").path,
            "--target", "deploy@example.test",
        ],
        executor: executor,
        identityFileUnlockReader: { prompted = true; return Data() }
    )

    #expect(!prompted)
    let ssh = executor.requests.first { $0.executable == .ssh }!
    #expect(ssh.arguments.contains("BatchMode=yes"))
    #expect(ssh.standardInput == nil)
    #expect(ssh.environment["SSH_ASKPASS"] == nil)
}

@Test func anEncryptedIdentityFileWithNoTerminalExplainsTheWayOut() throws {
    let root = try verificationFixture(cipher: "aes256-ctr")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = PassphraseExecutor()

    #expect(throws: CLIError.self) {
        try CLI.run(
            arguments: [
                "verify", "local", "--ctk-sha256", String(repeating: "A", count: 64),
                "--identity-file", root.appendingPathComponent("identity").path,
            ],
            executor: executor
        )
    }
}

private func verificationFixture(cipher: String) throws -> URL {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let identityFile = root.appendingPathComponent("identity")
    try Data(opensshContainer(cipher: cipher).utf8).write(to: identityFile)
    try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
        .write(to: URL(fileURLWithPath: identityFile.path + ".pub"))
    return root
}

/// The smallest byte sequence that carries a cipher name where OpenSSH puts it.
private func opensshContainer(cipher: String) -> String {
    var blob = Data("openssh-key-v1\0".utf8)
    let name = Data(cipher.utf8)
    blob.append(contentsOf: (0..<4).reversed().map { UInt8((name.count >> ($0 * 8)) & 0xff) })
    blob.append(name)
    blob.append(Data(repeating: 0, count: 32))
    return """
    -----BEGIN OPENSSH PRIVATE KEY-----
    \(blob.base64EncodedString())
    -----END OPENSSH PRIVATE KEY-----
    """
}

private func generateKey(at path: String, passphrase: String) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: SystemExecutable.sshKeygen.path)
    process.arguments = ["-q", "-t", "ecdsa", "-N", passphrase, "-f", path]
    process.standardInput = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
}

private final class PassphraseExecutor: SubprocessExecuting {
    private(set) var requests: [SubprocessRequest] = []

    func run(_ request: SubprocessRequest) throws -> SubprocessResult {
        requests.append(request)
        if request.executable == .codesign {
            return request.arguments.first == "-dr"
                ? passphraseResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")
                : passphraseResult()
        }
        if request.executable == .scAuth {
            let typeIndex = request.arguments.firstIndex(of: "-t")!
            return passphraseResult(stdout: passphraseIdentityTable(hashType: request.arguments[typeIndex + 1]))
        }
        if request.arguments.first == "-K" {
            let directory = request.currentDirectoryURL!
            try Data("identityFile".utf8).write(to: directory.appendingPathComponent("id_test"))
            try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
                .write(to: directory.appendingPathComponent("id_test.pub"))
            return passphraseResult(stderr: [
                "\(AskPassResponder.successMarker):pin",
                "\(AskPassResponder.successMarker):passphrase",
                "\(AskPassResponder.successMarker):passphrase",
            ].joined(separator: "\n"))
        }
        if request.arguments.first == "-l" {
            return passphraseResult(stdout: "256 SHA256:\(String(repeating: "C", count: 43)) test (ECDSA-SK)\n")
        }
        if request.arguments.prefix(2) == ["-Y", "sign"] {
            try Data("signature".utf8).write(to: URL(fileURLWithPath: request.arguments.last! + ".sig"))
        }
        return passphraseResult()
    }
}

private func passphraseResult(stdout: String = "", stderr: String = "") -> SubprocessResult {
    SubprocessResult(stdout: stdout, stderr: stderr, exitStatus: 0, terminationReason: .exit, timedOut: false)
}

private func passphraseIdentityTable(hashType: String) -> String {
    let hash = switch hashType {
    case "sha1": String(repeating: "B", count: 40)
    case "ssh": "SHA256:" + String(repeating: "C", count: 43)
    default: String(repeating: "A", count: 64)
    }
    let header = "Key Type  Public Key Hash                                                   Prot  Label   Common Name  Email Address  Valid To                  Valid"
    let row = "p-256-ne  \(hash.padding(toLength: 66, withPad: " ", startingAt: 0))none  deploy  CN           email          2027-01-01 00:00:00 +0000 YES"
    return header + "\n" + row + "\n"
}

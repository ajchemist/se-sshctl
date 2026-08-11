import Foundation
import Testing
@testable import SSHCTLCore

@Test func wrapperInstallMatchesFingerprintAndRefusesImplicitOverwrite() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let destination = root.appendingPathComponent("identity")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor()

    let report = try WrapperInstaller(executor: executor).install(
        ctkSHA256: hash, destination: destination, passphrase: Data()
    )

    #expect(report.identityFile == destination.path)
    #expect(report.publicKey == "sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ==")
    #expect(FileManager.default.fileExists(atPath: destination.path))
    #expect(FileManager.default.fileExists(atPath: destination.path + ".pub"))
    let wrapperMode = try #require(
        FileManager.default.attributesOfItem(atPath: destination.path)[.posixPermissions] as? NSNumber
    )
    let publicKeyMode = try #require(
        FileManager.default.attributesOfItem(atPath: destination.path + ".pub")[.posixPermissions] as? NSNumber
    )
    #expect(wrapperMode.intValue == 0o400)
    #expect(publicKeyMode.intValue == 0o444)
    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.arguments == ["-K", "-w", "/usr/lib/ssh-keychain.dylib"])
    #expect(download.environment["KEYCHAIN_CERTIFICATES"] == String(repeating: "B", count: 40))
    #expect(download.standardInput == Data("0\n\n\n".utf8))
    #expect(throws: OperationalCommandError.destinationExists) {
        try WrapperInstaller(executor: executor).install(
            ctkSHA256: hash, destination: destination, passphrase: Data()
        )
    }
}

@Test func wrapperInstallRefusesAmbiguousCrossFormatIdentityMetadata() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(duplicateMetadata: true)

    #expect(throws: OperationalCommandError.identityMetadataAmbiguous) {
        try WrapperInstaller(executor: executor).install(
            ctkSHA256: hash,
            destination: root.appendingPathComponent("identity"),
            passphrase: Data()
        )
    }
    #expect(!executor.requests.contains { $0.arguments.first == "-K" })
}

@Test func wrapperInstallSuppliesNonEmptyPassphraseTwice() throws {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor()

    _ = try WrapperInstaller(executor: executor).install(
        ctkSHA256: hash,
        destination: root.appendingPathComponent("identity"),
        passphrase: Data("test passphrase".utf8)
    )

    let download = executor.requests.first { $0.arguments.first == "-K" }!
    #expect(download.standardInput == Data("0\ntest passphrase\ntest passphrase\n".utf8))
}

@Test func failedWrapperInstallDoesNotDeleteACompetitorInstall() {
    let hash = String(repeating: "A", count: 64)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let destination = root.appendingPathComponent("identity")
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = OperationalExecutor(racingDestination: destination)

    #expect(throws: (any Error).self) {
        try WrapperInstaller(executor: executor).install(
            ctkSHA256: hash, destination: destination, passphrase: Data()
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
    let wrapper = root.appendingPathComponent("identity")
    try Data("wrapper".utf8).write(to: wrapper)
    try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
        .write(to: URL(fileURLWithPath: wrapper.path + ".pub"))
    let executor = OperationalExecutor()

    let report = try LocalVerifier(executor: executor).verify(ctkSHA256: hash, wrapper: wrapper)

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
    let wrapper = root.appendingPathComponent("identity")
    try Data("wrapper".utf8).write(to: wrapper)
    try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
        .write(to: URL(fileURLWithPath: wrapper.path + ".pub"))
    let executor = OperationalExecutor()

    let report = try RemoteVerifier(executor: executor).verify(
        ctkSHA256: hash,
        wrapper: wrapper.path,
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

    init(duplicateMetadata: Bool = false, racingDestination: URL? = nil) {
        self.duplicateMetadata = duplicateMetadata
        self.racingDestination = racingDestination
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
                duplicateMetadata: duplicateMetadata
            ))
        }
        if request.arguments.first == "-K" {
            let directory = request.currentDirectoryURL!
            try Data("wrapper".utf8).write(to: directory.appendingPathComponent("id_test"))
            try Data("sk-ecdsa-sha2-nistp256@openssh.com QUFBQQ== test\n".utf8)
                .write(to: directory.appendingPathComponent("id_test.pub"))
            return operationalResult()
        }
        if request.arguments.first == "-l" {
            if let racingDestination {
                try Data("competitor wrapper".utf8).write(to: racingDestination)
                try Data("competitor public key".utf8)
                    .write(to: URL(fileURLWithPath: racingDestination.path + ".pub"))
            }
            return operationalResult(stdout: "256 \(sshFingerprint) test (ECDSA-SK)\n")
        }
        if request.arguments.prefix(2) == ["-Y", "sign"] {
            let challenge = request.arguments.last!
            try Data("signature".utf8).write(to: URL(fileURLWithPath: challenge + ".sig"))
        }
        return operationalResult()
    }
}

private let sshFingerprint = "SHA256:" + String(repeating: "C", count: 43)

private func identityTable(hashType: String, duplicateMetadata: Bool) -> String {
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
    let row = lines[1].replacingOccurrences(of: String(repeating: "A", count: 64), with: paddedHash)
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

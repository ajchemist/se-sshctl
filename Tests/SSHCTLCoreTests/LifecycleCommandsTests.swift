import Foundation
import Testing
@testable import SSHCTLCore

@Test func noneProtectionRequiresExplicitUnattendedSigningAcknowledgement() {
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: IdentityLifecycleError.unattendedSigningNotAcknowledged) {
        try IdentityCreator(executor: executor).create(
            label: "deploy",
            keyType: "p-256-ne",
            protection: "none",
            allowUnattendedSigning: false
        )
    }
    #expect(executor.requests.isEmpty)
}

@Test func creationPreservesScAuthParameterNamesAndValues() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: false))),
        .success(lifecycleResult()),
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: true))),
    ])
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }

    let output = try CLI.run(
        arguments: [
            "identity", "create", "-l", "deploy key 東京",
            "-k", "p-256-ne", "-t", "none", "--allow-unattended-signing",
        ],
        executor: executor,
        lockDirectory: lockDirectory
    )

    #expect(output.contains(String(repeating: "A", count: 64)))
    #expect(executor.requests[1].arguments == [
        "create-ctk-identity", "-l", "deploy key 東京",
        "-k", "p-256-ne", "-t", "none",
    ])
}

@Test func creationRejectsNonSSHKeyTypesAndUnknownProtection() {
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: IdentityLifecycleError.unsupportedKeyType) {
        try IdentityCreator(executor: executor).create(
            label: "deploy", keyType: "p-384-ne", protection: "bio", allowUnattendedSigning: false
        )
    }
    #expect(throws: IdentityLifecycleError.invalidProtection) {
        try IdentityCreator(executor: executor).create(
            label: "deploy", keyType: "p-256-ne", protection: "interactive", allowUnattendedSigning: false
        )
    }
    #expect(executor.requests.isEmpty)
}

private func identityFixture(includeIdentity: Bool) -> String {
    let text = try! String(
        contentsOf: Bundle.module.url(
            forResource: "identities-multiple",
            withExtension: "txt",
            subdirectory: "Fixtures"
        )!,
        encoding: .utf8
    )
    let lines = text.split(whereSeparator: \Character.isNewline)
    return ([String(lines[0])] + (includeIdentity ? [String(lines[1])] : [])).joined(separator: "\n") + "\n"
}

private func lifecycleResult(stdout: String = "", stderr: String = "") -> SubprocessResult {
    SubprocessResult(
        stdout: stdout,
        stderr: stderr,
        exitStatus: 0,
        terminationReason: .exit,
        timedOut: false
    )
}

private func uniqueTemporaryDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
}

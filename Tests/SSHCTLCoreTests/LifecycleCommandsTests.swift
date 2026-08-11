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

@Test func nativeDeletionPreservesScAuthSHA1HashOptionAndVerifiesAbsence() throws {
    let hash = String(repeating: "B", count: 40)
    let executor = FakeSubprocessExecutor(results: [
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: true, hashType: .sha1))),
        .success(lifecycleResult()),
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: false, hashType: .sha1))),
    ])
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }

    let output = try CLI.run(
        arguments: ["identity", "delete", "-h", hash, "--confirm", hash],
        executor: executor,
        lockDirectory: lockDirectory
    )

    #expect(output == "Deleted SHA-1/hex \(hash)")
    #expect(executor.requests[1].arguments == ["delete-ctk-identity", "-h", hash])
}

@Test func retirementRequiresExactConfirmationAndVerifiesAbsence() throws {
    let hash = String(repeating: "A", count: 64)
    let executor = FakeSubprocessExecutor(results: [
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: true))),
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: true, hashType: .sha1))),
        .success(lifecycleResult()),
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: false))),
    ])
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }

    let report = try IdentityRetirer(executor: executor, lockDirectory: lockDirectory).retire(
        ctkSHA256: hash,
        confirmation: hash,
        remoteAuthorizationCleared: true,
        recoveryAccessVerified: true
    )

    #expect(report.ctkPublicKeyHash == hash)
    #expect(executor.requests[2].arguments == [
        "delete-ctk-identity", "-h", String(repeating: "B", count: 40),
    ])
}

@Test func retirementRefusesMissingRemoteAndRecoveryAcknowledgements() {
    let hash = String(repeating: "A", count: 64)
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: IdentityLifecycleError.retirementSafetyNotAcknowledged) {
        try IdentityRetirer(executor: executor).retire(
            ctkSHA256: hash,
            confirmation: hash,
            remoteAuthorizationCleared: false,
            recoveryAccessVerified: true
        )
    }
    #expect(executor.requests.isEmpty)
}

private func identityFixture(
    includeIdentity: Bool,
    hashType: CTKIdentityHashType = .sha256
) -> String {
    let text = try! String(
        contentsOf: Bundle.module.url(
            forResource: "identities-multiple",
            withExtension: "txt",
            subdirectory: "Fixtures"
        )!,
        encoding: .utf8
    )
    let lines = text.split(whereSeparator: \Character.isNewline)
    var row = String(lines[1])
    if hashType == .sha1 {
        row = row.replacingOccurrences(
            of: String(repeating: "A", count: 64),
            with: String(repeating: "B", count: 40) + String(repeating: " ", count: 24)
        )
    }
    return ([String(lines[0])] + (includeIdentity ? [row] : [])).joined(separator: "\n") + "\n"
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

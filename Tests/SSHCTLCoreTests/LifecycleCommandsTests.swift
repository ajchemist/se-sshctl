import Darwin
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

@Test func aSecondIdentityOperationRefusesWhileAnotherHoldsTheLock() throws {
    // Two concurrent creates would each snapshot the identity list before the
    // other's sc_auth call landed, and both would then attribute the same new
    // identity to themselves. The lock has to refuse rather than queue.
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }
    try FileManager.default.createDirectory(
        at: lockDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
    )
    let lockPath = lockDirectory.appendingPathComponent("operation.lock").path
    let held = Darwin.open(lockPath, O_CREAT | O_RDWR, 0o600)
    try #require(held >= 0)
    try #require(flock(held, LOCK_EX | LOCK_NB) == 0)
    defer { flock(held, LOCK_UN); Darwin.close(held) }
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: IdentityLifecycleError.operationBusy) {
        try IdentityCreator(executor: executor, lockDirectory: lockDirectory).create(
            label: "deploy", keyType: "p-256-ne", protection: "bio", allowUnattendedSigning: false
        )
    }
    // Refused before touching sc_auth, so a contended run cannot create anything.
    #expect(executor.requests.isEmpty)
}

@Test func cancelledBiometricCreationLeavesNothingBehind() throws {
    // Declining Touch ID makes sc_auth exit non-zero. The tool must surface
    // that, and must not go on to claim an identity it never created.
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }
    let executor = FakeSubprocessExecutor(results: [
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: false))),
        .success(SubprocessResult(
            stdout: "",
            stderr: "Error creating identity: user canceled the request\n",
            exitStatus: 1,
            terminationReason: .exit,
            timedOut: false
        )),
    ])

    #expect(throws: IdentityLifecycleError.commandFailed("Error creating identity: user canceled the request")) {
        try IdentityCreator(executor: executor, lockDirectory: lockDirectory).create(
            label: "deploy", keyType: "p-256-ne", protection: "bio", allowUnattendedSigning: false
        )
    }
    // It stopped at the failed create: no post-create listing was attempted.
    #expect(executor.requests.count == 2)
}

@Test func biometricCreationWaitsLongerThanTheUnattendedPath() throws {
    // A bio create blocks on a human reaching for the sensor; reusing the
    // unattended timeout would kill the prompt mid-approval.
    let lockDirectory = uniqueTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: lockDirectory) }
    let executor = FakeSubprocessExecutor(results: [
        .success(lifecycleResult(stdout: identityFixture(includeIdentity: false))),
        .success(SubprocessResult(
            stdout: "", stderr: "", exitStatus: 1, terminationReason: .exit, timedOut: false
        )),
    ])

    #expect(throws: IdentityLifecycleError.self) {
        try IdentityCreator(executor: executor, lockDirectory: lockDirectory).create(
            label: "deploy", keyType: "p-256-ne", protection: "bio", allowUnattendedSigning: false
        )
    }

    let create = executor.requests.first { $0.arguments.first == "create-ctk-identity" }
    #expect(create?.timeout == CTKProtection.bio.creationTimeout)
    #expect(CTKProtection.bio.creationTimeout > CTKProtection.none.creationTimeout)
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

import Foundation
import Testing
@testable import SSHCTLCore

@Test func aLocalRunDoesNotEraseAnEarlierRemoteResult() throws {
    // Results accumulate. If verify local overwrote remoteAuthentication with
    // not-run, yesterday's remote pass would be reported as never attempted —
    // the same "not tested" confusion the tri-state work removed, displaced in
    // time.
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let monday = Date(timeIntervalSince1970: 1_800_000_000)
    let identityFile = "/Users/example/.ssh/identities/id_test"

    try VerificationManifestStore(directory: root, now: { monday })
        .record(remoteReport(status: .passed), identityFile: identityFile)
    try VerificationManifestStore(directory: root, now: { monday.addingTimeInterval(86_400) })
        .record(localReport(), identityFile: identityFile)

    let entry = try #require(VerificationManifestStore(directory: root).load().identities.first)
    #expect(entry.localSigning.outcome == .passed)
    #expect(entry.remoteAuthentication.outcome == .passed)
    #expect(entry.remoteAuthentication.at == monday)
    #expect(entry.localSigning.at == monday.addingTimeInterval(86_400))
    #expect(entry.target == "deploy@example.test")
}

@Test func aLaterFailureReplacesAnEarlierPass() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let identityFile = "/Users/example/.ssh/identities/id_test"

    try VerificationManifestStore(directory: root).record(
        remoteReport(status: .passed), identityFile: identityFile
    )
    try VerificationManifestStore(directory: root).record(
        remoteReport(status: .failed), identityFile: identityFile
    )

    let entry = try #require(VerificationManifestStore(directory: root).load().identities.first)
    #expect(entry.remoteAuthentication.outcome == .failed)
    #expect(try VerificationManifestStore(directory: root).load().identities.count == 1)
}

@Test func aRunThatNeverMatchedAFingerprintIsNotRecorded() throws {
    // The specification asks that the manifest be written only after state and
    // fingerprint checks pass. An entry keyed to an identity this run never
    // resolved would be a guess about which key it refers to.
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let report = VerificationReport(
        status: .failed,
        kind: "local",
        ctkSHA256: String(repeating: "A", count: 64),
        target: nil,
        checks: VerificationChecks(providerLoad: .failed),
        sshFingerprint: nil
    )

    let recorded = try VerificationManifestStore(directory: root)
        .record(report, identityFile: "/Users/example/.ssh/id_test")

    #expect(!recorded)
    #expect(try VerificationManifestStore(directory: root).load().identities.isEmpty == true)
}

@Test func pruneDropsRecordsWhoseIdentityFileOrCTKIdentityIsGone() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let present = root.appendingPathComponent("kept").path
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try Data("identityFile".utf8).write(to: URL(fileURLWithPath: present))
    let store = VerificationManifestStore(directory: root)
    let hash = String(repeating: "A", count: 64)
    let otherHash = String(repeating: "E", count: 64)
    try store.record(localReport(ctkSHA256: hash), identityFile: present)
    try store.record(localReport(ctkSHA256: otherHash), identityFile: present)
    try store.record(localReport(ctkSHA256: hash), identityFile: root.appendingPathComponent("gone").path)

    let removed = try store.prune(knownIdentityHashes: [hash])

    // One record lost its file, one lost its CTK identity.
    #expect(removed.count == 2)
    let kept = try store.load().identities
    #expect(kept.count == 1)
    #expect(kept[0].ctkSHA256 == hash)
    #expect(kept[0].identityFile == present)
}

@Test func pruneNeverTouchesTheIdentityFilesThemselves() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let present = root.appendingPathComponent("kept").path
    try Data("identityFile".utf8).write(to: URL(fileURLWithPath: present))
    let store = VerificationManifestStore(directory: root)
    try store.record(localReport(), identityFile: present)

    _ = try store.prune(knownIdentityHashes: [])

    #expect(FileManager.default.fileExists(atPath: present))
}

@Test func theStoreIsPrivateToItsOwner() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = VerificationManifestStore(directory: root)

    try store.record(localReport(), identityFile: "/Users/example/.ssh/id_test")

    let fileMode = try #require(
        FileManager.default.attributesOfItem(atPath: store.url.path)[.posixPermissions] as? NSNumber
    )
    let directoryMode = try #require(
        FileManager.default.attributesOfItem(atPath: root.path)[.posixPermissions] as? NSNumber
    )
    #expect(fileMode.intValue == 0o600)
    #expect(directoryMode.intValue == 0o700)
}

@Test func outcomesAreAlwaysShownWithTheirAge() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let recordedAt = Date(timeIntervalSince1970: 1_800_000_000)
    try VerificationManifestStore(directory: root, now: { recordedAt })
        .record(localReport(), identityFile: "/Users/example/.ssh/id_test")
    let executor = FakeSubprocessExecutor(results: [])

    let output = try CLI.run(
        arguments: ["manifest", "list"],
        executor: executor,
        manifestDirectory: root,
        now: { recordedAt.addingTimeInterval(37 * 86_400) }
    )

    // A pass from 37 days ago is still a pass, but the operator cannot judge
    // whether it is current without seeing when it happened.
    #expect(output.contains("local signing:         passed (37d ago)"))
    #expect(output.contains("remote authentication: not-run"))
    #expect(executor.requests.isEmpty)
}

@Test func anEmptyStoreSaysSoInsteadOfPrintingNothing() throws {
    let root = uniqueDirectory()
    defer { try? FileManager.default.removeItem(at: root) }

    let output = try CLI.run(
        arguments: ["manifest", "list"],
        executor: FakeSubprocessExecutor(results: []),
        manifestDirectory: root
    )

    #expect(output == "No recorded verifications.")
}

private func uniqueDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
}

private func localReport(ctkSHA256: String = String(repeating: "A", count: 64)) -> VerificationReport {
    VerificationReport(
        status: .passed,
        kind: "local",
        ctkSHA256: ctkSHA256,
        target: nil,
        checks: VerificationChecks(providerLoad: .passed, localSigning: .passed),
        sshFingerprint: "SHA256:" + String(repeating: "C", count: 43)
    )
}

private func remoteReport(status: VerificationOutcome) -> VerificationReport {
    VerificationReport(
        status: status,
        kind: "remote",
        ctkSHA256: String(repeating: "A", count: 64),
        target: "deploy@example.test",
        checks: VerificationChecks(
            providerLoad: .passed,
            remoteAuthentication: status
        ),
        sshFingerprint: "SHA256:" + String(repeating: "C", count: 43)
    )
}

import Foundation
import Testing
@testable import SSHCTLCore

private let sha256Hash = String(repeating: "A", count: 64)
private let sha1Hash = String(repeating: "B", count: 40)
private let sshFingerprint = "SHA256:" + String(repeating: "C", count: 43)

@Test func deletionPreviewShowsTheFingerprintAndDestroysNothing() throws {
    // The handoff wants the SSH fingerprint displayed and then approved, in
    // that order. Approving a hash pasted from elsewhere is not that: the
    // fingerprint is the only identifier a server knows this key by.
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = VerificationManifestStore(directory: root)
    try store.record(deleteReport(), identityFile: root.appendingPathComponent("id_test").path)
    let executor = DeleteExecutor()

    let output = try CLI.run(
        arguments: ["identity", "delete", "--ctk-sha256", sha256Hash],
        executor: executor,
        manifestDirectory: root
    )

    #expect(output.contains(sshFingerprint))
    #expect(output.contains(sha256Hash))
    #expect(output.contains(sha1Hash))
    #expect(output.contains("deploy"))
    #expect(output.contains("-k p-256-ne -t none"))
    #expect(output.contains("--confirm \(sha256Hash)"))
    // Nothing destructive ran: sc_auth was only ever asked to list.
    #expect(executor.requests.allSatisfy { $0.arguments.first == "list-ctk-identities" })
}

@Test func deletionResolvesTheSHA1LocatorSoTheOperatorNeverPassesIt() throws {
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = DeleteExecutor()

    let output = try CLI.run(
        arguments: ["identity", "delete", "--ctk-sha256", sha256Hash, "--confirm", sha256Hash],
        executor: executor,
        lockDirectory: root,
        manifestDirectory: root
    )

    let deletion = try #require(executor.requests.first { $0.arguments.first == "delete-ctk-identity" })
    // Selected by the stable SHA-256 hash, deleted by sc_auth's own SHA-1
    // locator, which the operator never sees or types.
    #expect(deletion.arguments == ["delete-ctk-identity", "-h", sha1Hash])
    #expect(deletion.executable == .scAuth)
    #expect(output.contains("Deleted CTK SHA-256/hex \(sha256Hash)"))
    #expect(output.contains(sshFingerprint))
}

@Test func deletionRefusesAMismatchedConfirmationBeforeTouchingScAuth() {
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let executor = DeleteExecutor()

    #expect(throws: IdentityLifecycleError.confirmationMismatch) {
        try IdentityDeleter(
            executor: executor,
            manifestStore: VerificationManifestStore(directory: root),
            lockDirectory: root
        ).delete(ctkSHA256: sha256Hash, confirmation: String(repeating: "D", count: 64))
    }
    #expect(executor.requests.isEmpty)
}

@Test func deletionIsNotBelievedUntilTheIdentityIsAbsentInBothFormats() {
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    // sc_auth exits 0 but the identity is still listed afterwards.
    let executor = DeleteExecutor(survivesDeletion: true)

    #expect(throws: IdentityLifecycleError.deletionNotVerified) {
        try IdentityDeleter(
            executor: executor,
            manifestStore: VerificationManifestStore(directory: root),
            lockDirectory: root
        ).delete(ctkSHA256: sha256Hash, confirmation: sha256Hash)
    }
}

@Test func deletionRefusesWhenTheMetadataCannotIdentifyOneRow() {
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    // Two rows share every metadata field, so the SHA-1 locator is ambiguous.
    let executor = DeleteExecutor(duplicateMetadata: true)

    #expect(throws: OperationalCommandError.identityMetadataAmbiguous) {
        try IdentityDeleter(
            executor: executor,
            manifestStore: VerificationManifestStore(directory: root),
            lockDirectory: root
        ).delete(ctkSHA256: sha256Hash, confirmation: sha256Hash)
    }
    #expect(!executor.requests.contains { $0.arguments.first == "delete-ctk-identity" })
}

@Test func deletionAlsoRemovesTheIdentityFileAndItsRecord() throws {
    // Deleting the enclave key turns the identity file into a handle to
    // nothing and the record into a claim about nothing. Leaving either
    // behind makes deletion a first step the operator has to remember to
    // finish.
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let identityFile = root.appendingPathComponent("id_test").path
    try Data("identityFile".utf8).write(to: URL(fileURLWithPath: identityFile))
    try Data("public".utf8).write(to: URL(fileURLWithPath: identityFile + ".pub"))
    let store = VerificationManifestStore(directory: root)
    try store.record(deleteReport(), identityFile: identityFile)

    let report = try IdentityDeleter(
        executor: DeleteExecutor(),
        manifestStore: store,
        lockDirectory: root
    ).delete(ctkSHA256: sha256Hash, confirmation: sha256Hash)

    #expect(report.removedRecords == 1)
    #expect(report.removedFiles.sorted() == [identityFile, identityFile + ".pub"].sorted())
    #expect(!FileManager.default.fileExists(atPath: identityFile))
    #expect(!FileManager.default.fileExists(atPath: identityFile + ".pub"))
    #expect(try store.load().identities.isEmpty == true)
}

@Test func deletionLeavesAPathThatNowHoldsADifferentKey() throws {
    let root = uniqueDeleteDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let identityFile = root.appendingPathComponent("reused").path
    try Data("someone else's key".utf8).write(to: URL(fileURLWithPath: identityFile))
    try Data("public".utf8).write(to: URL(fileURLWithPath: identityFile + ".pub"))
    let store = VerificationManifestStore(directory: root)
    try store.record(deleteReport(), identityFile: identityFile)

    let report = try IdentityDeleter(
        executor: DeleteExecutor(foreignFingerprint: true),
        manifestStore: store,
        lockDirectory: root
    ).delete(ctkSHA256: sha256Hash, confirmation: sha256Hash)

    #expect(report.removedFiles.isEmpty)
    #expect(report.keptFiles == [identityFile])
    #expect(FileManager.default.fileExists(atPath: identityFile))
}

private func uniqueDeleteDirectory() -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
}

private func deleteReport() -> VerificationReport {
    VerificationReport(
        status: .passed,
        kind: "local",
        ctkSHA256: sha256Hash,
        target: nil,
        checks: VerificationChecks(providerLoad: .passed, localSigning: .passed),
        sshFingerprint: sshFingerprint
    )
}

private final class DeleteExecutor: SubprocessExecuting {
    private(set) var requests: [SubprocessRequest] = []
    private let survivesDeletion: Bool
    private let duplicateMetadata: Bool
    private let foreignFingerprint: Bool
    private var deleted = false

    init(
        survivesDeletion: Bool = false,
        duplicateMetadata: Bool = false,
        foreignFingerprint: Bool = false
    ) {
        self.survivesDeletion = survivesDeletion
        self.duplicateMetadata = duplicateMetadata
        self.foreignFingerprint = foreignFingerprint
    }

    func run(_ request: SubprocessRequest) throws -> SubprocessResult {
        requests.append(request)
        if request.arguments.first == "delete-ctk-identity" {
            deleted = true
            return deleteResult()
        }
        if request.arguments.first == "list-ctk-identities" {
            let typeIndex = request.arguments.firstIndex(of: "-t")!
            let present = !deleted || survivesDeletion
            return deleteResult(stdout: identityTable(
                hashType: request.arguments[typeIndex + 1],
                present: present,
                duplicateMetadata: duplicateMetadata
            ))
        }
        if request.arguments.first == "-l" {
            let fingerprint = foreignFingerprint
                ? "SHA256:" + String(repeating: "E", count: 43)
                : sshFingerprint
            return deleteResult(stdout: "256 \(fingerprint) test (ECDSA-SK)\n")
        }
        return deleteResult()
    }
}

private func deleteResult(stdout: String = "") -> SubprocessResult {
    SubprocessResult(stdout: stdout, stderr: "", exitStatus: 0, terminationReason: .exit, timedOut: false)
}

private func identityTable(hashType: String, present: Bool, duplicateMetadata: Bool) -> String {
    let hash = switch hashType {
    case "sha1": sha1Hash
    case "ssh": sshFingerprint
    default: sha256Hash
    }
    let other = switch hashType {
    case "sha1": String(repeating: "F", count: 40)
    case "ssh": "SHA256:" + String(repeating: "G", count: 43)
    default: String(repeating: "F", count: 64)
    }
    let header = "Key Type  Public Key Hash                                                   Prot  Label   Common Name  Email Address  Valid To                  Valid"
    func row(_ value: String) -> String {
        "p-256-ne  \(value.padding(toLength: 66, withPad: " ", startingAt: 0))none  deploy  CN           email          2030-01-01 00:00:00 +0000 YES"
    }
    var rows: [String] = []
    if present { rows.append(row(hash)) }
    // A second row with identical metadata makes the cross-format match ambiguous.
    if duplicateMetadata { rows.append(row(other)) }
    return ([header] + rows).joined(separator: "\n") + "\n"
}

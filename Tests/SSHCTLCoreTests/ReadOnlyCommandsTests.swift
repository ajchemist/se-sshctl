import Foundation
import Testing
@testable import SSHCTLCore

@Test func doctorReportsVersionedReadOnlyEvidence() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(result(stdout: "26.6.1\n")),
        .success(result(stdout: "25G76\n")),
        .success(result(stdout: "arm64\n")),
        .success(result(stderr: "OpenSSH_10.3p1, LibreSSL 3.3.6\n")),
        .success(result()),
        .success(result(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ])
    let doctor = Doctor(
        executor: executor,
        pathExists: { ["/usr/sbin/sc_auth", "/usr/bin/ssh", "/usr/lib/ssh-keychain.dylib"].contains($0) }
    )

    let report = try doctor.report()

    #expect(report.schemaVersion == 2)
    #expect(report.platform.verifiedRelease == true)
    #expect(report.platform.minimumVerifiedRelease == "26")
    #expect(report.platform.version == "26.6.1")
    #expect(report.platform.build == "25G76")
    #expect(report.platform.architecture == "arm64")
    #expect(report.openSSH.version == "OpenSSH_10.3p1, LibreSSL 3.3.6")
    #expect(report.provider.signatureValid)
    #expect(report.provider.appleAnchored)
    #expect(report.provider.identifier == "com.apple.ssh-keychain")
    #expect(executor.requests.map(\.executable) == [.swVers, .swVers, .uname, .ssh, .codesign, .codesign])
}

@Test func identityListUsesOnlyTheReadOnlyScAuthCommand() throws {
    let executor = FakeSubprocessExecutor(results: [.success(result(stdout: fixtureText("identities-empty")))])

    let report = try IdentityLister(executor: executor).list()

    #expect(report.schemaVersion == 2)
    #expect(report.hashType == .sha256)
    #expect(report.hashEncoding == .hex)
    #expect(report.identities.isEmpty)
    #expect(executor.requests == [
        SubprocessRequest(
            executable: .scAuth,
            arguments: ["list-ctk-identities", "-t", "sha256", "-e", "hex"]
        ),
    ])
}

@Test func doctorReportsMissingProviderWithoutRunningCodesign() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(result(stdout: "26.6.1\n")),
        .success(result(stdout: "25G76\n")),
        .success(result(stdout: "arm64\n")),
        .success(result(stderr: "OpenSSH_10.3p1\n")),
    ])

    let report = try Doctor(executor: executor, pathExists: { $0 != "/usr/lib/ssh-keychain.dylib" }).report()

    #expect(!report.provider.available)
    #expect(!report.provider.signatureValid)
    #expect(!report.provider.appleAnchored)
    #expect(report.provider.identifier == nil)
    #expect(!executor.requests.contains { $0.executable == .codesign })
}

@Test func jsonOutputIsSchemaVersionedAndDeterministic() throws {
    let report = IdentityListReport(identities: [])

    #expect(try JSONOutput.encode(report) == #"{"hashEncoding":"hex","hashType":"sha256","identities":[],"schemaVersion":2}"#)
}

@Test func jsonKeyTypeAndProtectionKeepTheirNativeScAuthSpelling() throws {
    // Typing these fields must not change the wire format: external tooling
    // reads the sc_auth values, not Swift case names.
    let report = IdentityListReport(identities: [
        CTKIdentity(
            keyType: .p256NonExportable,
            ctkPublicKeyHash: String(repeating: "A", count: 64),
            protection: .none,
            label: "deploy",
            commonName: "",
            emailAddress: "",
            validTo: "2027-01-01 00:00:00 +0000",
            certificateValid: true
        ),
    ])

    let json = try JSONOutput.encode(report)

    #expect(json.contains(#""keyType":"p-256-ne""#))
    #expect(json.contains(#""protection":"none""#))
}

private func result(
    stdout: String = "",
    stderr: String = "",
    exitStatus: Int32 = 0,
    terminationReason: SubprocessResult.TerminationReason = .exit,
    timedOut: Bool = false
) -> SubprocessResult {
    SubprocessResult(
        stdout: stdout,
        stderr: stderr,
        exitStatus: exitStatus,
        terminationReason: terminationReason,
        timedOut: timedOut
    )
}

private func fixtureText(_ name: String) -> String {
    let url = Bundle.module.url(forResource: name, withExtension: "txt", subdirectory: "Fixtures")!
    return try! String(contentsOf: url, encoding: .utf8)
}

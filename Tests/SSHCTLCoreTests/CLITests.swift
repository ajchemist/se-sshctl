import Foundation
import Testing
@testable import SSHCTLCore

@Test func cliRoutesDoctorJSON() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(cliResult(stdout: "26.6.1\n")),
        .success(cliResult(stdout: "25G76\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_10.3p1\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ])

    let output = try CLI.run(
        arguments: ["doctor", "--json"],
        executor: executor,
        pathExists: { _ in true }
    )

    #expect(output.contains(#""schemaVersion":2"#))
    #expect(output.contains(#""appleAnchored":true"#))
}

@Test func doctorTextOutputKeepsEveryProviderEvidenceFieldSeparate() throws {
    // docs/THREAT_MODEL.md trust boundary 2: path, signature validity,
    // identifier, and Apple anchor evidence are four independent signals.
    // A provider that verifies but is anchored elsewhere must not read as
    // trusted, so this fixture signs successfully under a non-Apple anchor.
    let executor = FakeSubprocessExecutor(results: [
        .success(cliResult(stdout: "26.6.1\n")),
        .success(cliResult(stdout: "25G76\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_10.3p1\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.example.impostor\" and anchor trusted\n")),
    ])

    let output = try CLI.run(arguments: ["doctor"], executor: executor, pathExists: { _ in true })

    #expect(output.contains("/usr/lib/ssh-keychain.dylib"))
    #expect(output.contains("present:    yes"))
    #expect(output.contains("signature:  valid"))
    #expect(output.contains("anchor:     not apple"))
    #expect(output.contains("identifier: unknown"))
    #expect(!output.contains("verified"))
}

@Test func doctorTextOutputNamesATrustedProviderInFull() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(cliResult(stdout: "26.6.1\n")),
        .success(cliResult(stdout: "25G76\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_10.3p1\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ])

    let output = try CLI.run(arguments: ["doctor"], executor: executor, pathExists: { _ in true })

    #expect(output.contains("signature:  valid"))
    #expect(output.contains("anchor:     apple"))
    #expect(output.contains("identifier: com.apple.ssh-keychain"))
    #expect(output.contains("/usr/sbin/sc_auth"))
}

@Test func theBinaryReportsItsOwnVersion() throws {
    // Schema versions moved several times in one release. A binary that cannot
    // say which build it is leaves an operator unable to tell whether the
    // output they are looking at is the shape they expect.
    let executor = FakeSubprocessExecutor(results: [])

    #expect(try CLI.run(arguments: ["--version"], executor: executor) == "se-sshctl \(seSSHCTLVersion)")
    #expect(try CLI.run(arguments: ["version"], executor: executor) == "se-sshctl \(seSSHCTLVersion)")
    #expect(executor.requests.isEmpty)
}

@Test func doctorNamesTheBuildThatProducedTheReport() throws {
    let executor = FakeSubprocessExecutor(results: healthyDoctorResults())

    let json = try CLI.run(
        arguments: ["doctor", "--json"],
        executor: executor,
        pathExists: { _ in true },
        consoleUser: { "operator" }
    )

    #expect(json.contains(#""seSSHCTL":"\#(seSSHCTLVersion)""#))
}

@Test func doctorWarnsWhenNobodyIsLoggedInAtTheConsole() throws {
    // Measured on macOS 26.6.2: a logged-out Mac still enumerates its CTK
    // identities but cannot sign — "device not found". Every binary check
    // below passes in that state, so without this the report is an all-clear
    // in exactly the situation that needs a warning.
    let executor = FakeSubprocessExecutor(results: healthyDoctorResults())

    let output = try CLI.run(
        arguments: ["doctor"],
        executor: executor,
        pathExists: { _ in true },
        consoleUser: { nil }
    )

    #expect(output.contains("console session: none"))
    #expect(output.contains("warning:"))
    #expect(output.contains("device not found"))
    // The binary checks still report what they found; nothing is suppressed.
    #expect(output.contains("signature:  valid"))
    #expect(output.contains("anchor:     apple"))
}

@Test func doctorNamesTheConsoleSessionWhenThereIsOne() throws {
    let executor = FakeSubprocessExecutor(results: healthyDoctorResults())

    let output = try CLI.run(
        arguments: ["doctor"],
        executor: executor,
        pathExists: { _ in true },
        consoleUser: { "operator" }
    )

    #expect(output.contains("console session: operator"))
    #expect(!output.contains("warning:"))
}

private func healthyDoctorResults() -> [Result<SubprocessResult, Error>] {
    [
        .success(cliResult(stdout: "26.6.2\n")),
        .success(cliResult(stdout: "25G83\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_10.3p1\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ]
}

@Test func doctorWarnsBelowTheVerifiedMacOSReleaseWithoutBlocking() throws {
    // Public reports conflict about whether Sequoia works, so this warns
    // rather than refusing: blocking would deny setups that may be fine, and
    // silence leaves the operator debugging an untested OS.
    let executor = FakeSubprocessExecutor(results: [
        .success(cliResult(stdout: "15.6\n")),
        .success(cliResult(stdout: "24G84\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_9.9p2\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ])

    let output = try CLI.run(arguments: ["doctor"], executor: executor, pathExists: { _ in true })

    #expect(output.contains("warning:"))
    #expect(output.contains("macOS 26 and later"))
    #expect(output.contains("Nothing is blocked"))
    // The provider evidence is still reported in full.
    #expect(output.contains("identifier: com.apple.ssh-keychain"))
}

@Test func doctorIsSilentAboutTheReleaseWhenItIsVerified() throws {
    let executor = FakeSubprocessExecutor(results: [
        .success(cliResult(stdout: "26.6.2\n")),
        .success(cliResult(stdout: "25G83\n")),
        .success(cliResult(stdout: "arm64\n")),
        .success(cliResult(stderr: "OpenSSH_10.3p1\n")),
        .success(cliResult()),
        .success(cliResult(stderr: "designated => identifier \"com.apple.ssh-keychain\" and anchor apple\n")),
    ])

    let output = try CLI.run(arguments: ["doctor"], executor: executor, pathExists: { _ in true })

    #expect(!output.contains("warning:"))
}

@Test func anUnreadableReleaseNumberIsNotTreatedAsVerified() {
    let platform = PlatformReport(version: "beta", build: "25G83", architecture: "arm64")

    #expect(platform.verifiedRelease == nil)
}

@Test func cliHelpDocumentsTheCompleteLocalLifecycleWithoutRunningCommands() throws {
    let executor = FakeSubprocessExecutor(results: [])

    let output = try CLI.run(arguments: ["--help"], executor: executor)

    #expect(output.contains("identity create"))
    #expect(output.contains("identity delete"))
    #expect(!output.contains("identity retire"))
    #expect(output.contains("se-sshctl install"))
    #expect(!output.contains("wrapper"))
    #expect(output.contains("verify remote"))
    #expect(output.contains("manifest list"))
    #expect(output.contains("WORKFLOW"))
    #expect(output.contains("~/.ssh/identities/example/id_ecdsa_sk_rk"))
    #expect(output.contains("0400"))
    #expect(output.contains("0444"))
    #expect(executor.requests.isEmpty)
}

@Test func cliHelpIsHierarchicalAndDocumentsEveryLeafOption() throws {
    let executor = FakeSubprocessExecutor(results: [])
    let cases: [([String], [String])] = [
        (["doctor", "--help"], ["--json"]),
        (["identity", "list", "--help"], ["-t", "sha1|sha256|ssh", "-e", "hex|b64", "--json"]),
        (["identity", "create", "--help"], ["-l", "-k", "-t", "p-256-ne", "bio|none", "--allow-unattended-signing", "--unique", "--json"]),
        (["install", "--help"], ["--ctk-sha256", "--identity-file", "--no-passphrase", "--json"]),
        (["identity", "delete", "--help"], ["--ctk-sha256", "--confirm", "SHA256", "sc_auth delete-ctk-identity", "--json"]),
        (["manifest", "list", "--help"], ["--json"]),
        (["manifest", "prune", "--help"], ["--json"]),
        (["config", "render", "--help"], ["--identity-file", "--host-pattern", "--json"]),
        (["verify", "local", "--help"], ["--ctk-sha256", "--identity-file", "--json"]),
        (["verify", "remote", "--help"], ["--ctk-sha256", "--identity-file", "--target", "--json"]),
    ]

    for (arguments, options) in cases {
        let output = try CLI.run(arguments: arguments, executor: executor)
        for option in options { #expect(output.contains(option)) }
    }
    for group in ["identity", "config", "verify", "manifest"] {
        #expect(try CLI.run(arguments: [group, "--help"], executor: executor).contains("SUBCOMMANDS"))
    }
    #expect(executor.requests.isEmpty)
}

@Test func cliRejectsMutatingOrUnknownCommands() {
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["identity", "create"], executor: executor)
    }
    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["identity", "retire"], executor: executor)
    }
    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["wrapper", "install"], executor: executor)
    }
    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["install", "--destination", "/tmp/key"], executor: executor)
    }
    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["verify", "local", "--wrapper", "/tmp/key"], executor: executor)
    }
    #expect(executor.requests.isEmpty)
}

private func cliResult(stdout: String = "", stderr: String = "") -> SubprocessResult {
    SubprocessResult(
        stdout: stdout,
        stderr: stderr,
        exitStatus: 0,
        terminationReason: .exit,
        timedOut: false
    )
}

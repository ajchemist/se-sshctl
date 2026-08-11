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

    #expect(output.contains(#""schemaVersion":1"#))
    #expect(output.contains(#""appleAnchored":true"#))
}

@Test func cliHelpDocumentsTheCompleteLocalLifecycleWithoutRunningCommands() throws {
    let executor = FakeSubprocessExecutor(results: [])

    let output = try CLI.run(arguments: ["--help"], executor: executor)

    #expect(output.contains("identity create"))
    #expect(output.contains("identity delete"))
    #expect(output.contains("identity retire"))
    #expect(output.contains("wrapper install"))
    #expect(output.contains("verify remote"))
    #expect(output.contains("PLUMBING WORKFLOW"))
    #expect(output.contains("user-defined workflows"))
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
        (["identity", "create", "--help"], ["-l", "-k", "-t", "p-256-ne", "bio|none", "--allow-unattended-signing", "--json"]),
        (["identity", "delete", "--help"], ["-h", "--confirm", "sha1", "--json"]),
        (["identity", "retire", "--help"], ["--ctk-sha256", "--confirm", "--remote-authorization-cleared", "--recovery-access-verified", "--json"]),
        (["wrapper", "install", "--help"], ["--ctk-sha256", "--destination", "--json"]),
        (["config", "render", "--help"], ["--identity-file", "--host-pattern", "--json"]),
        (["verify", "local", "--help"], ["--ctk-sha256", "--wrapper", "--json"]),
        (["verify", "remote", "--help"], ["--ctk-sha256", "--wrapper", "--target", "--json"]),
    ]

    for (arguments, options) in cases {
        let output = try CLI.run(arguments: arguments, executor: executor)
        for option in options { #expect(output.contains(option)) }
    }
    for group in ["identity", "wrapper", "config", "verify"] {
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
        try CLI.run(arguments: ["identity", "delete", "-h"], executor: executor)
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

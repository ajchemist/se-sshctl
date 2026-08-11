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

@Test func cliRejectsMutatingOrUnknownCommands() {
    let executor = FakeSubprocessExecutor(results: [])

    #expect(throws: CLIError.self) {
        try CLI.run(arguments: ["identity", "create"], executor: executor)
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

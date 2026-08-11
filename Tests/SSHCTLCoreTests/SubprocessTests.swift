import Foundation
import Testing
@testable import SSHCTLCore

@Test func subprocessRequestsUseFixedAbsoluteExecutables() {
    let request = SubprocessRequest(
        executable: .scAuth,
        arguments: ["list-ctk-identities", "-t", "sha256", "-e", "hex"],
        timeout: 3
    )

    #expect(request.executable.path == "/usr/sbin/sc_auth")
    #expect(request.arguments[0] == "list-ctk-identities")
    #expect(request.timeout == 3)
}

@Test func fakeExecutorReturnsBoundaryEvidence() throws {
    let expected = SubprocessResult(
        stdout: "partial output",
        stderr: "terminated",
        exitStatus: 15,
        terminationReason: .uncaughtSignal,
        timedOut: true
    )
    let executor = FakeSubprocessExecutor(results: [.success(expected)])

    let actual = try executor.run(SubprocessRequest(executable: .ssh, arguments: ["-V"]))

    #expect(actual == expected)
    #expect(executor.requests.map(\.executable) == [.ssh])
}

@Test func subprocessTimeoutIncludesBlockedStandardInputWrite() throws {
    let started = Date()
    let result = try ProcessExecutor().run(SubprocessRequest(
        executable: .ssh,
        arguments: [
            "-F", "none",
            "-o", "BatchMode=yes",
            "-o", "ProxyCommand=/bin/sleep 1",
            "example.invalid",
        ],
        standardInput: Data(repeating: 65, count: 2 * 1024 * 1024),
        timeout: 0.05
    ))

    #expect(result.timedOut)
    #expect(Date().timeIntervalSince(started) < 0.5)
}

final class FakeSubprocessExecutor: SubprocessExecuting {
    private(set) var requests: [SubprocessRequest] = []
    private var results: [Result<SubprocessResult, Error>]

    init(results: [Result<SubprocessResult, Error>]) {
        self.results = results
    }

    func run(_ request: SubprocessRequest) throws -> SubprocessResult {
        requests.append(request)
        return try results.removeFirst().get()
    }
}

import Darwin
import Foundation

public enum SystemExecutable: String, Codable, CaseIterable, Sendable {
    case codesign = "/usr/bin/codesign"
    case scAuth = "/usr/sbin/sc_auth"
    case ssh = "/usr/bin/ssh"
    case sshKeygen = "/usr/bin/ssh-keygen"
    case swVers = "/usr/bin/sw_vers"
    case uname = "/usr/bin/uname"

    public var path: String { rawValue }
}

public struct SubprocessRequest: Equatable, Sendable {
    public let executable: SystemExecutable
    public let arguments: [String]
    public let environment: [String: String]
    public let currentDirectoryURL: URL?
    public let standardInput: Data?
    public let timeout: TimeInterval

    public init(
        executable: SystemExecutable,
        arguments: [String] = [],
        environment: [String: String] = [:],
        currentDirectoryURL: URL? = nil,
        standardInput: Data? = nil,
        timeout: TimeInterval = 10
    ) {
        self.executable = executable
        self.arguments = arguments
        self.environment = environment
        self.currentDirectoryURL = currentDirectoryURL
        self.standardInput = standardInput
        self.timeout = timeout
    }
}

public struct SubprocessResult: Equatable, Sendable {
    public enum TerminationReason: String, Codable, Sendable {
        case exit
        case uncaughtSignal
    }

    public let stdout: String
    public let stderr: String
    public let exitStatus: Int32
    public let terminationReason: TerminationReason
    public let timedOut: Bool

    public init(
        stdout: String,
        stderr: String,
        exitStatus: Int32,
        terminationReason: TerminationReason,
        timedOut: Bool
    ) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitStatus = exitStatus
        self.terminationReason = terminationReason
        self.timedOut = timedOut
    }

    /// The single definition of a successful run: it finished on its own,
    /// exited rather than being signalled, and reported status 0. Callers
    /// distinguish the failure kinds through `timedOut` and `stderr`.
    public var succeeded: Bool {
        !timedOut && terminationReason == .exit && exitStatus == 0
    }
}

public protocol SubprocessExecuting {
    func run(_ request: SubprocessRequest) throws -> SubprocessResult
}

public struct ProcessExecutor: SubprocessExecuting {
    public init() {}

    public func run(_ request: SubprocessRequest) throws -> SubprocessResult {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        let stdin = Pipe()
        let stdoutBuffer = LockedData()
        let stderrBuffer = LockedData()
        let reads = DispatchGroup()
        let writes = DispatchGroup()
        let deadline = Date().addingTimeInterval(request.timeout)

        process.executableURL = URL(fileURLWithPath: request.executable.path)
        process.arguments = request.arguments
        process.environment = ProcessInfo.processInfo.environment.merging(request.environment) { _, new in new }
        process.currentDirectoryURL = request.currentDirectoryURL
        process.standardOutput = stdout
        process.standardError = stderr
        if request.standardInput != nil {
            process.standardInput = stdin
        }

        reads.enter()
        DispatchQueue.global().async {
            stdoutBuffer.set(stdout.fileHandleForReading.readDataToEndOfFile())
            reads.leave()
        }
        reads.enter()
        DispatchQueue.global().async {
            stderrBuffer.set(stderr.fileHandleForReading.readDataToEndOfFile())
            reads.leave()
        }

        do {
            try process.run()
        } catch {
            stdout.fileHandleForWriting.closeFile()
            stderr.fileHandleForWriting.closeFile()
            reads.wait()
            throw error
        }

        if let input = request.standardInput {
            let handle = stdin.fileHandleForWriting
            _ = fcntl(handle.fileDescriptor, F_SETNOSIGPIPE, 1)
            writes.enter()
            DispatchQueue.global().async {
                try? handle.write(contentsOf: input)
                handle.closeFile()
                writes.leave()
            }
        }

        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        let timedOut = process.isRunning
        if timedOut {
            killDescendants(of: process.processIdentifier, signal: SIGKILL)
            process.terminate()
            let terminationDeadline = Date().addingTimeInterval(1)
            while process.isRunning && Date() < terminationDeadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if process.isRunning {
                killDescendants(of: process.processIdentifier, signal: SIGKILL)
                kill(process.processIdentifier, SIGKILL)
            }
        }
        process.waitUntilExit()
        reads.wait()
        writes.wait()

        return SubprocessResult(
            stdout: stdoutBuffer.string,
            stderr: stderrBuffer.string,
            exitStatus: process.terminationStatus,
            terminationReason: process.terminationReason == .exit ? .exit : .uncaughtSignal,
            timedOut: timedOut
        )
    }
}

private func killDescendants(of processID: pid_t, signal: Int32) {
    for child in childProcessIDs(of: processID) {
        killDescendants(of: child, signal: signal)
        if childProcessIDs(of: processID).contains(child) {
            kill(child, signal)
        }
    }
}

private func childProcessIDs(of processID: pid_t) -> [pid_t] {
    let capacity = proc_listchildpids(processID, nil, 0)
    guard capacity > 0 else { return [] }
    var processIDs = [pid_t](repeating: 0, count: Int(capacity))
    let count = processIDs.withUnsafeMutableBytes {
        proc_listchildpids(processID, $0.baseAddress, Int32($0.count))
    }
    guard count > 0 else { return [] }
    return Array(processIDs.prefix(Int(count)))
}

private final class LockedData: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func set(_ newValue: Data) {
        lock.lock()
        data = newValue
        lock.unlock()
    }

    var string: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}

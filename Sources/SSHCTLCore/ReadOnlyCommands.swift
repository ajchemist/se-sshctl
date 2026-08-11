import Foundation

public enum ReadOnlyCommandError: Error, Equatable {
    case commandFailed(SystemExecutable)
}

public struct PlatformReport: Codable, Equatable, Sendable {
    public let version: String
    public let build: String
    public let architecture: String
}

public struct ToolReport: Codable, Equatable, Sendable {
    public let path: String
    public let available: Bool
    public let version: String?
}

public struct ProviderReport: Codable, Equatable, Sendable {
    public let path: String
    public let available: Bool
    public let signatureValid: Bool
    public let appleAnchored: Bool
    public let identifier: String?
}

public struct DoctorReport: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let platform: PlatformReport
    public let scAuth: ToolReport
    public let openSSH: ToolReport
    public let provider: ProviderReport
}

public struct Doctor {
    private let executor: any SubprocessExecuting
    private let pathExists: (String) -> Bool

    public init(
        executor: any SubprocessExecuting,
        pathExists: @escaping (String) -> Bool = FileManager.default.fileExists(atPath:)
    ) {
        self.executor = executor
        self.pathExists = pathExists
    }

    public func report() throws -> DoctorReport {
        let providerPath = "/usr/lib/ssh-keychain.dylib"
        let version = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-productVersion"]))
        let build = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-buildVersion"]))
        let architecture = try successfulOutput(SubprocessRequest(executable: .uname, arguments: ["-m"]))
        let sshVersion = try successfulOutput(SubprocessRequest(executable: .ssh, arguments: ["-V"]))
        let providerAvailable = pathExists(providerPath)
        let signatureValid = providerAvailable
            ? try succeeds(SubprocessRequest(executable: .codesign, arguments: ["--verify", "--strict", providerPath]))
            : false
        let requirement = providerAvailable
            ? try successfulOutput(SubprocessRequest(executable: .codesign, arguments: ["-dr", "-", providerPath]))
            : ""
        return DoctorReport(
            schemaVersion: 1,
            platform: PlatformReport(version: version, build: build, architecture: architecture),
            scAuth: ToolReport(path: SystemExecutable.scAuth.path, available: pathExists(SystemExecutable.scAuth.path), version: nil),
            openSSH: ToolReport(
                path: SystemExecutable.ssh.path,
                available: pathExists(SystemExecutable.ssh.path),
                version: sshVersion
            ),
            provider: ProviderReport(
                path: providerPath,
                available: providerAvailable,
                signatureValid: signatureValid,
                appleAnchored: requirement.contains("anchor apple"),
                identifier: requirement.contains(#"identifier "com.apple.ssh-keychain""#) ? "com.apple.ssh-keychain" : nil
            )
        )
    }

    private func successfulOutput(_ request: SubprocessRequest) throws -> String {
        let result = try executor.run(request)
        guard !result.timedOut, result.terminationReason == .exit, result.exitStatus == 0 else {
            throw ReadOnlyCommandError.commandFailed(request.executable)
        }
        let output = result.stdout.isEmpty ? result.stderr : result.stdout
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func succeeds(_ request: SubprocessRequest) throws -> Bool {
        let result = try executor.run(request)
        return !result.timedOut && result.terminationReason == .exit && result.exitStatus == 0
    }
}

public struct IdentityListReport: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let identities: [CTKIdentity]

    public init(schemaVersion: Int = 1, identities: [CTKIdentity]) {
        self.schemaVersion = schemaVersion
        self.identities = identities
    }
}

public struct IdentityLister {
    private let executor: any SubprocessExecuting

    public init(executor: any SubprocessExecuting) {
        self.executor = executor
    }

    public func list() throws -> IdentityListReport {
        let request = SubprocessRequest(
            executable: .scAuth,
            arguments: ["list-ctk-identities", "-t", "sha256", "-e", "hex"]
        )
        let result = try executor.run(request)
        guard !result.timedOut, result.terminationReason == .exit, result.exitStatus == 0 else {
            throw ReadOnlyCommandError.commandFailed(.scAuth)
        }
        return IdentityListReport(identities: try CTKIdentityParser().parse(result.stdout))
    }
}

public enum JSONOutput {
    public static func encode<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }
}

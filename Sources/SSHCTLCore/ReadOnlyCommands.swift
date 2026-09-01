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

public struct ProviderInspector {
    private let executor: any SubprocessExecuting
    private let pathExists: (String) -> Bool

    public init(
        executor: any SubprocessExecuting,
        pathExists: @escaping (String) -> Bool = FileManager.default.fileExists(atPath:)
    ) {
        self.executor = executor
        self.pathExists = pathExists
    }

    public func report() throws -> ProviderReport {
        let path = "/usr/lib/ssh-keychain.dylib"
        let available = pathExists(path)
        let verification = available
            ? try executor.run(SubprocessRequest(executable: .codesign, arguments: ["--verify", "--strict", path]))
            : nil
        let signatureValid = verification?.succeeded ?? false
        let requirementResult = available
            ? try executor.run(SubprocessRequest(executable: .codesign, arguments: ["-dr", "-", path]))
            : nil
        let requirement = requirementResult.flatMap {
            guard $0.succeeded else { return nil }
            return ($0.stdout.isEmpty ? $0.stderr : $0.stdout).trimmingCharacters(in: .whitespacesAndNewlines)
        } ?? ""
        return ProviderReport(
            path: path,
            available: available,
            signatureValid: signatureValid,
            appleAnchored: requirement.contains("anchor apple"),
            identifier: requirement.contains(#"identifier "com.apple.ssh-keychain""#)
                ? "com.apple.ssh-keychain"
                : nil
        )
    }
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
        let version = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-productVersion"]))
        let build = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-buildVersion"]))
        let architecture = try successfulOutput(SubprocessRequest(executable: .uname, arguments: ["-m"]))
        let sshVersion = try successfulOutput(SubprocessRequest(executable: .ssh, arguments: ["-V"]))
        return DoctorReport(
            schemaVersion: 1,
            platform: PlatformReport(version: version, build: build, architecture: architecture),
            scAuth: ToolReport(path: SystemExecutable.scAuth.path, available: pathExists(SystemExecutable.scAuth.path), version: nil),
            openSSH: ToolReport(
                path: SystemExecutable.ssh.path,
                available: pathExists(SystemExecutable.ssh.path),
                version: sshVersion
            ),
            provider: try ProviderInspector(executor: executor, pathExists: pathExists).report()
        )
    }

    private func successfulOutput(_ request: SubprocessRequest) throws -> String {
        let result = try executor.run(request)
        guard result.succeeded else {
            throw ReadOnlyCommandError.commandFailed(request.executable)
        }
        let output = result.stdout.isEmpty ? result.stderr : result.stdout
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

public struct IdentityListReport: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let hashType: CTKIdentityHashType
    public let hashEncoding: CTKIdentityHashEncoding
    public let identities: [CTKIdentity]

    public init(
        schemaVersion: Int = 2,
        hashType: CTKIdentityHashType = .sha256,
        hashEncoding: CTKIdentityHashEncoding = .hex,
        identities: [CTKIdentity]
    ) {
        self.schemaVersion = schemaVersion
        self.hashType = hashType
        self.hashEncoding = hashEncoding
        self.identities = identities
    }
}

public struct IdentityLister {
    private let executor: any SubprocessExecuting
    private let hashType: CTKIdentityHashType
    private let hashEncoding: CTKIdentityHashEncoding

    public init(
        executor: any SubprocessExecuting,
        hashType: CTKIdentityHashType = .sha256,
        hashEncoding: CTKIdentityHashEncoding = .hex
    ) {
        self.executor = executor
        self.hashType = hashType
        self.hashEncoding = hashEncoding
    }

    public func list() throws -> IdentityListReport {
        let request = SubprocessRequest(
            executable: .scAuth,
            arguments: ["list-ctk-identities", "-t", hashType.rawValue, "-e", hashEncoding.rawValue]
        )
        let result = try executor.run(request)
        guard result.succeeded else {
            throw ReadOnlyCommandError.commandFailed(.scAuth)
        }
        return IdentityListReport(
            hashType: hashType,
            hashEncoding: hashEncoding,
            identities: try CTKIdentityParser(hashType: hashType, hashEncoding: hashEncoding).parse(result.stdout)
        )
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

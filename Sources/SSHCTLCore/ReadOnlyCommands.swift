import Foundation

public enum ReadOnlyCommandError: Error, Equatable {
    case commandFailed(SystemExecutable)
}

/// The oldest macOS this project has physical evidence for.
///
/// Below it `doctor` warns but nothing is blocked. Public reports conflict
/// about whether Sequoia works at all (see docs/SECURE_ENCLAVE_SSH_RESEARCH.md
/// and Beads se-sshctl-8c1), so refusing to run would deny setups that may be
/// perfectly fine, while saying nothing leaves an operator to debug a failure
/// whose cause is simply an untested OS.
public let minimumVerifiedMacOSMajorVersion = 26

public struct PlatformReport: Codable, Equatable, Sendable {
    public let version: String
    public let build: String
    public let architecture: String
    /// Whether `version` is at or above the verified minimum. `nil` when the
    /// version string could not be read as a number, which is itself worth
    /// surfacing rather than silently treating as supported.
    public let verifiedRelease: Bool?
    public let minimumVerifiedRelease: String

    public init(version: String, build: String, architecture: String) {
        self.version = version
        self.build = build
        self.architecture = architecture
        self.verifiedRelease = version.split(separator: ".").first
            .flatMap { Int($0) }
            .map { $0 >= minimumVerifiedMacOSMajorVersion }
        self.minimumVerifiedRelease = "\(minimumVerifiedMacOSMajorVersion)"
    }
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
    /// Which build produced this report. A report that cannot say what made it
    /// is hard to act on once the schema has moved.
    public let seSSHCTL: String
    public let platform: PlatformReport
    public let scAuth: ToolReport
    public let openSSH: ToolReport
    public let provider: ProviderReport
    /// The account logged in at the console, or nil at the login window.
    ///
    /// Every other check here inspects a binary, and all of them pass on a
    /// machine where signing cannot work at all: measured on macOS 26.6.2, a
    /// logged-out Mac still enumerates its CTK identities but fails to sign
    /// with "device not found". Without this field `doctor` reports an
    /// all-clear in exactly the situation an operator most needs the warning.
    public let consoleSession: String?
}

/// Reads the console session from `/dev/console` ownership, which macOS leaves
/// with root at the login window and assigns to the user on login.
public func currentConsoleUser(fileManager: FileManager = .default) -> String? {
    let attributes = try? fileManager.attributesOfItem(atPath: "/dev/console")
    guard let owner = attributes?[.ownerAccountName] as? String, owner != "root" else { return nil }
    return owner
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
    private let consoleUser: () -> String?

    public init(
        executor: any SubprocessExecuting,
        pathExists: @escaping (String) -> Bool = FileManager.default.fileExists(atPath:),
        consoleUser: @escaping () -> String? = { currentConsoleUser() }
    ) {
        self.executor = executor
        self.pathExists = pathExists
        self.consoleUser = consoleUser
    }

    public func report() throws -> DoctorReport {
        let version = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-productVersion"]))
        let build = try successfulOutput(SubprocessRequest(executable: .swVers, arguments: ["-buildVersion"]))
        let architecture = try successfulOutput(SubprocessRequest(executable: .uname, arguments: ["-m"]))
        let sshVersion = try successfulOutput(SubprocessRequest(executable: .ssh, arguments: ["-V"]))
        return DoctorReport(
            schemaVersion: 2,
            seSSHCTL: seSSHCTLVersion,
            platform: PlatformReport(version: version, build: build, architecture: architecture),
            scAuth: ToolReport(path: SystemExecutable.scAuth.path, available: pathExists(SystemExecutable.scAuth.path), version: nil),
            openSSH: ToolReport(
                path: SystemExecutable.ssh.path,
                available: pathExists(SystemExecutable.ssh.path),
                version: sshVersion
            ),
            provider: try ProviderInspector(executor: executor, pathExists: pathExists).report(),
            consoleSession: consoleUser()
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

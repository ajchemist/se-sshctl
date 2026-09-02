import Foundation

public struct ConfigRenderReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 1
    public let config: String
}

public struct SSHConfigRenderer {
    public init() {}

    public func render(identityFile: String, hostPattern: String) throws -> ConfigRenderReport {
        guard !hostPattern.isEmpty,
              !hostPattern.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw OperationalCommandError.invalidHostPattern
        }
        return try block("Host \(hostPattern)", identityFile: identityFile)
    }

    /// A `Match tagged TAG` block, selected with `ssh -P TAG user@host` on any
    /// target. It ends with `Match all` so the file can be `Include`d at the
    /// top of `~/.ssh/config`: without it, the lines after the Include would
    /// still be inside the Match block.
    public func render(identityFile: String, tag: String) throws -> ConfigRenderReport {
        guard !tag.isEmpty,
              !tag.unicodeScalars.contains(where: CharacterSet.whitespacesAndNewlines.union(.controlCharacters).contains) else {
            throw OperationalCommandError.invalidTag
        }
        let report = try block("Match tagged \(tag)", identityFile: identityFile)
        return ConfigRenderReport(config: report.config + "\nMatch all")
    }

    private func block(_ header: String, identityFile: String) throws -> ConfigRenderReport {
        try validatePath(identityFile)
        let quotedPath = identityFile
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return ConfigRenderReport(config: """
        \(header)
            IdentityFile "\(quotedPath)"
            SecurityKeyProvider \(providerPath)
            IdentitiesOnly yes
            ForwardAgent no
        """)
    }
}

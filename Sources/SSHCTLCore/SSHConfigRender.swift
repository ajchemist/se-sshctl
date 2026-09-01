import Foundation

public struct ConfigRenderReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 1
    public let config: String
}

public struct SSHConfigRenderer {
    public init() {}

    public func render(identityFile: String, hostPattern: String) throws -> ConfigRenderReport {
        try validatePath(identityFile)
        guard !hostPattern.isEmpty,
              !hostPattern.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw OperationalCommandError.invalidHostPattern
        }
        let quotedPath = identityFile
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return ConfigRenderReport(config: """
        Host \(hostPattern)
            IdentityFile "\(quotedPath)"
            SecurityKeyProvider \(providerPath)
            IdentitiesOnly yes
            ForwardAgent no
        """)
    }
}

import Foundation

/// The native `sc_auth -k` key types. Encodes as its raw sc_auth value.
public enum CTKKeyType: String, Codable, Sendable, CaseIterable {
    case p256 = "p-256"
    case p384 = "p-384"
    case p521 = "p-521"
    case p256NonExportable = "p-256-ne"
    case p384NonExportable = "p-384-ne"

    /// Only the non-exportable P-256 identity is usable through Apple's
    /// OpenSSH security-key provider.
    public var isOpenSSHCompatible: Bool { self == .p256NonExportable }
}

/// The native `sc_auth -t` per-use authorization value. Encodes as its raw
/// sc_auth value.
///
/// `none` removes the user-presence gate rather than replacing it with a
/// password or PIN: any process running as the user can request signatures.
public enum CTKProtection: String, Codable, Sendable, CaseIterable {
    case bio
    case none

    /// `sc_auth create-ctk-identity` blocks on a Touch ID prompt under `bio`,
    /// so it needs the operator's reaction time, not just Apple's.
    public var creationTimeout: TimeInterval { self == .bio ? 120 : 30 }

    /// Apple's provider prompts for a PIN on the `none` path only; `bio`
    /// authorizes through Touch ID and takes an empty reply.
    public var providerPIN: Data { self == .bio ? Data() : Data("0".utf8) }
}

public struct CTKIdentity: Codable, Equatable, Sendable {
    public let keyType: CTKKeyType
    public let ctkPublicKeyHash: String
    public let protection: CTKProtection
    public let label: String
    public let commonName: String
    public let emailAddress: String
    public let validTo: String
    public let certificateValid: Bool
}

public enum CTKIdentityParseError: Error, Equatable {
    case unexpectedHeader
    case malformedRow(Int)
}

public enum CTKIdentityHashType: String, Codable, Sendable {
    case sha1
    case sha256
    case ssh
}

public enum CTKIdentityHashEncoding: String, Codable, Sendable {
    case hex
    case b64
}

public struct CTKIdentityParser {
    private let headers = [
        "Key Type", "Public Key Hash", "Prot", "Label",
        "Common Name", "Email Address", "Valid To", "Valid",
    ]

    private let hashType: CTKIdentityHashType
    private let hashEncoding: CTKIdentityHashEncoding

    public init(
        hashType: CTKIdentityHashType = .sha256,
        hashEncoding: CTKIdentityHashEncoding = .hex
    ) {
        self.hashType = hashType
        self.hashEncoding = hashEncoding
    }

    public func parse(_ output: String) throws -> [CTKIdentity] {
        let lines = output.split(whereSeparator: \Character.isNewline).map(String.init)
        guard let header = lines.first else { throw CTKIdentityParseError.unexpectedHeader }
        let starts = try columnStarts(in: header)

        return try lines.dropFirst().enumerated().map { offset, line in
            let values = try fields(in: line, starts: starts, lineNumber: offset + 2)
            guard
                let keyType = CTKKeyType(rawValue: values[0]),
                validHash(values[1]),
                let protection = CTKProtection(rawValue: values[2]),
                !values[3].isEmpty,
                !values[6].isEmpty,
                ["YES", "NO"].contains(values[7])
            else { throw CTKIdentityParseError.malformedRow(offset + 2) }

            return CTKIdentity(
                keyType: keyType,
                ctkPublicKeyHash: values[1],
                protection: protection,
                label: values[3],
                commonName: values[4],
                emailAddress: values[5],
                validTo: values[6],
                certificateValid: values[7] == "YES"
            )
        }
    }

    private func validHash(_ value: String) -> Bool {
        let pattern = switch (hashType, hashEncoding) {
        case (.sha1, .hex): #"^[0-9A-Fa-f]{40}$"#
        case (.sha1, .b64): #"^[A-Za-z0-9+/]{27}=$"#
        case (.sha256, .hex), (.ssh, .hex): #"^[0-9A-Fa-f]{64}$"#
        case (.sha256, .b64): #"^[A-Za-z0-9+/]{43}=$"#
        case (.ssh, .b64): #"^SHA256:[A-Za-z0-9+/]{43}$"#
        }
        return value.range(of: pattern, options: .regularExpression) != nil
    }

    private func columnStarts(in header: String) throws -> [Int] {
        var starts: [Int] = []
        var searchStart = header.startIndex
        for name in headers {
            guard let range = header.range(of: name, range: searchStart..<header.endIndex) else {
                throw CTKIdentityParseError.unexpectedHeader
            }
            starts.append(header.distance(from: header.startIndex, to: range.lowerBound))
            searchStart = range.upperBound
        }
        guard starts.first == 0, header[searchStart...].allSatisfy(\.isWhitespace) else {
            throw CTKIdentityParseError.unexpectedHeader
        }
        return starts
    }

    private func fields(in line: String, starts: [Int], lineNumber: Int) throws -> [String] {
        guard line.count >= starts.last! else { throw CTKIdentityParseError.malformedRow(lineNumber) }
        return starts.indices.map { index in
            let start = line.index(line.startIndex, offsetBy: starts[index])
            let end = index + 1 < starts.count
                ? line.index(line.startIndex, offsetBy: min(starts[index + 1], line.count))
                : line.endIndex
            return line[start..<end].trimmingCharacters(in: .whitespaces)
        }
    }
}

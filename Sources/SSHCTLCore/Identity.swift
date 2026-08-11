import Foundation

public struct CTKIdentity: Codable, Equatable, Sendable {
    public let keyType: String
    public let ctkPublicKeyHash: String
    public let protection: String
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

public struct CTKIdentityParser {
    private let headers = [
        "Key Type", "Public Key Hash", "Prot", "Label",
        "Common Name", "Email Address", "Valid To", "Valid",
    ]

    public init() {}

    public func parse(_ output: String) throws -> [CTKIdentity] {
        let lines = output.split(whereSeparator: \Character.isNewline).map(String.init)
        guard let header = lines.first else { throw CTKIdentityParseError.unexpectedHeader }
        let starts = try columnStarts(in: header)

        return try lines.dropFirst().enumerated().map { offset, line in
            let values = try fields(in: line, starts: starts, lineNumber: offset + 2)
            guard
                ["p-256", "p-384", "p-521", "p-256-ne", "p-384-ne"].contains(values[0]),
                values[1].range(of: #"^[0-9A-Fa-f]{64}$"#, options: .regularExpression) != nil,
                ["bio", "none"].contains(values[2]),
                !values[3].isEmpty,
                !values[6].isEmpty,
                ["YES", "NO"].contains(values[7])
            else { throw CTKIdentityParseError.malformedRow(offset + 2) }

            return CTKIdentity(
                keyType: values[0],
                ctkPublicKeyHash: values[1],
                protection: values[2],
                label: values[3],
                commonName: values[4],
                emailAddress: values[5],
                validTo: values[6],
                certificateValid: values[7] == "YES"
            )
        }
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

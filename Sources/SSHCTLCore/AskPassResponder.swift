import Darwin
import Foundation

public enum AskPassResponder {
    public static let failureMarker = "se-sshctl-askpass-error"
    public static let successMarker = "se-sshctl-askpass-ok"

    public enum Error: Swift.Error, Equatable {
        case unavailable
    }

    public enum ResponseKind: String {
        case pin
        case passphrase

        fileprivate var tag: UInt8 { self == .pin ? 1 : 2 }
    }

    public static func run(prompt: String) throws -> ResponseKind {
        try respond(prompt: prompt, inputDescriptor: STDIN_FILENO, outputDescriptor: STDOUT_FILENO)
    }

    static func pinReply(_ response: Data) -> Data { tagged(.pin, response) }
    static func passphraseReply(_ response: Data) -> Data { tagged(.passphrase, response) }

    static func respond(
        prompt: String,
        inputDescriptor: Int32,
        outputDescriptor: Int32
    ) throws -> ResponseKind {
        let expected = try expectedReply(for: prompt)
        while true {
            let line = try readLine(from: inputDescriptor)
            guard let tag = line.first else { throw Error.unavailable }
            if tag == expected.tag {
                var response = line.dropFirst()
                response.append(10)
                try writeAll(Data(response), to: outputDescriptor)
                return expected
            }
            guard expected == .passphrase, tag == ResponseKind.pin.tag else { throw Error.unavailable }
        }
    }

    private static func expectedReply(for prompt: String) throws -> ResponseKind {
        if prompt.hasPrefix("Enter PIN for authenticator:") { return .pin }
        if prompt.hasPrefix("Enter passphrase") || prompt.hasPrefix("Enter same passphrase again:") {
            return .passphrase
        }
        throw Error.unavailable
    }

    private static func tagged(_ reply: ResponseKind, _ response: Data) -> Data {
        var result = Data([reply.tag])
        result.append(response)
        result.append(10)
        return result
    }

    private static func readLine(from descriptor: Int32) throws -> Data {
        var line = Data()
        var byte: UInt8 = 0
        while line.count < 1025 {
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0 {
                if errno == EINTR { continue }
                throw Error.unavailable
            }
            guard count == 1 else { throw Error.unavailable }
            if byte == 10 { return line }
            line.append(byte)
        }
        throw Error.unavailable
    }

    private static func writeAll(_ data: Data, to descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    bytes.count - offset
                )
                if count < 0 {
                    if errno == EINTR { continue }
                    throw Error.unavailable
                }
                guard count > 0 else { throw Error.unavailable }
                offset += count
            }
        }
    }
}

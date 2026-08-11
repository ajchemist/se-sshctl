import Darwin
import Foundation

public enum AskPassResponder {
    public enum Error: Swift.Error, Equatable {
        case unavailable
    }

    public static func run() throws {
        try respond(inputDescriptor: STDIN_FILENO, outputDescriptor: STDOUT_FILENO)
    }

    static func respond(inputDescriptor: Int32, outputDescriptor: Int32) throws {
        var response = Data()
        var byte: UInt8 = 0
        while response.count < 1024 {
            let count = Darwin.read(inputDescriptor, &byte, 1)
            if count < 0 {
                if errno == EINTR { continue }
                throw Error.unavailable
            }
            guard count == 1 else { throw Error.unavailable }
            if byte == 10 {
                response.append(byte)
                try writeAll(response, to: outputDescriptor)
                return
            }
            response.append(byte)
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

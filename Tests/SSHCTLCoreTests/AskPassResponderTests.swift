import Darwin
import Foundation
import Testing
@testable import SSHCTLCore

@Test func askPassResponderConsumesExactlyOneLine() throws {
    var input = [Int32](repeating: -1, count: 2)
    var output = [Int32](repeating: -1, count: 2)
    #expect(pipe(&input) == 0)
    #expect(pipe(&output) == 0)
    defer {
        close(input[0])
        close(output[0])
    }
    Data("first response\nsecond response\n".utf8).withUnsafeBytes {
        #expect(Darwin.write(input[1], $0.baseAddress!, $0.count) == $0.count)
    }
    close(input[1])

    try AskPassResponder.respond(inputDescriptor: input[0], outputDescriptor: output[1])
    close(output[1])

    let reply = FileHandle(fileDescriptor: output[0], closeOnDealloc: false).readDataToEndOfFile()
    let remaining = FileHandle(fileDescriptor: input[0], closeOnDealloc: false).readDataToEndOfFile()
    #expect(reply == Data("first response\n".utf8))
    #expect(remaining == Data("second response\n".utf8))
}

@Test func askPassResponderFailsOnEOF() {
    var input = [Int32](repeating: -1, count: 2)
    #expect(pipe(&input) == 0)
    close(input[1])
    defer { close(input[0]) }

    #expect(throws: AskPassResponder.Error.unavailable) {
        try AskPassResponder.respond(inputDescriptor: input[0], outputDescriptor: STDOUT_FILENO)
    }
}

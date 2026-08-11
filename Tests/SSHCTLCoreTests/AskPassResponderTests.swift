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
    var responses = AskPassResponder.pinReply(Data("unused PIN".utf8))
    responses.append(AskPassResponder.passphraseReply(Data("first response".utf8)))
    responses.append(AskPassResponder.passphraseReply(Data("second response".utf8)))
    responses.withUnsafeBytes {
        #expect(Darwin.write(input[1], $0.baseAddress!, $0.count) == $0.count)
    }
    close(input[1])

    let kind = try AskPassResponder.respond(
        prompt: "Enter passphrase for key:",
        inputDescriptor: input[0],
        outputDescriptor: output[1]
    )
    close(output[1])

    let reply = FileHandle(fileDescriptor: output[0], closeOnDealloc: false).readDataToEndOfFile()
    let remaining = FileHandle(fileDescriptor: input[0], closeOnDealloc: false).readDataToEndOfFile()
    #expect(kind == .passphrase)
    #expect(reply == Data("first response\n".utf8))
    #expect(remaining == AskPassResponder.passphraseReply(Data("second response".utf8)))
}

@Test func askPassResponderFailsOnEOF() {
    var input = [Int32](repeating: -1, count: 2)
    #expect(pipe(&input) == 0)
    close(input[1])
    defer { close(input[0]) }

    #expect(throws: AskPassResponder.Error.unavailable) {
        try AskPassResponder.respond(
            prompt: "Enter PIN for authenticator:",
            inputDescriptor: input[0],
            outputDescriptor: STDOUT_FILENO
        )
    }
}

@Test func askPassResponderRecognizesConfirmationPrompt() throws {
    var input = [Int32](repeating: -1, count: 2)
    var output = [Int32](repeating: -1, count: 2)
    #expect(pipe(&input) == 0)
    #expect(pipe(&output) == 0)
    defer {
        close(input[0])
        close(output[0])
    }
    AskPassResponder.passphraseReply(Data("confirmed".utf8)).withUnsafeBytes {
        #expect(Darwin.write(input[1], $0.baseAddress!, $0.count) == $0.count)
    }
    close(input[1])

    let kind = try AskPassResponder.respond(
        prompt: "Enter same passphrase again:",
        inputDescriptor: input[0],
        outputDescriptor: output[1]
    )
    close(output[1])

    let reply = FileHandle(fileDescriptor: output[0], closeOnDealloc: false).readDataToEndOfFile()
    #expect(kind == .passphrase)
    #expect(reply == Data("confirmed\n".utf8))
}

@Test func askPassResponderRejectsUnknownPromptWithoutConsumingInput() {
    var input = [Int32](repeating: -1, count: 2)
    #expect(pipe(&input) == 0)
    defer {
        close(input[0])
        close(input[1])
    }

    #expect(throws: AskPassResponder.Error.unavailable) {
        try AskPassResponder.respond(
            prompt: "Unexpected prompt:",
            inputDescriptor: input[0],
            outputDescriptor: STDOUT_FILENO
        )
    }
}

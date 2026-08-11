import Darwin
import Foundation
import SSHCTLCore

if ProcessInfo.processInfo.environment["SE_SSHCTL_ASKPASS_MODE"] == "1" {
    do {
        try AskPassResponder.run()
        exit(EXIT_SUCCESS)
    } catch {
        exit(EXIT_FAILURE)
    }
}

private enum ConsolePassphraseError: Error, LocalizedError {
    case unavailable

    var errorDescription: String? {
        "unable to read wrapper passphrase from a controlling terminal"
    }
}

private func readWrapperPassphrase() throws -> Data {
    while true {
        let passphrase = try readPassphrase("Enter passphrase (empty for no passphrase): ")
        let confirmation = try readPassphrase("Enter same passphrase again: ")
        if passphrase == confirmation { return passphrase }
        FileHandle.standardError.write(Data("Passphrases do not match. Try again.\n".utf8))
    }
}

private func readPassphrase(_ prompt: String) throws -> Data {
    var buffer = [CChar](repeating: 0, count: 1024)
    defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
    let result = prompt.withCString { promptPointer in
        buffer.withUnsafeMutableBufferPointer {
            readpassphrase(promptPointer, $0.baseAddress, $0.count, RPP_REQUIRE_TTY)
        }
    }
    guard result != nil else { throw ConsolePassphraseError.unavailable }
    let length = buffer.firstIndex(of: 0) ?? buffer.count
    return buffer.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: length) }
}

let arguments = Array(CommandLine.arguments.dropFirst())

do {
    let output = try CLI.run(
        arguments: arguments,
        executor: ProcessExecutor(),
        wrapperPassphraseReader: readWrapperPassphrase
    )
    FileHandle.standardOutput.write(Data((output + "\n").utf8))
} catch {
    let message = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
    let output = arguments.contains("--json")
        ? (try? JSONOutput.encode(CLIErrorReport(message: message))) ?? #"{"schemaVersion":1,"status":"error"}"#
        : "se-sshctl: " + message
    FileHandle.standardError.write(Data((output + "\n").utf8))
    exit(error is CLIError ? 2 : 1)
}

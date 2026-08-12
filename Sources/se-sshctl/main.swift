import Darwin
import Foundation
import SSHCTLCore

if ProcessInfo.processInfo.environment["SE_SSHCTL_ASKPASS_MODE"] == "1",
   ProcessInfo.processInfo.environment["SSH_ASKPASS_REQUIRE"] == "force",
    CommandLine.arguments.count == 2 {
    do {
        let response = try AskPassResponder.run(prompt: CommandLine.arguments[1])
        FileHandle.standardError.write(Data(
            ("\(AskPassResponder.successMarker):\(response.rawValue)\n").utf8
        ))
        exit(EXIT_SUCCESS)
    } catch {
        FileHandle.standardError.write(Data((AskPassResponder.failureMarker + "\n").utf8))
        exit(EXIT_FAILURE)
    }
}

private enum ConsolePassphraseError: Error, LocalizedError {
    case unavailable

    var errorDescription: String? {
        "unable to read identity file passphrase from a controlling terminal"
    }
}

private func readIdentityFilePassphrase() throws -> Data {
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
        identityFilePassphraseReader: readIdentityFilePassphrase
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

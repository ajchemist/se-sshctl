import Foundation
import SSHCTLCore

do {
    let output = try CLI.run(
        arguments: Array(CommandLine.arguments.dropFirst()),
        executor: ProcessExecutor()
    )
    FileHandle.standardOutput.write(Data((output + "\n").utf8))
} catch {
    let message = (error as? LocalizedError)?.errorDescription ?? String(describing: error)
    FileHandle.standardError.write(Data(("se-sshctl: " + message + "\n").utf8))
    exit(2)
}

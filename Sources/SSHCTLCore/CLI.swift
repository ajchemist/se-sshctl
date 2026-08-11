import Foundation

public enum CLIError: Error, LocalizedError {
    case usage

    public var errorDescription: String? {
        "usage: se-sshctl doctor --json | se-sshctl identity list --json"
    }
}

public enum CLI {
    public static func run(
        arguments: [String],
        executor: any SubprocessExecuting,
        pathExists: @escaping (String) -> Bool = FileManager.default.fileExists(atPath:)
    ) throws -> String {
        switch arguments {
        case ["doctor", "--json"]:
            return try JSONOutput.encode(Doctor(executor: executor, pathExists: pathExists).report())
        case ["identity", "list", "--json"]:
            return try JSONOutput.encode(IdentityLister(executor: executor).list())
        default:
            throw CLIError.usage
        }
    }
}

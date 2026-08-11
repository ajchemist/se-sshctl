import Foundation

public enum CLIError: Error, LocalizedError, Equatable {
    case usage(String)

    public var errorDescription: String? {
        switch self {
        case let .usage(message): message
        }
    }
}

public struct CLIErrorReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 1
    public let status = "error"
    public let message: String

    public init(message: String) {
        self.message = message
    }
}

public enum CLI {
    public static func run(
        arguments: [String],
        executor: any SubprocessExecuting,
        pathExists: @escaping (String) -> Bool = FileManager.default.fileExists(atPath:),
        fileManager: FileManager = .default,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        lockDirectory: URL? = nil,
        wrapperPassphraseReader: (() throws -> Data)? = nil
    ) throws -> String {
        if arguments.isEmpty || arguments == ["help"] || arguments == ["--help"] || arguments == ["-h"] {
            return rootHelp
        }
        if arguments == ["identity", "--help"] || arguments == ["identity", "-h"] {
            return identityHelp
        }
        if arguments.last == "--help" {
            return try help(for: Array(arguments.dropLast()))
        }

        switch Array(arguments.prefix(2)) {
        case ["doctor", "--json"] where arguments.count == 2:
            return try JSONOutput.encode(Doctor(executor: executor, pathExists: pathExists).report())
        case ["doctor"] where arguments.count == 1:
            return human(try Doctor(executor: executor, pathExists: pathExists).report())
        case ["identity", "list"]:
            let options = try Options(
                Array(arguments.dropFirst(2)), values: ["-t", "-e"], flags: ["--json"]
            )
            guard let hashType = CTKIdentityHashType(rawValue: options.value("-t") ?? "sha256") else {
                throw CLIError.usage("-t must be sha1, sha256, or ssh")
            }
            let defaultEncoding = hashType == .ssh ? "b64" : "hex"
            guard let hashEncoding = CTKIdentityHashEncoding(
                rawValue: options.value("-e") ?? defaultEncoding
            ) else {
                throw CLIError.usage("-e must be hex or b64")
            }
            let report = try IdentityLister(
                executor: executor, hashType: hashType, hashEncoding: hashEncoding
            ).list()
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["identity", "create"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["-l", "-k", "-t"],
                flags: ["--allow-unattended-signing", "--json"]
            )
            let report = try IdentityCreator(
                executor: executor,
                lockDirectory: lockDirectory ?? defaultLockDirectory
            ).create(
                label: try options.required("-l"),
                keyType: try options.required("-k"),
                protection: try options.required("-t"),
                allowUnattendedSigning: options.has("--allow-unattended-signing")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["identity", "delete"]:
            let options = try Options(
                Array(arguments.dropFirst(2)), values: ["-h", "--confirm"], flags: ["--json"]
            )
            let report = try CTKIdentityDeleter(
                executor: executor,
                lockDirectory: lockDirectory ?? defaultLockDirectory
            ).delete(
                hash: try options.required("-h"),
                confirmation: try options.required("--confirm")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["identity", "retire"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--ctk-sha256", "--confirm"],
                flags: ["--remote-authorization-cleared", "--recovery-access-verified", "--json"]
            )
            let report = try IdentityRetirer(
                executor: executor,
                lockDirectory: lockDirectory ?? defaultLockDirectory
            ).retire(
                ctkSHA256: try options.required("--ctk-sha256"),
                confirmation: try options.required("--confirm"),
                remoteAuthorizationCleared: options.has("--remote-authorization-cleared"),
                recoveryAccessVerified: options.has("--recovery-access-verified")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["wrapper", "install"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--ctk-sha256", "--destination"],
                flags: ["--json"]
            )
            let hash = try options.required("--ctk-sha256")
            let destination = options.value("--destination")
                ?? homeDirectory.appendingPathComponent(
                    ".ssh/identities/id_\(String(hash.prefix(16)).lowercased())"
                ).path
            guard let wrapperPassphraseReader else {
                throw CLIError.usage("wrapper install requires a controlling terminal for passphrase input")
            }
            let report = try WrapperInstaller(executor: executor, fileManager: fileManager).install(
                ctkSHA256: hash,
                destination: URL(fileURLWithPath: expand(destination, homeDirectory: homeDirectory)),
                passphrase: try wrapperPassphraseReader()
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["config", "render"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--identity-file", "--host-pattern"],
                flags: ["--json"]
            )
            let report = try SSHConfigRenderer().render(
                identityFile: expand(try options.required("--identity-file"), homeDirectory: homeDirectory),
                hostPattern: try options.required("--host-pattern")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : report.config
        case ["verify", "local"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--ctk-sha256", "--wrapper"],
                flags: ["--json"]
            )
            let report = try LocalVerifier(executor: executor, fileManager: fileManager).verify(
                ctkSHA256: try options.required("--ctk-sha256"),
                wrapper: URL(fileURLWithPath: expand(try options.required("--wrapper"), homeDirectory: homeDirectory))
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["verify", "remote"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--ctk-sha256", "--wrapper", "--target"],
                flags: ["--json"]
            )
            let report = try RemoteVerifier(executor: executor, fileManager: fileManager).verify(
                ctkSHA256: try options.required("--ctk-sha256"),
                wrapper: expand(try options.required("--wrapper"), homeDirectory: homeDirectory),
                target: try options.required("--target")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        default:
            throw CLIError.usage("unknown command; run 'se-sshctl --help'")
        }
    }

    private static func help(for command: [String]) throws -> String {
        switch command {
        case ["doctor"]: doctorHelp
        case ["identity"]: identityHelp
        case ["identity", "list"]: identityListHelp
        case ["identity", "create"]: identityCreateHelp
        case ["identity", "delete"]: identityDeleteHelp
        case ["identity", "retire"]: identityRetireHelp
        case ["wrapper"]: wrapperHelp
        case ["wrapper", "install"]: wrapperInstallHelp
        case ["config"]: configHelp
        case ["config", "render"]: configRenderHelp
        case ["verify"]: verifyHelp
        case ["verify", "local"]: verifyLocalHelp
        case ["verify", "remote"]: verifyRemoteHelp
        default: throw CLIError.usage("unknown command; run 'se-sshctl --help'")
        }
    }
}

private struct Options {
    private var values: [String: String] = [:]
    private var flags: Set<String> = []

    init(_ arguments: [String], values valueNames: Set<String>, flags flagNames: Set<String>) throws {
        var index = 0
        while index < arguments.count {
            let name = arguments[index]
            if flagNames.contains(name) {
                guard flags.insert(name).inserted else { throw CLIError.usage("duplicate option: \(name)") }
                index += 1
            } else if valueNames.contains(name) {
                guard values[name] == nil else { throw CLIError.usage("duplicate option: \(name)") }
                guard index + 1 < arguments.count else { throw CLIError.usage("missing value for \(name)") }
                values[name] = arguments[index + 1]
                index += 2
            } else {
                throw CLIError.usage("unknown option: \(name)")
            }
        }
    }

    func value(_ name: String) -> String? { values[name] }
    func has(_ name: String) -> Bool { flags.contains(name) }

    func required(_ name: String) throws -> String {
        guard let value = values[name], !value.isEmpty else { throw CLIError.usage("missing required option: \(name)") }
        return value
    }
}

private func expand(_ path: String, homeDirectory: URL) -> String {
    path.hasPrefix("~/") ? homeDirectory.appendingPathComponent(String(path.dropFirst(2))).path : path
}

private func human(_ report: DoctorReport) -> String {
    """
    macOS \(report.platform.version) (\(report.platform.build)) \(report.platform.architecture)
    OpenSSH: \(report.openSSH.version ?? "unknown")
    sc_auth: \(report.scAuth.available ? "available" : "missing")
    provider: \(report.provider.signatureValid && report.provider.appleAnchored ? "verified" : "unverified")
    """
}

private func human(_ report: IdentityListReport) -> String {
    let heading = "CTK public-key hash: \(report.hashType.rawValue)/\(report.hashEncoding.rawValue)"
    guard !report.identities.isEmpty else { return heading + "\nNo CTK identities." }
    return heading + "\n" + report.identities.map {
        "\($0.ctkPublicKeyHash)  \($0.keyType)/\($0.protection)  \($0.label)"
    }.joined(separator: "\n")
}

private func human(_ report: IdentityCreateReport) -> String {
    "Created CTK SHA-256/hex \(report.identity.ctkPublicKeyHash) (\(report.identity.keyType)/\(report.identity.protection)) \(report.identity.label)"
}

private func human(_ report: CTKIdentityDeleteReport) -> String {
    "Deleted SHA-1/hex \(report.ctkPublicKeyHash)"
}

private func human(_ report: IdentityRetireReport) -> String {
    "Retired SHA-256/hex \(report.ctkPublicKeyHash)"
}

private func human(_ report: WrapperInstallReport) -> String {
    "Installed \(report.identityFile)\nCTK SHA-256/hex \(report.ctkPublicKeyHash)\nFingerprint \(report.sshFingerprint)\nPublic key \(report.publicKey)"
}

private func human(_ report: VerificationReport) -> String {
    let target = report.target.map { ": \($0)" } ?? ""
    return "\(report.kind) verification passed\(target)\nCTK SHA-256/hex \(report.ctkSHA256)"
}

private let rootHelp = """
se-sshctl manages Apple CryptoTokenKit/Secure Enclave SSH identities.

LAYERS
  Plumbing commands expose CTK/OpenSSH concepts and native values without deployment-specific policy.
  Porcelain may compose plumbing for user-defined workflows without changing plumbing semantics.

PLUMBING
  se-sshctl doctor [--json]
  se-sshctl identity list [-t sha1|sha256|ssh] [-e hex|b64] [--json]
  se-sshctl identity create -l LABEL -k p-256-ne -t bio|none [--allow-unattended-signing] [--json]
  se-sshctl identity delete -h SHA1 --confirm SHA1 [--json]
  se-sshctl wrapper install --ctk-sha256 SHA256 [--destination PATH] [--json]
  se-sshctl config render --identity-file PATH --host-pattern PATTERN [--json]
  se-sshctl verify local --ctk-sha256 SHA256 --wrapper PATH [--json]
  se-sshctl verify remote --ctk-sha256 SHA256 --wrapper PATH --target HOST [--json]

PORCELAIN
  se-sshctl identity retire --ctk-sha256 SHA256 --confirm SHA256 --remote-authorization-cleared --recovery-access-verified [--json]

PLUMBING WORKFLOW
  1. Check this Mac and Apple's provider:
       se-sshctl doctor
  2. Create an identity and copy its full CTK SHA-256 hash:
       se-sshctl identity create -l example-key -k p-256-ne -t bio
  3. Install its wrapper (private handle 0400, public key 0444):
       se-sshctl wrapper install --ctk-sha256 SHA256 --destination ~/.ssh/identities/example/id_ecdsa_sk_rk
  4. Prove local signing works:
       se-sshctl verify local --ctk-sha256 SHA256 --wrapper ~/.ssh/identities/example/id_ecdsa_sk_rk
  5. Render a config block, then install the .pub key on the server yourself:
       se-sshctl config render --identity-file ~/.ssh/identities/example/id_ecdsa_sk_rk --host-pattern example-*
  6. Prove the selected identity authenticates remotely:
       se-sshctl verify remote --ctk-sha256 SHA256 --wrapper ~/.ssh/identities/example/id_ecdsa_sk_rk --target user@host.example

DELETION
  Remove the public key from every server, verify recovery access, then run
  'se-sshctl identity retire --help'. Raw 'identity delete' expects the native
  sc_auth SHA-1 hash. Secure Enclave deletion is permanent.

Run any command with --help for details. Mutating commands never select by label.
"""

private let doctorHelp = """
USAGE
  se-sshctl doctor [--json]

Checks fixed Apple system tools and the ssh-keychain provider signature without modifying state.

OPTIONS
  --json  Emit the versioned machine-readable report instead of text.
"""

private let identityHelp = """
USAGE
  se-sshctl identity list|create|delete|retire ...

SUBCOMMANDS
  list    [plumbing] List CTK identities using sc_auth hash type and encoding values.
  create  [plumbing] Create one identity using sc_auth parameter names and values.
  delete  [plumbing] Delete one identity using the native sc_auth SHA-1 hash.
  retire  [porcelain] Apply remote/recovery policy, then permanently delete one identity.

Operational selectors use --ctk-sha256; raw delete uses sc_auth -h SHA-1. Labels never select.
Run 'se-sshctl identity <subcommand> --help' for every option.
"""

private let identityListHelp = """
USAGE
  se-sshctl identity list [-t sha1|sha256|ssh] [-e hex|b64] [--json]

Lists identity metadata. Output may disclose labels and should be redacted before sharing.

OPTIONS
  -t sha1|sha256|ssh  sc_auth public-key hash type. Default: sha256.
  -e hex|b64          sc_auth hash encoding. Default: hex, or b64 with -t ssh.
  --json              Emit hash type, encoding, and identities as versioned JSON.
"""

private let identityCreateHelp = """
USAGE
  se-sshctl identity create -l LABEL -k p-256-ne -t bio|none [--allow-unattended-signing] [--json]

Low-level wrapper for 'sc_auth create-ctk-identity'. Its parameter names and values are preserved.
Only p-256-ne is accepted because the resulting non-exportable identity is compatible with
Apple's OpenSSH security-key provider. -t none requires --allow-unattended-signing because
any process in the user context may request signatures.
The command verifies exactly one matching identity appeared and never auto-deletes on partial failure.

OPTIONS
  -l LABEL                    sc_auth label. Labels need not be unique.
  -k p-256-ne                 sc_auth non-exportable P-256 key type; required explicitly.
  -t bio|none                 sc_auth private-key protection; required explicitly.
  --allow-unattended-signing  Required acknowledgement when -t none is selected.
  --json                      Emit the versioned machine-readable report instead of text.
"""

private let identityDeleteHelp = """
USAGE
  se-sshctl identity delete -h SHA1 --confirm SHA1 [--json]

Low-level wrapper for 'sc_auth delete-ctk-identity -h hash'. Permanently deletes one CTK
identity and verifies its SHA-1 hash is absent. Use 'identity list -t sha1 -e hex' to obtain
the exact native hash. Prefer 'identity retire' for the operator workflow. There is no delete-all command.

OPTIONS
  -h SHA1         sc_auth 40-character hexadecimal SHA-1 public-key hash.
  --confirm SHA1  Repeat the exact same hash to confirm permanent deletion.
  --json          Emit the versioned machine-readable report instead of text.
"""

private let identityRetireHelp = """
USAGE
  se-sshctl identity retire --ctk-sha256 SHA256 --confirm SHA256 --remote-authorization-cleared --recovery-access-verified [--json]

Porcelain retirement resolves the operational SHA-256 identity to sc_auth's SHA-1 deletion
hash, permanently deletes it, and verifies absence. Remove remote authorization and verify a
replacement or break-glass key before supplying both acknowledgements.

OPTIONS
  --ctk-sha256 SHA256               Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --confirm SHA256                  Repeat the same full hash to confirm permanent deletion.
  --remote-authorization-cleared    Assert its public key was removed from every remote authorization store.
  --recovery-access-verified        Assert replacement or break-glass access was tested successfully.
  --json                            Emit the versioned machine-readable report instead of text.
"""

private let wrapperHelp = """
USAGE
  se-sshctl wrapper install ...

SUBCOMMANDS
  install  Download and install the selected resident-key wrapper and public key.

Run 'se-sshctl wrapper install --help' for every option.
"""

private let wrapperInstallHelp = """
USAGE
  se-sshctl wrapper install --ctk-sha256 SHA256 [--destination PATH] [--json]

Runs 'ssh-keygen -K -w /usr/lib/ssh-keychain.dylib' in isolated directories,
selects by SSH fingerprint, and refuses overwrite. The trusted provider path is fixed, not user-configurable.
The default destination is ~/.ssh/identities/id_<first-16-hash-characters>.
The wrapper is a private key handle, not exported private key material. It is installed mode 0400;
its .pub file is installed mode 0444; newly created parent directories are mode 0700.
Before download, the command reads a wrapper passphrase twice from the controlling terminal
with echo disabled, like ssh-keygen. Submit an empty passphrase twice for no passphrase.

OPTIONS
  --ctk-sha256 SHA256 Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --destination PATH  Install the wrapper at PATH and its public key at PATH.pub.
                      Default: ~/.ssh/identities/id_<first-16-hash-characters>.
  --json              Emit the versioned machine-readable report instead of text.
"""

private let configHelp = """
USAGE
  se-sshctl config render ...

SUBCOMMANDS
  render  Print an SSH config block without modifying user files.

Run 'se-sshctl config render --help' for every option.
"""

private let configRenderHelp = """
USAGE
  se-sshctl config render --identity-file PATH --host-pattern PATTERN [--json]

Renders an SSH config block to stdout. It does not modify ~/.ssh/config.

OPTIONS
  --identity-file PATH   Set IdentityFile to the installed Secure Enclave wrapper PATH.
  --host-pattern PATTERN Set the SSH Host pattern for the rendered block.
  --json                 Emit a versioned object containing the rendered config instead of raw text.
"""

private let verifyHelp = """
USAGE
  se-sshctl verify local|remote ...

SUBCOMMANDS
  local   Prove the selected Secure Enclave identity can sign locally.
  remote  Prove the selected identity alone can authenticate to one SSH target.

Run 'se-sshctl verify <subcommand> --help' for every option.
"""

private let verifyLocalHelp = """
USAGE
  se-sshctl verify local --ctk-sha256 SHA256 --wrapper PATH [--json]

Signs a temporary challenge through Apple's provider and verifies the resulting SSH signature.

OPTIONS
  --ctk-sha256 SHA256  Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --wrapper PATH   Use the installed resident-key wrapper at PATH and verify its fingerprint.
  --json           Emit the versioned machine-readable report instead of text.
"""

private let verifyRemoteHelp = """
USAGE
  se-sshctl verify remote --ctk-sha256 SHA256 --wrapper PATH --target HOST [--json]

Performs a public-key-only BatchMode SSH authentication and runs the fixed remote command 'true'.
It does not install or revoke remote authorized_keys entries.

OPTIONS
  --ctk-sha256 SHA256  Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --wrapper PATH   Use only the installed resident-key wrapper at PATH.
  --target HOST    Connect to HOST, normally user@hostname, using isolated SSH options.
  --json           Emit the versioned machine-readable report instead of text.
"""

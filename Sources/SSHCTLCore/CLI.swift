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
        manifestDirectory: URL? = nil,
        consoleUser: @escaping () -> String? = { currentConsoleUser() },
        identityFilePassphraseReader: (() throws -> Data)? = nil,
        identityFileUnlockReader: (() throws -> Data)? = nil,
        now: @escaping () -> Date = Date.init
    ) throws -> String {
        let manifestStore = VerificationManifestStore(
            directory: manifestDirectory, fileManager: fileManager, now: now
        )
        if arguments.isEmpty || arguments == ["help"] || arguments == ["--help"] || arguments == ["-h"] {
            return rootHelp
        }
        if arguments == ["--version"] || arguments == ["version"] {
            return "se-sshctl \(seSSHCTLVersion)"
        }
        if arguments == ["identity", "--help"] || arguments == ["identity", "-h"] {
            return identityHelp
        }
        if arguments == ["manifest", "--help"] || arguments == ["manifest", "-h"] {
            return manifestHelp
        }
        if arguments.last == "--help" {
            return try help(for: Array(arguments.dropLast()))
        }

        switch Array(arguments.prefix(2)) {
        case ["doctor", "--json"] where arguments.count == 2:
            return try JSONOutput.encode(
                Doctor(executor: executor, pathExists: pathExists, consoleUser: consoleUser).report()
            )
        case ["doctor"] where arguments.count == 1:
            return human(
                try Doctor(executor: executor, pathExists: pathExists, consoleUser: consoleUser).report()
            )
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
                flags: ["--allow-unattended-signing", "--unique", "--json"]
            )
            let report = try IdentityCreator(
                executor: executor,
                lockDirectory: lockDirectory ?? defaultLockDirectory
            ).create(
                label: try options.required("-l"),
                keyType: try options.required("-k"),
                protection: try options.required("-t"),
                allowUnattendedSigning: options.has("--allow-unattended-signing"),
                unique: options.has("--unique")
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["identity", "delete"]:
            let options = try Options(
                Array(arguments.dropFirst(2)), values: ["--ctk-sha256", "--confirm"], flags: ["--json"]
            )
            let deleter = IdentityDeleter(
                executor: executor,
                manifestStore: manifestStore,
                lockDirectory: lockDirectory ?? defaultLockDirectory
            )
            let hash = try options.required("--ctk-sha256")
            // Without --confirm this shows what would be destroyed and stops.
            // The handoff wants the SSH fingerprint displayed and then
            // approved, in that order; approving a hash you pasted from
            // somewhere else is not that.
            guard let confirmation = options.value("--confirm") else {
                let plan = try deleter.plan(ctkSHA256: hash)
                return options.has("--json") ? try JSONOutput.encode(plan) : human(plan)
            }
            let report = try deleter.delete(ctkSHA256: hash, confirmation: confirmation)
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case let prefix where prefix.first == "install":
            let options = try Options(
                Array(arguments.dropFirst()),
                values: ["--ctk-sha256", "--identity-file"],
                flags: ["--json", "--no-passphrase"]
            )
            let hash = try options.required("--ctk-sha256")
            let identityFile = options.value("--identity-file")
                ?? homeDirectory.appendingPathComponent(
                    ".ssh/identities/id_\(String(hash.prefix(16)).lowercased())"
                ).path
            let passphrase: Data
            if options.has("--no-passphrase") {
                // The only non-interactive path. It selects an empty
                // passphrase; it never carries one, so no secret can reach
                // argv here.
                passphrase = Data()
            } else {
                guard let identityFilePassphraseReader else {
                    throw CLIError.usage(
                        "install needs a controlling terminal to read a passphrase; "
                            + "pass --no-passphrase to install without one"
                    )
                }
                passphrase = try identityFilePassphraseReader()
            }
            let report = try IdentityFileInstaller(executor: executor, fileManager: fileManager).install(
                ctkSHA256: hash,
                identityFile: URL(fileURLWithPath: expand(identityFile, homeDirectory: homeDirectory)),
                passphrase: passphrase
            )
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["manifest", "list"]:
            let options = try Options(Array(arguments.dropFirst(2)), values: [], flags: ["--json"])
            let manifest = try manifestStore.load()
            return options.has("--json")
                ? try JSONOutput.encode(manifest)
                : human(manifest, now: now())
        case ["manifest", "prune"]:
            let options = try Options(Array(arguments.dropFirst(2)), values: [], flags: ["--json"])
            let known = Set(
                try IdentityLister(executor: executor).list().identities
                    .map { $0.ctkPublicKeyHash.uppercased() }
            )
            let outcome = try manifestStore.prune(knownIdentityHashes: known) { entry in
                // Delete only the key this record is about. If the path was
                // reused, its fingerprint no longer matches and the file stays.
                let found = try? readFingerprint(
                    executor: executor, publicKeyPath: entry.identityFile + ".pub"
                )
                return found == entry.sshFingerprint
            }
            return options.has("--json")
                ? try JSONOutput.encode(ManifestPruneReport(outcome: outcome))
                : human(pruned: outcome)
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
                values: ["--ctk-sha256", "--identity-file"],
                flags: ["--json"]
            )
            let identityFilePath = expand(try options.required("--identity-file"), homeDirectory: homeDirectory)
            let report = try recording(into: manifestStore, identityFile: identityFilePath) {
                try LocalVerifier(executor: executor, fileManager: fileManager).verify(
                    ctkSHA256: try options.required("--ctk-sha256"),
                    identityFile: URL(fileURLWithPath: identityFilePath),
                    passphrase: try unlockPassphrase(
                        forIdentityFileAt: identityFilePath,
                        fileManager: fileManager,
                        reader: identityFileUnlockReader
                    )
                )
            }
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        case ["verify", "remote"]:
            let options = try Options(
                Array(arguments.dropFirst(2)),
                values: ["--ctk-sha256", "--identity-file", "--target"],
                flags: ["--json"],
                repeatable: ["--ssh-option"]
            )
            let identityFilePath = expand(try options.required("--identity-file"), homeDirectory: homeDirectory)
            let report = try recording(into: manifestStore, identityFile: identityFilePath) {
                try RemoteVerifier(executor: executor, fileManager: fileManager).verify(
                    ctkSHA256: try options.required("--ctk-sha256"),
                    identityFile: identityFilePath,
                    target: try options.required("--target"),
                    sshOptions: options.values("--ssh-option"),
                    passphrase: try unlockPassphrase(
                        forIdentityFileAt: identityFilePath,
                        fileManager: fileManager,
                        reader: identityFileUnlockReader
                    )
                )
            }
            return options.has("--json") ? try JSONOutput.encode(report) : human(report)
        default:
            throw CLIError.usage("unknown command; run 'se-sshctl --help'")
        }
    }

    /// Renders a verification manifest as text. Public so a failed run prints
    /// the same manifest a passing one does, instead of only an error line.
    public static func describe(_ report: VerificationReport) -> String { human(report) }

    private static func help(for command: [String]) throws -> String {
        switch command {
        case ["doctor"]: doctorHelp
        case ["identity"]: identityHelp
        case ["identity", "list"]: identityListHelp
        case ["identity", "create"]: identityCreateHelp
        case ["identity", "delete"]: identityDeleteHelp
        case ["manifest"]: manifestHelp
        case ["manifest", "list"]: manifestListHelp
        case ["manifest", "prune"]: manifestPruneHelp
        case ["install"]: installHelp
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
    private var lists: [String: [String]] = [:]
    private var flags: Set<String> = []

    init(
        _ arguments: [String],
        values valueNames: Set<String>,
        flags flagNames: Set<String>,
        repeatable repeatableNames: Set<String> = []
    ) throws {
        var index = 0
        while index < arguments.count {
            let name = arguments[index]
            if flagNames.contains(name) {
                guard flags.insert(name).inserted else { throw CLIError.usage("duplicate option: \(name)") }
                index += 1
            } else if repeatableNames.contains(name) {
                guard index + 1 < arguments.count else { throw CLIError.usage("missing value for \(name)") }
                lists[name, default: []].append(arguments[index + 1])
                index += 2
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
    func values(_ name: String) -> [String] { lists[name] ?? [] }
    func has(_ name: String) -> Bool { flags.contains(name) }

    func required(_ name: String) throws -> String {
        guard let value = values[name], !value.isEmpty else { throw CLIError.usage("missing required option: \(name)") }
        return value
    }
}

public struct ManifestPruneReport: Encodable, Equatable, Sendable {
    public let schemaVersion = 2
    public let status = "pruned"
    public let removedRecords: [ManifestEntry]
    public let removedFiles: [String]
    public let keptFiles: [String]

    public init(outcome: ManifestPruneOutcome) {
        self.removedRecords = outcome.removedRecords
        self.removedFiles = outcome.removedFiles
        self.keptFiles = outcome.keptFiles
    }
}

/// Runs a verification and records it either way.
///
/// A failed run is recorded too: that is the whole point of keeping failed
/// distinct from not-run. A recording failure on the success path is reported
/// rather than swallowed, because a verification whose result was not kept did
/// not finish the job it was asked to do.
private func recording(
    into store: VerificationManifestStore,
    identityFile: String,
    _ verify: () throws -> VerificationReport
) throws -> VerificationReport {
    do {
        let report = try verify()
        try store.record(report, identityFile: identityFile)
        return report
    } catch let failure as VerificationFailed {
        // Never let a bookkeeping problem replace the verification failure the
        // operator actually needs to see.
        try? store.record(failure.report, identityFile: identityFile)
        throw failure
    }
}

/// Reads a passphrase only when the identity file actually has one.
///
/// An unencrypted identity file must stay fully non-interactive so that
/// verification runs from automation and from a session with no terminal. A
/// missing file returns nil and lets the verifier report it, so the operator
/// is not asked to unlock something that is not there.
private func unlockPassphrase(
    forIdentityFileAt path: String,
    fileManager: FileManager,
    reader: (() throws -> Data)?
) throws -> Data? {
    guard fileManager.fileExists(atPath: path), try identityFileIsEncrypted(at: path) else {
        return nil
    }
    guard let reader else {
        throw CLIError.usage(
            "this identity file is passphrase-protected, and unlocking it needs a controlling "
                + "terminal; reinstall with --no-passphrase to verify from automation"
        )
    }
    return try reader()
}

private func expand(_ path: String, homeDirectory: URL) -> String {
    path.hasPrefix("~/") ? homeDirectory.appendingPathComponent(String(path.dropFirst(2))).path : path
}

private func human(_ report: DoctorReport) -> String {
    // docs/THREAT_MODEL.md requires path, signature validity, identifier, and
    // Apple anchor evidence to stay separately readable, so a provider that is
    // signed but not Apple-anchored cannot be confused with a trusted one.
    var lines = """
    se-sshctl \(report.seSSHCTL)
    macOS \(report.platform.version) (\(report.platform.build)) \(report.platform.architecture)
    OpenSSH: \(report.openSSH.version ?? "unknown") (\(report.openSSH.path))
    sc_auth: \(report.scAuth.available ? "available" : "missing") (\(report.scAuth.path))
    provider: \(report.provider.path)
      present:    \(report.provider.available ? "yes" : "no")
      signature:  \(report.provider.signatureValid ? "valid" : "invalid")
      anchor:     \(report.provider.appleAnchored ? "apple" : "not apple")
      identifier: \(report.provider.identifier ?? "unknown")
    console session: \(report.consoleSession ?? "none")
    """
    if report.consoleSession == nil {
        lines += """
        \n
        warning: nobody is logged in at the console. Every check above inspects a \
        binary, and they all pass here, but provider-backed signing was measured \
        on macOS 26.6.2 to fail in this state with "device not found" — CTK \
        identities still list, they just cannot sign. Log in at the console; the \
        screen may then be locked.
        """
    }
    if report.platform.verifiedRelease != true {
        lines += """
        \n
        warning: se-sshctl has physical evidence only for macOS \
        \(report.platform.minimumVerifiedRelease) and later. On \
        \(report.platform.version), identity creation, identity-file download, or \
        provider-backed signing may fail in ways this tool cannot explain. \
        Nothing is blocked; reports about older releases conflict.
        """
    }
    return lines
}

private func human(_ manifest: VerificationManifest, now: Date) -> String {
    guard !manifest.identities.isEmpty else {
        return "No recorded verifications."
    }
    return manifest.identities.map { entry in
        let target = entry.target.map { " → \($0)" } ?? ""
        return """
        \(entry.ctkSHA256)
          identity file:         \(entry.identityFile)
          SSH fingerprint:       \(entry.sshFingerprint)
          provider load:         \(describe(entry.providerLoad, now: now))
          local signing:         \(describe(entry.localSigning, now: now))
          remote authentication: \(describe(entry.remoteAuthentication, now: now))\(target)
        """
    }.joined(separator: "\n\n")
}

private func human(pruned outcome: ManifestPruneOutcome) -> String {
    guard !outcome.isEmpty else { return "Nothing to prune." }
    var lines: [String] = []
    if !outcome.removedRecords.isEmpty {
        lines.append("Removed \(outcome.removedRecords.count) record(s):")
        lines += outcome.removedRecords.map { "  \($0.ctkSHA256)  \($0.identityFile)" }
    }
    if !outcome.removedFiles.isEmpty {
        lines.append("Deleted \(outcome.removedFiles.count) file(s) left by a deleted CTK identity:")
        lines += outcome.removedFiles.map { "  \($0)" }
    }
    if !outcome.keptFiles.isEmpty {
        lines.append("Left in place — the path no longer holds the recorded key:")
        lines += outcome.keptFiles.map { "  \($0)" }
    }
    return lines.joined(separator: "\n")
}

/// An outcome is never shown without its age. A `passed` from months ago is a
/// real result, but only the operator can decide whether it is still current,
/// and it cannot decide that without knowing when it was measured.
private func describe(_ check: ManifestCheck, now: Date) -> String {
    guard let at = check.at else { return check.outcome.rawValue }
    let seconds = Int(now.timeIntervalSince(at))
    let age = switch seconds {
    case ..<0: "in the future"
    case ..<60: "just now"
    case ..<3600: "\(seconds / 60)m ago"
    case ..<86400: "\(seconds / 3600)h ago"
    default: "\(seconds / 86400)d ago"
    }
    return "\(check.outcome.rawValue) (\(age))"
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

private func human(_ plan: IdentityDeletionPlan) -> String {
    var lines = [
        "Would permanently delete:",
        "  CTK SHA-256/hex  \(plan.ctkSHA256)",
        "  sc_auth SHA-1    \(plan.ctkSHA1)",
        "  SSH fingerprint  \(plan.sshFingerprint)",
        "  label            \(plan.label)",
        "  parameters       -k \(plan.keyType) -t \(plan.protection)",
    ]
    if plan.identityFiles.isEmpty {
        lines.append("  identity files   none recorded")
    } else {
        lines.append("  identity files   " + plan.identityFiles.joined(separator: "\n                   "))
    }
    lines += [
        "",
        "Check the SSH fingerprint against every authorized_keys that trusts it, remove",
        "it there, and confirm replacement access first. Secure Enclave deletion is",
        "permanent; this tool cannot prove either condition for you.",
        "",
        "Re-run with --confirm \(plan.ctkSHA256) to delete.",
    ]
    return lines.joined(separator: "\n")
}

private func human(_ report: IdentityDeleteReport) -> String {
    var lines = [
        "Deleted CTK SHA-256/hex \(report.ctkSHA256)",
        "  sc_auth SHA-1    \(report.ctkSHA1)",
        "  SSH fingerprint  \(report.sshFingerprint)",
    ]
    if report.removedRecords > 0 {
        lines.append("  removed \(report.removedRecords) verification record(s)")
    }
    for file in report.removedFiles { lines.append("  deleted \(file)") }
    for file in report.keptFiles {
        lines.append("  left in place (path no longer holds this key) \(file)")
    }
    return lines.joined(separator: "\n")
}

private func human(_ report: IdentityFileInstallReport) -> String {
    "Installed \(report.identityFile)\nCTK SHA-256/hex \(report.ctkPublicKeyHash)\nFingerprint \(report.sshFingerprint)\nPublic key \(report.publicKey)"
}

private func human(_ report: VerificationReport) -> String {
    let target = report.target.map { ": \($0)" } ?? ""
    var lines = [
        "\(report.kind) verification \(report.status.rawValue)\(target)",
        "CTK SHA-256/hex \(report.ctkSHA256)",
        "  provider load:         \(report.checks.providerLoad.rawValue)",
        "  local signing:         \(report.checks.localSigning.rawValue)",
        "  remote authentication: \(report.checks.remoteAuthentication.rawValue)",
    ]
    if let detail = report.detail { lines.append("  detail: \(detail)") }
    // The client log is diagnostic noise on a pass; on a failure it is the
    // reason. JSON always carries it, text prints it only when it is needed.
    if report.status != .passed, let clientLog = report.clientLog {
        lines.append("  client log:")
        lines.append(contentsOf: clientLog.split(whereSeparator: \Character.isNewline).map { "    \($0)" })
    }
    return lines.joined(separator: "\n")
}

private let rootHelp = """
se-sshctl manages Apple CryptoTokenKit/Secure Enclave SSH identities.

COMMANDS
  se-sshctl --version
  se-sshctl doctor [--json]
  se-sshctl identity list [-t sha1|sha256|ssh] [-e hex|b64] [--json]
  se-sshctl identity create -l LABEL -k p-256-ne -t bio|none [--allow-unattended-signing] [--unique] [--json]
  se-sshctl identity delete --ctk-sha256 SHA256 [--confirm SHA256] [--json]
  se-sshctl install --ctk-sha256 SHA256 [--identity-file PATH] [--no-passphrase] [--json]
  se-sshctl config render --identity-file PATH --host-pattern PATTERN [--json]
  se-sshctl verify local --ctk-sha256 SHA256 --identity-file PATH [--json]
  se-sshctl verify remote --ctk-sha256 SHA256 --identity-file PATH --target HOST [--ssh-option OPT]... [--json]
  se-sshctl manifest list|prune [--json]

WORKFLOW
  1. Check this Mac and Apple's provider:
       se-sshctl doctor
  2. Create an identity and copy its full CTK SHA-256 hash:
       se-sshctl identity create -l example-key -k p-256-ne -t bio
  3. Install its identity file (key handle 0400, public key 0444):
       se-sshctl install --ctk-sha256 SHA256 --identity-file ~/.ssh/identities/example/id_ecdsa_sk_rk
  4. Prove local signing works:
       se-sshctl verify local --ctk-sha256 SHA256 --identity-file ~/.ssh/identities/example/id_ecdsa_sk_rk
  5. Render a config block, then install the .pub key on the server yourself:
       se-sshctl config render --identity-file ~/.ssh/identities/example/id_ecdsa_sk_rk --host-pattern example-*
  6. Prove the selected identity authenticates remotely:
       se-sshctl verify remote --ctk-sha256 SHA256 --identity-file ~/.ssh/identities/example/id_ecdsa_sk_rk --target user@host.example
  7. Every verification above is recorded. Review what has been proven, and when:
       se-sshctl manifest list

DELETION
  'identity delete' without --confirm shows what would be destroyed and stops.
  Deletion is permanent and this tool cannot check that you removed the key from
  your servers or that replacement access works. Do both first.

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
  se-sshctl identity list|create|delete ...

SUBCOMMANDS
  list    List CTK identities using sc_auth hash type and encoding values.
  create  Create one identity using sc_auth parameter names and values.
  delete  Permanently delete one identity and clean up what depended on it.

Mutating selectors use --ctk-sha256. Labels never select.
Run 'se-sshctl identity <subcommand> --help' for every option.
"""

private let identityListHelp = """
USAGE
  se-sshctl identity list [-t sha1|sha256|ssh] [-e hex|b64] [--json]

Lists identity metadata. Output may disclose labels and should be redacted before sharing.

The Valid and Valid To columns describe the identity's X.509 certificate, not its usability.
An expired certificate was measured on macOS 26.6.2 to leave provider-backed signing, SSH
authentication, and identity-file download all working, so do not read Valid=NO as "this key
no longer works" — and never as "this key is safe to delete". See docs/HARDWARE_VERIFICATION.md.

OPTIONS
  -t sha1|sha256|ssh  sc_auth public-key hash type. Default: sha256.
  -e hex|b64          sc_auth hash encoding. Default: hex, or b64 with -t ssh.
  --json              Emit hash type, encoding, and identities as versioned JSON.
"""

private let identityCreateHelp = """
USAGE
  se-sshctl identity create -l LABEL -k p-256-ne -t bio|none [--allow-unattended-signing] [--unique] [--json]
  se-sshctl identity delete --ctk-sha256 SHA256 [--confirm SHA256] [--json]

Invokes 'sc_auth create-ctk-identity'. Its parameter names and values are preserved.
Only p-256-ne is accepted because the resulting non-exportable identity is compatible with
Apple's OpenSSH security-key provider. -t none requires --allow-unattended-signing because
any process in the user context may request signatures.
The command verifies exactly one matching identity appeared and never auto-deletes on partial failure.

OPTIONS
  -l LABEL                    sc_auth label. Labels need not be unique.
  -k p-256-ne                 sc_auth non-exportable P-256 key type; required explicitly.
  -t bio|none                 sc_auth private-key protection; required explicitly.
  --allow-unattended-signing  Required acknowledgement when -t none is selected.
  --unique                    Refuse when an identity with LABEL already exists, naming its
                              CTK SHA-256 hash. sc_auth allows duplicate labels, but two
                              identities with the same label and parameters cannot be told
                              apart by this tool afterwards, so automation should pass this.
  --json                      Emit the versioned machine-readable report instead of text.
"""

private let identityDeleteHelp = """
USAGE
  se-sshctl identity delete --ctk-sha256 SHA256 [--confirm SHA256] [--json]

Permanently deletes one CTK identity and everything this tool knows that depended
on it. Without --confirm it shows what would be destroyed and stops, so you approve
an SSH fingerprint you have seen rather than a hash you pasted.

PLUMBING
  The underlying operation is exactly:

      sc_auth delete-ctk-identity -h SHA1

  where SHA1 is sc_auth's own SHA-1/hex locator. You never pass it: this command
  selects by the stable SHA-256 hash and resolves the SHA-1 internally, so the
  identifier you select with and the identifier that deletes cannot drift apart.

  On top of that plumbing this command:

    refuses when identity metadata is duplicated, instead of guessing which row
      the SHA-1 locator refers to;
    requires --confirm to repeat the exact SHA-256 hash;
    displays the SSH fingerprint — the only identifier a server knows — before
      the destructive step;
    holds the operation lock, so a concurrent create cannot shift which row is
      resolved between the preview and the deletion;
    verifies absence afterwards in both hash formats rather than trusting the
      exit status;
    deletes the recorded identity file and its .pub, which after this are handles
      to a key that no longer exists, and removes the verification record, which
      is a claim about an identity that no longer exists.

  A recorded identity file is deleted only when its .pub still carries this key's
  SSH fingerprint. A path reused for another key is left alone and reported.

  There is no wrapper for 'sc_auth delete-all-ctk-identities' and there will not
  be one.

OPTIONS
  --ctk-sha256 SHA256  Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --confirm SHA256     Repeat the exact same hash to delete. Omit to preview.
  --json               Emit the versioned machine-readable plan or report instead of text.
"""

private let installHelp = """
USAGE
  se-sshctl install --ctk-sha256 SHA256 [--identity-file PATH] [--no-passphrase] [--json]

Runs 'ssh-keygen -K -w /usr/lib/ssh-keychain.dylib' in isolated directories,
selects by SSH fingerprint, and refuses overwrite. The trusted provider path is fixed, not user-configurable.
The default identity-file path is ~/.ssh/identities/id_<first-16-hash-characters>.
The identity file contains a key handle, not exported Secure Enclave private-key material. It is installed mode 0400;
its .pub file is installed mode 0444; newly created parent directories are mode 0700.
Before download, the command reads an identity-file passphrase twice from the controlling terminal
with echo disabled, like ssh-keygen. Submit an empty passphrase twice for no passphrase.

--no-passphrase installs without one and needs no terminal, which is how this command runs over
a non-interactive remote session. It selects an empty passphrase; it never carries a passphrase,
because an argument value would be visible to every process on the machine.

The identity file holds a key handle, not exported private-key material, so a passphrase here
protects a copy of the handle rather than the key itself; the Secure Enclave and the -t setting
remain the real control. A passphrase-protected identity file can still be verified, but only
from a terminal, because unlocking it requires reading the passphrase.

OPTIONS
  --ctk-sha256 SHA256 Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --identity-file PATH  Install the identity file at PATH and its public key at PATH.pub.
                        Default: ~/.ssh/identities/id_<first-16-hash-characters>.
  --no-passphrase       Install with an empty passphrase and no terminal prompt.
  --json              Emit the versioned machine-readable report instead of text.
"""

private let manifestHelp = """
USAGE
  se-sshctl manifest list|prune [--json]

Every verification is recorded, so an answer survives the run that produced it.
Without a record, "has this identity been verified?" can only be answered by
verifying again, and a check that was never run looks the same as one that passed
months ago.

Results accumulate per check: 'verify local' updates provider load and local
signing and leaves an earlier remote result alone, with its original timestamp.
Every outcome is shown with its age, and nothing expires on its own — a passed
check really did pass, and only you can decide whether it is still current.

The store is one JSON file at
~/Library/Application Support/se-sshctl/manifest.json, mode 0600.

SUBCOMMANDS
  list   Show every recorded verification with the age of each result.
  prune  Drop records whose identity file or CTK identity no longer exists.

Run 'se-sshctl manifest <subcommand> --help' for every option.
"""

private let manifestListHelp = """
USAGE
  se-sshctl manifest list [--json]

Prints every recorded verification: the CTK SHA-256 hash, identity file, SSH
fingerprint, and each check's outcome with how long ago it was measured. A
recorded remote pass also names the host it was against, because a pass against
one host proves nothing about another.

Records are written only after the fingerprint check matched, so an entry always
refers to an identity this tool actually resolved.

OPTIONS
  --json  Emit the stored manifest as versioned JSON.
"""

private let manifestPruneHelp = """
USAGE
  se-sshctl manifest prune [--json]

This is the cleanup path after 'sc_auth delete-ctk-identity'. Deleting the enclave
key leaves two dead things behind, and prune removes both:

  the record, which describes an identity that no longer exists;
  the identity file and its .pub, which hold nothing but a handle to the key that
  was just destroyed.

Neither can ever be used again, and 'install' cannot recreate the file, because
there is no identity left to download it from. Leaving the file would keep a
convincing-looking private key on disk that authenticates nothing.

A record whose identity file is already missing is dropped with nothing to delete.
A file is deleted only when its .pub still carries the recorded SSH fingerprint;
if the path was reused for another key, the file is left alone and reported.

prune never deletes a CTK identity and never touches a file whose CTK identity is
still present.

OPTIONS
  --json  Emit the removed records, deleted files, and kept files as versioned JSON.
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
  --identity-file PATH   Set IdentityFile to the installed Secure Enclave identity file PATH.
  --host-pattern PATTERN Set the SSH Host pattern for the rendered block.
  --json                 Emit a versioned object containing the rendered config instead of raw text.
"""

private let verifyHelp = """
USAGE
  se-sshctl verify local|remote ...

SUBCOMMANDS
  local   Prove the selected Secure Enclave identity can sign locally.
  remote  Prove the selected identity alone can authenticate to one SSH target.

Both report every check as passed, failed, or not-run. A check that did not run is
never reported as a pass.

Run 'se-sshctl verify <subcommand> --help' for every option.
"""

private let verifyLocalHelp = """
USAGE
  se-sshctl verify local --ctk-sha256 SHA256 --identity-file PATH [--json]

Signs a temporary challenge through Apple's provider and verifies the resulting SSH signature.

Every run reports providerLoad, localSigning, and remoteAuthentication as passed, failed, or
not-run. This command never contacts a server, so remoteAuthentication is always not-run;
it is reported rather than omitted so an untested check is never read as a passing one.
A failed run still prints the manifest and exits non-zero.

OPTIONS
  --ctk-sha256 SHA256  Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --identity-file PATH  Use the installed identity file at PATH and verify its fingerprint.
  --json                Emit the versioned machine-readable report instead of text.

An unencrypted identity file verifies with no prompt and no terminal. If the file is
passphrase-protected the passphrase is read once from the terminal and delivered to OpenSSH
over a pipe, never through arguments or the environment.
"""

private let verifyRemoteHelp = """
USAGE
  se-sshctl verify remote --ctk-sha256 SHA256 --identity-file PATH --target HOST [--ssh-option OPT]... [--json]

Performs a public-key-only BatchMode SSH authentication and runs the fixed remote command 'true'.
It does not install or revoke remote authorized_keys entries.

Every run reports providerLoad, localSigning, and remoteAuthentication as passed, failed, or
not-run; localSigning is always not-run here. A failed run still prints the manifest and exits
non-zero.

The client runs verbosely and its log is captured into the report on both pass and fail.
--json always carries it; text output prints it only on failure. Server authentication logs
are not collected: reading them requires privileged access on the target, which is outside
this tool's boundary. Check the server's own sshd log when the client log is not enough.

OPTIONS
  --ctk-sha256 SHA256  Select exactly one identity by its 64-character CTK SHA-256 public-key hash.
  --identity-file PATH  Use only the installed identity file at PATH.
  --target HOST         Connect to HOST, normally user@hostname, using isolated SSH options.
  --ssh-option OPT      Pass 'ssh -o OPT' (ssh_config syntax, e.g. Port=2222 or
                        'ProxyCommand=nc -x 127.0.0.1:9050 -X 5 %h %p'). Repeatable. The
                        client runs with -F none, so nothing from ~/.ssh/config applies;
                        this is how a target behind a jump or proxy is reached. Each OPT is
                        placed after the isolation options, and ssh keeps the first value
                        it sees for an option, so an OPT cannot re-enable the agent, the
                        user config, or password methods.
  --json                Emit the versioned machine-readable report instead of text.

An unencrypted identity file verifies with no prompt and no terminal. Unlocking an encrypted
one drops BatchMode, because OpenSSH uses BatchMode to suppress the passphrase prompt as well;
every other isolation option stays, the askpass responder refuses any prompt it does not
recognise, and the timeout still kills the process tree.
"""

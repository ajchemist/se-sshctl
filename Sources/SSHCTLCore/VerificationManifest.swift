import Foundation

public enum ManifestError: Error, LocalizedError, Equatable {
    case unreadable(String)
    case unwritable(String)

    public var errorDescription: String? {
        switch self {
        case let .unreadable(detail): "verification manifest could not be read: \(detail)"
        case let .unwritable(detail): "verification manifest could not be written: \(detail)"
        }
    }
}

/// One check's last known outcome and when it was established.
///
/// The timestamp is the point: a `passed` from months ago is still a real
/// result, but an operator deciding whether to trust it needs to see its age.
public struct ManifestCheck: Codable, Equatable, Sendable {
    public let outcome: VerificationOutcome
    public let at: Date?

    public init(outcome: VerificationOutcome = .notRun, at: Date? = nil) {
        self.outcome = outcome
        self.at = at
    }
}

public struct ManifestEntry: Codable, Equatable, Sendable {
    public var ctkSHA256: String
    public var sshFingerprint: String
    public var identityFile: String
    public var providerLoad: ManifestCheck
    public var localSigning: ManifestCheck
    public var remoteAuthentication: ManifestCheck
    /// The last `verify remote` target, so a recorded remote pass says which
    /// host it was against. A pass against one host proves nothing about another.
    public var target: String?
}

public struct VerificationManifest: Codable, Equatable, Sendable {
    public let schemaVersion = 1
    public var identities: [ManifestEntry]

    public init(identities: [ManifestEntry] = []) {
        self.identities = identities
    }
}

/// Keeps verification results across runs in one place.
///
/// A single store rather than a file beside each identity file: it answers
/// "what has been verified on this Mac" in one read, and it can be pruned when
/// identity files disappear, which a scattered file cannot be — an orphaned
/// sidecar is invisible once its directory is gone.
///
/// Results accumulate per check. A `verify local` run does not erase yesterday's
/// remote result; it updates what it actually measured and leaves the rest with
/// its original timestamp, so the age of each answer stays honest.
public struct VerificationManifestStore {
    private let directory: URL
    private let fileManager: FileManager
    private let now: () -> Date

    public init(
        directory: URL? = nil,
        fileManager: FileManager = .default,
        now: @escaping () -> Date = Date.init
    ) {
        self.directory = directory ?? fileManager
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("se-sshctl", isDirectory: true)
        self.fileManager = fileManager
        self.now = now
    }

    public var url: URL { directory.appendingPathComponent("manifest.json") }

    public func load() throws -> VerificationManifest {
        guard fileManager.fileExists(atPath: url.path) else { return VerificationManifest() }
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(VerificationManifest.self, from: Data(contentsOf: url))
        } catch {
            throw ManifestError.unreadable(
                (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            )
        }
    }

    /// Records a run. Reports whose preflight never matched a fingerprint are
    /// dropped: the specification asks that the manifest be written only after
    /// state and fingerprint checks pass, and an entry keyed to an identity
    /// this run never established would be a guess.
    @discardableResult
    public func record(_ report: VerificationReport, identityFile: String) throws -> Bool {
        guard let sshFingerprint = report.sshFingerprint else { return false }
        var manifest = try load()
        let timestamp = now()
        var entry = manifest.identities.first {
            $0.ctkSHA256 == report.ctkSHA256 && $0.identityFile == identityFile
        } ?? ManifestEntry(
            ctkSHA256: report.ctkSHA256,
            sshFingerprint: sshFingerprint,
            identityFile: identityFile,
            providerLoad: ManifestCheck(),
            localSigning: ManifestCheck(),
            remoteAuthentication: ManifestCheck(),
            target: nil
        )
        entry.sshFingerprint = sshFingerprint
        entry.providerLoad = merged(entry.providerLoad, report.checks.providerLoad, at: timestamp)
        entry.localSigning = merged(entry.localSigning, report.checks.localSigning, at: timestamp)
        let remote = merged(entry.remoteAuthentication, report.checks.remoteAuthentication, at: timestamp)
        if remote != entry.remoteAuthentication { entry.target = report.target }
        entry.remoteAuthentication = remote

        manifest.identities.removeAll {
            $0.ctkSHA256 == report.ctkSHA256 && $0.identityFile == identityFile
        }
        manifest.identities.append(entry)
        manifest.identities.sort { $0.ctkSHA256 < $1.ctkSHA256 }
        try write(manifest)
        return true
    }

    /// Drops entries whose identity file or CTK identity is gone. Returns what
    /// was removed so the operator sees it rather than having records vanish.
    public func prune(knownIdentityHashes: Set<String>) throws -> [ManifestEntry] {
        var manifest = try load()
        let orphaned = manifest.identities.filter {
            !fileManager.fileExists(atPath: $0.identityFile)
                || !knownIdentityHashes.contains($0.ctkSHA256)
        }
        guard !orphaned.isEmpty else { return [] }
        manifest.identities.removeAll { entry in orphaned.contains { $0 == entry } }
        try write(manifest)
        return orphaned
    }

    /// A check that did not run leaves the stored answer alone. Overwriting it
    /// with `not-run` would discard a real earlier result and report a check as
    /// never attempted when it had been.
    private func merged(
        _ stored: ManifestCheck,
        _ measured: VerificationOutcome,
        at timestamp: Date
    ) -> ManifestCheck {
        measured == .notRun ? stored : ManifestCheck(outcome: measured, at: timestamp)
    }

    private func write(_ manifest: VerificationManifest) throws {
        do {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
            encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(manifest).write(to: url, options: .atomic)
            // Set after the atomic replace: the temporary file it swaps in does
            // not inherit the old file's mode.
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw ManifestError.unwritable(
                (error as? LocalizedError)?.errorDescription ?? String(describing: error)
            )
        }
    }
}

# Changelog

## Unreleased

This release breaks compatibility in several places. Every break is listed
here with what replaces it.

### Removed: `se-sshctl identity delete`

Deletion now requires Apple's own `sc_auth delete-ctk-identity`.

The originating specification deferred destructive lifecycle commands until
creation, discovery, identity-file handling, and verification were proven on
hardware, and said not to add deletion in the same milestone. The command
shipped against that, and the prohibiting sentences were later deleted from
`HANDOFF.md` rather than honoured. Deletion is the one irreversible operation
here, and the ordering existed to keep an unproven tool from destroying a
user's only credential.

Migration:

```sh
se-sshctl identity list -t sha1        # find the sc_auth deletion hash
/usr/sbin/sc_auth delete-ctk-identity -h SHA1
se-sshctl manifest prune               # clear the record and the dead identity file
```

Remove remote authorization and confirm recovery access before doing this.
Neither `sc_auth` nor this tool can check either for you.

Beads decision `se-sshctl-9jy`.

### Removed: Homebrew tap dispatch from the release workflow

Tagged releases publish a GitHub Release and dispatch nothing further, so
`ajchemist/tap/se-sshctl` is no longer updated from this repository. The
specification excluded release publishing from this project.

Migration: build from source with `swift build --configuration release`, or
consume the published GitHub Release and its immutable tag archive from your
own tap. `docs/RELEASING.md` lists the repository variables and secrets that
are now unused and can be deleted.

Beads decision `se-sshctl-9jy`.

### Changed: verification JSON is `schemaVersion` 3

`status` was always the literal `"passed"` and the report existed only on the
success path. It is now one of `passed`, `failed`, or `not-run`, a `checks`
object is always present with all three checks, and `detail` carries the
failure reason.

A failed verification now emits this report on stderr instead of the generic
error report, and still exits non-zero.

New fields: `checks`, `detail`, `sshFingerprint`, and `clientLog` on
`verify remote`.

Consumers that asserted `status == "passed"` keep working. Consumers that
assumed a report implies success do not — check `status` explicitly.

### Changed: `doctor` JSON is `schemaVersion` 2

`platform` gains `verifiedRelease` (`true`, `false`, or `null` when the version
string could not be read as a number) and `minimumVerifiedRelease`.

The human output also changed shape: `provider: verified|unverified` collapsed
signature validity and Apple anchoring into one word and omitted the path and
identifier, which `docs/THREAT_MODEL.md` requires it to report. It now prints
the four signals separately. Parse `--json`, not the text.

### Changed: `manifest prune` JSON is `schemaVersion` 2

Introduced during this same cycle. `removed` is replaced by `removedRecords`,
`removedFiles`, and `keptFiles`, because prune now also deletes the identity
file and `.pub` left behind by a deleted CTK identity.

### Added

- `se-sshctl install --no-passphrase` installs without a controlling terminal,
  which is what makes a non-interactive remote install possible. It selects an
  empty passphrase; no flag ever carries a passphrase value.
- `verify local` and `verify remote` unlock a passphrase-protected identity
  file, which previously could be installed but never verified.
- `se-sshctl manifest list` and `se-sshctl manifest prune`: verification
  results now survive the run that produced them.
- `verify remote` runs the client verbosely and carries the log into the report.
- `doctor` warns below macOS 26 without blocking.
- `scripts/verify-none-remote.sh` and `scripts/verify-cert-expiry.sh` measure
  two questions nobody has answered yet.

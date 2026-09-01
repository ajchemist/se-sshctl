# Changelog

## Unreleased

This release breaks compatibility in several places. Every break is listed
here with what replaces it.

### Changed: `se-sshctl identity delete`

The command survives, with different behaviour. It was removed mid-cycle and
restored before release; nothing shipped without it, so the net change from
v0.1.4 is the one described here.

`--confirm` is now optional. Without it, the command resolves the identity,
prints what would be destroyed — SSH fingerprint, CTK SHA-256, sc_auth SHA-1,
label, parameters, and the identity files that would go with it — and stops.
The specification asks for the fingerprint to be displayed and then approved,
in that order; approving a hash pasted from elsewhere is not that.

Deletion now also removes what depended on the key: the identity file and its
`.pub`, which after deletion are handles to a key that no longer exists, and the
verification record, which is a claim about an identity that no longer exists.
A recorded file is deleted only when its `.pub` still carries this key's SSH
fingerprint, so a path reused for another key is left alone and reported.

The report is `schemaVersion` 3 and gains `ctkSHA1`, `sshFingerprint`,
`removedFiles`, `removedRecords`, and `keptFiles`.

Why it was removed and restored: the original specification deferred destructive
commands until the rest was hardware-verified, and the command had shipped
against that with the prohibition quietly deleted from `HANDOFF.md`. Reverting
restored the specification but not the safety, because removing the command did
not remove the operation — it moved the operation to raw
`sc_auth delete-ctk-identity -h SHA1`, which has no SHA-256 selection, no
ambiguity check, no fingerprint display, no confirmation, and no absence check.
The wrapper was safer than the workflow that replaced it.

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
string could not be read as a number) and `minimumVerifiedRelease`. The report
gains `consoleSession`, the account logged in at the console or `null` at the
login window, because provider-backed signing was measured to fail without one
while every other check still passes.

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
  results now survive the run that produced them. `prune` also deletes the
  identity file and `.pub` left behind by a deleted CTK identity.
- README documents which Apple binary and arguments each command runs, and
  which `sc_auth` subcommands this tool deliberately does not wrap.
- `verify remote` runs the client verbosely and carries the log into the report.
- `doctor` warns below macOS 26 without blocking.
- `scripts/verify-none-remote.sh` and `scripts/verify-cert-expiry.sh` measure
  two questions nobody has answered yet.

# Changelog

## 0.3.0

No compatibility breaks. Existing invocations behave as before; one check is
looser, on purpose, and is listed under Changed.

### Added: `identity create --unique`

`sc_auth` allows duplicate labels, and two identities with the same label and
parameters cannot be told apart by this tool afterwards: `IdentityResolver`
refuses to guess between rows with identical metadata, so neither `install` nor
`identity delete` can reach either of them. `--unique` refuses up front when an
identity with the label already exists, naming its CTK SHA-256 hash, before
`sc_auth` is invoked. Automation that creates by label should pass it.

### Added: `verify remote --ssh-option OPT`

The isolated client runs with `-F none`, so a target behind a jump host or a
proxy could not be verified at all. `--ssh-option` (repeatable, `ssh -o`
syntax, e.g. `Port=2222` or `ProxyCommand=nc -x 127.0.0.1:9050 -X 5 %h %p`)
appends `-o OPT` after the isolation set. `ssh` keeps the first value it sees
for an option, so an appended one cannot re-enable the agent, the user config,
or password methods. Control characters are rejected. Recorded in
`docs/THREAT_MODEL.md`.

### Added: `config render --tag TAG`

Renders a `Match tagged TAG` block instead of a `Host` block, so the identity
is selected by tag rather than by host: `ssh -P TAG user@host` uses it on any
target (OpenSSH 9.4 or later). The block ends with `Match all`, so the output
can be saved to a file and `Include`d at the top of `~/.ssh/config` without
pulling the lines after the Include into the block. Exactly one of
`--host-pattern` or `--tag` is required.

### Changed: an existing identity-file directory is refused only when writable

`install` refused any pre-existing parent directory with group or other bits,
so a common 755 `~/.ssh/identities` failed with `insecureDirectory` even though
the installed file is 0400 and holds a handle, not key material. The threat in
that directory is a swap, not a read: it now refuses group- or world-writable
directories and accepts readable ones. Missing directories are still created
0700. The error text changed from "accessible" to "writable".

### Added: release binaries

Each GitHub Release now carries `se-sshctl-<version>-macos-universal.tar.gz`
(one universal arm64 + x86_64 `se-sshctl`) and `SHA256SUMS`, so a nix
expression or a script can pin a binary by tag and hash instead of depending on
the Homebrew bottle. The tap dispatch payload gains `asset` and `asset_url`.
See `docs/RELEASING.md`.

## 0.2.0

Breaks compatibility in several places. Every break is listed here with what
replaces it.

It also records the first measurement of the workflow this tool exists for:
**`-t none` requires a console session.** From an SSH session, signing and SSH
authentication work while the account is logged in at the console, unlocked or
locked. Logged out they fail — the identity still lists and the server still
accepts the key, but the provider reports `device not found`. An unattended Mac
has to stay logged in; the screen may be locked. See
`docs/HARDWARE_VERIFICATION.md`.

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
- `se-sshctl --version`, and `seSSHCTL` in the `doctor` report. With schema
  versions moving, a binary that cannot say which build it is leaves an
  operator unable to tell whether output has the shape they expect. The release
  workflow refuses a tag whose version constant does not match it.
- `scripts/verify-none-remote.sh` and `scripts/verify-cert-expiry.sh`, which
  measured the two questions above. Both are runnable again on other hardware.

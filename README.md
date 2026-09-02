# se-sshctl

`se-sshctl` is a dependency-free Swift CLI for Apple Secure Enclave SSH
identities on macOS. It creates and manages CryptoTokenKit (CTK) identities
that OpenSSH can use through Apple's security-key provider.

## Why this exists

Apple's native commands cover the single-identity happy path. `se-sshctl` adds
deterministic identity selection and fail-closed lifecycle checks: it works
around `ssh-keygen -K` filename collisions, matches the requested identity by
SSH fingerprint, validates Apple's provider, and verifies signing and isolated
SSH authentication instead of trusting command exit status. It is safety-focused
orchestration around Apple tools, not another SSH agent or cryptographic
implementation.

## Install

```sh
brew install ajchemist/tap/se-sshctl
```

Each GitHub Release also carries `se-sshctl-<version>-macos-universal.tar.gz`
(one universal `se-sshctl` binary) and `SHA256SUMS`, for anything that pins a
binary by tag and hash (see `docs/RELEASING.md`).

Or build from source:

```sh
swift build --configuration release
```

The binary is written to `.build/release/se-sshctl`; copy it onto your `PATH`.

## Usage

This flow requests a CTK identity with a non-exportable `p-256-ne` private key.
Apple's tools keep that private key in the Secure Enclave so it cannot be
exported or copied; this provider path does not expose provenance attestation.
The commands install an OpenSSH identity file and verify authentication; you
authorize its public key on an SSH host with your existing access or
provisioning system.

### 1. Check this Mac

```sh
se-sshctl doctor
```

`doctor` checks the required Apple tools and verifies Apple's security-key
provider. It does not change the system.

### 2. Create a CTK identity

```sh
se-sshctl identity create -l example-key -k p-256-ne -t bio
```

`p-256-ne` creates a non-exportable private key. Labels are not unique to
`sc_auth`; `--unique` refuses when an identity with the label already exists,
which is what a script that creates by label should pass. `bio` requires user approval
for private-key operations. Copy the full `CTK SHA-256/hex` value from the
command output, then set these shell variables:

```sh
CTK_SHA256='<64-character CTK SHA-256 hash>'
IDENTITY_FILE="$HOME/.ssh/identities/example/id_ecdsa_sk_rk"
```

### 3. Install the identity file

```sh
se-sshctl install --ctk-sha256 "$CTK_SHA256" --identity-file "$IDENTITY_FILE"
```

The identity file is installed mode 0400 and its `.pub` mode 0444. A parent
directory that does not exist is created mode 0700; one that exists is accepted
unless group or other users can write to it.

The command asks for an identity-file passphrase twice. Enter an empty passphrase
twice if you do not want one. The OpenSSH private key file contains a key handle
for provider-backed operations, not exported Secure Enclave private-key material.

Verify local signing before you change a server:

```sh
se-sshctl verify local --ctk-sha256 "$CTK_SHA256" --identity-file "$IDENTITY_FILE"
```

### 4. Authorize the public key on the SSH host

```sh
cat "$IDENTITY_FILE.pub"
```

Add the printed public key to `~/.ssh/authorized_keys` for the remote account.
Use your existing access or your normal provisioning system. `se-sshctl` does
not modify remote authorization.

Render the required SSH client configuration:

```sh
se-sshctl config render --identity-file "$IDENTITY_FILE" --host-pattern host.example
```

Add the rendered block to `~/.ssh/config`. The command only prints the block;
it does not modify the file.

To select the identity by a tag instead of by host pattern, render a
`Match final tagged` block and either pass the tag on the command line or pin
it in a Host block (OpenSSH 9.4 or later):

```sh
se-sshctl config render --identity-file "$IDENTITY_FILE" --tag example > ~/.ssh/example.conf
# then, at the top of ~/.ssh/config:  Include ~/.ssh/example.conf
ssh -P example user@host.example
```

```
Host host.example
    Tag example        # every ssh host.example uses the identity; -P still wins
```

`final` makes the pinned form work: `Match` is evaluated once in file order,
so without it an Include at the top would never see a `Tag` set in a Host block
below. The block ends with `Match all`, so an `Include` at the top of the file
does not pull the lines after it into the block.

### 5. Verify remote authentication

```sh
se-sshctl verify remote --ctk-sha256 "$CTK_SHA256" --identity-file "$IDENTITY_FILE" --target user@host.example
ssh user@host.example
```

The verification command uses only the selected CTK identity. It does not
install or remove an `authorized_keys` entry. It ignores `~/.ssh/config`, so a
target behind a proxy or on another port is named with `--ssh-option`
(repeatable, `ssh -o` syntax), e.g. `--ssh-option Port=2222`; these are
appended after the isolation options and cannot override them.

Run any command with `--help` for all options and security effects.

The CLI supports:

- environment and provider diagnostics;
- human and versioned JSON identity listing;
- CTK identity creation with `p-256-ne` and `bio` or `none` protection;
- identity-file installation selected by SSH fingerprint;
- SSH configuration output without changes to user files;
- local signing and remote authentication verification;
- single-identity deletion selected by CTK SHA-256 hash.

## Security meaning

The supported creation parameters are:

```text
-k p-256-ne -t bio
-k p-256-ne -t none --allow-unattended-signing
```

`none` removes per-use approval. It does not replace Touch ID with a password.
Code running as the user can request signatures without approval. See the
[threat model](docs/THREAT_MODEL.md).

Labels do not select identities for changes; mutating commands take the full CTK
SHA-256 hash.

`identity delete` without `--confirm` shows what would be destroyed — the SSH
fingerprint, both hashes, the label, the parameters, and the identity files that
would go with it — and stops:

```sh
se-sshctl identity delete --ctk-sha256 SHA256              # preview
se-sshctl identity delete --ctk-sha256 SHA256 --confirm SHA256
```

Secure Enclave deletion is permanent. Remove the key from every server that
trusts it and confirm replacement access first; this tool cannot check either
condition for you.

`install` reads the identity-file passphrase from the controlling terminal with
echo disabled. It does not accept a passphrase through command arguments or the
environment, in either direction: `--no-passphrase` selects an empty one and
needs no terminal, which is how `install` runs over a non-interactive remote
session, but no flag ever carries a passphrase value.

An unencrypted identity file verifies with no prompt and no terminal. A
passphrase-protected one is unlocked by reading the passphrase once and handing
it to OpenSSH over a pipe; that path needs a terminal, and `verify remote` drops
`BatchMode` for it because OpenSSH uses `BatchMode` to suppress the passphrase
prompt as well. Every other isolation option stays in place.

The identity file holds a key handle, not exported private-key material, so a
passphrase here protects a copy of the handle rather than the key. The Secure
Enclave and the `-t` setting remain the real control.

`identity list` prints identity metadata for the current user. Share this output
only when you intend to disclose its labels and hashes.

`verify local` and `verify remote` report `providerLoad`, `localSigning`, and
`remoteAuthentication` as `passed`, `failed`, or `not-run`. A check a command
does not attempt is reported as `not-run` rather than omitted, so an untested
check is never read as a passing one. A failed run prints the same manifest and
exits non-zero. `verify remote` runs the client verbosely and carries that log
into the report; server authentication logs need privileged access on the target
and are not collected.

The CLI manages local CTK identities and verifies SSH access. It emits public-key
metadata for external tools, but it does not manage remote automation or
authorization.

## What each command actually runs

Every command is a wrapper around a fixed Apple binary at a fixed absolute path.
Nothing is resolved through `PATH`, and the provider path is not configurable.

| Command | Plumbing | What the wrapper adds |
| --- | --- | --- |
| `doctor` | `sw_vers`, `uname -m`, `ssh -V`, `codesign --verify --strict` and `-dr -` on the provider | Reports path, signature validity, Apple anchor, and identifier as four separate signals; warns below the verified macOS floor |
| `identity list` | `sc_auth list-ctk-identities -t TYPE -e ENCODING` | Column-boundary parsing that survives labels with spaces and Unicode; strict field validation; versioned JSON |
| `identity create` | `sc_auth create-ctk-identity -l LABEL -k TYPE -t PROT` | Refuses key types Apple's SSH provider cannot use; requires `--allow-unattended-signing` for `-t none`; snapshots the inventory before and after and proves exactly one matching identity appeared; never auto-deletes on partial failure; `--unique` refuses an existing label |
| `identity delete` | `sc_auth delete-ctk-identity -h SHA1` | Selects by the stable SHA-256 hash and resolves the SHA-1 locator internally; refuses ambiguous metadata; shows the SSH fingerprint before approval; verifies absence in both hash formats; removes the dead identity file and verification record |
| `install` | `ssh-keygen -K -w /usr/lib/ssh-keychain.dylib` | Runs in isolated directories and refuses overwrite; works around `-K` ignoring the provider filter by selecting on SSH fingerprint; answers OpenSSH prompts through a prompt-validating askpass that fails closed; installs 0400/0444 |
| `verify local` | `ssh-keygen -Y sign` then `ssh-keygen -Y verify` | Fingerprint and provider preflight; signs a throwaway challenge and verifies the signature against the installed public key; tri-state report |
| `verify remote` | `ssh -v` with every ambient identity source disabled | Proves the selected identity alone authenticated; captures the client log; tri-state report; `--ssh-option` reaches proxied targets without loosening isolation |
| `config render` | none | Prints a `Host` or `Match final tagged` block; never writes `~/.ssh/config` |
| `manifest list`, `manifest prune` | none | Local verification records only |

`sc_auth` subcommands this tool deliberately does not wrap:

- `delete-all-ctk-identities` — there is no bulk delete and there will not be one.
- `export-ctk-identity`, `import-ctk-identities` — moving key material is the
  opposite of what a non-exportable Secure Enclave identity is for.
- `create-ctk-csr`, `import-ctk-certificate` — certificate lifecycle is not
  managed here. `scripts/verify-cert-expiry.sh` uses them to measure whether
  certificate validity affects authentication at all.
- `pair`, `unpair`, `enable_for_login`, `filevault`, PIV and legacy smart-card
  commands — a different feature area.

## Verification records

Every `verify` run is recorded, so a result outlives the command that produced
it:

```sh
se-sshctl manifest list
se-sshctl manifest prune     # clean up after 'sc_auth delete-ctk-identity'
```

Results accumulate per check. A `verify local` run updates provider load and
local signing and leaves an earlier remote result alone, keeping its original
timestamp, so `manifest list` shows what has been proven and how long ago:

```text
  provider load:         passed (2h ago)
  local signing:         passed (2h ago)
  remote authentication: passed (37d ago) → deploy@host.example
```

Nothing expires by itself. A check that passed really did pass, and only you can
decide whether a 37-day-old result is still current — but you cannot decide that
without seeing its age, which is why the age is never omitted. Records are
written only after the fingerprint check matched.

The store is a single file at
`~/Library/Application Support/se-sshctl/manifest.json`, mode 0600.

`prune` is the cleanup path after `sc_auth delete-ctk-identity`. Deleting the
enclave key leaves two dead things behind, and `prune` removes both: the record,
and the identity file with its `.pub`, which hold nothing but a handle to the key
that was just destroyed. Neither can ever be used again, and `install` cannot
recreate the file because there is no identity left to download it from — leaving
it would keep a convincing-looking private key on disk that authenticates
nothing.

A file is deleted only when its `.pub` still carries the recorded SSH
fingerprint, so a path reused for another key is left alone and reported.
`prune` never deletes a CTK identity, and never touches a file whose CTK identity
is still present.

Breaking changes and their migrations are in [CHANGELOG.md](CHANGELOG.md).

## Requirements

### Server

The identity is an OpenSSH security key of type
`sk-ecdsa-sha2-nistp256@openssh.com`, so the server must accept that key type:
OpenSSH 8.2 or later, with `sk-ecdsa-sha2-nistp256@openssh.com` present in
`PubkeyAcceptedAlgorithms`. A server that restricts that list, or an older
sshd, refuses the key regardless of anything on this Mac. `verify remote`
captures the client log, which is where such a refusal shows up.

Nothing on the server side has been tested beyond a default-policy localhost
run; see the hardware boundary below.

### Client

macOS 26 (Tahoe) and later. That is where this project has physical evidence:
`docs/HARDWARE_VERIFICATION.md` records macOS 26.6.x, and nothing older has been
tested by anyone here.

Older releases are not blocked. Public reports disagree about whether the
`sc_auth` Secure Enclave path works on Sequoia at all, so refusing to run would
deny setups that may be fine. Instead `doctor` says plainly that the release is
below the verified minimum, so an unexplained failure during creation, download,
or signing has an obvious first suspect.

## CI and hardware boundary

GitHub Actions builds the project, runs all tests and fixtures, and performs
read-only JSON smoke checks on `macos-latest`. CI does not test Secure Enclave
key creation, provider-backed signing, biometric behavior, remote sessions, or
OpenSSH server policy. These tests require a controlled physical Mac.

See the [physical-Mac verification record](docs/HARDWARE_VERIFICATION.md) for
the tested create, install, sign, authenticate, and revoke flow.
Three wizards exercise the current source on real hardware and append what they
observe to that record. Each creates a throwaway identity and deletes it again:

- [`scripts/verify-bio.sh`](scripts/verify-bio.sh) — a `bio` run on a MacBook Air
  with Touch ID.
- [`scripts/verify-none-remote.sh`](scripts/verify-none-remote.sh) — whether a
  `none` identity signs and authenticates from an SSH session with the console
  locked, logged out, and after a reboot before first unlock. Run it over SSH,
  once per context; state survives the reboot.

  Each run performs two real operations on the Mac that holds the identity:
  `ssh-keygen -Y sign` through Apple's provider, and a full public-key SSH
  authentication to `USER@localhost` using only the installed identity file,
  with ssh-agent, `~/.ssh/config`, host-based, password, and
  keyboard-interactive authentication all disabled — so the only way it can
  succeed is a fresh signature from the enclave. `localhost` is deliberate: it
  removes the network and a remote sshd policy as variables, leaving exactly
  the question being asked. It does not cover launchd or other sessionless
  daemon contexts.
- [`scripts/verify-cert-expiry.sh`](scripts/verify-cert-expiry.sh) — whether an
  expired X.509 certificate stops OpenSSH from using the Secure Enclave key
  behind it. It replaces the certificate through `sc_auth create-ctk-csr` and
  `import-ctk-certificate`, so the private key is unchanged between the two
  measurements. Needs an OpenSSL 3 binary; macOS ships LibreSSL, which cannot
  backdate `notAfter`.

### What has been measured so far

- **Certificate expiry does not affect this path.** An expired X.509 certificate
  — replaced through `sc_auth create-ctk-csr` and `import-ctk-certificate`, so
  the non-exportable key is unchanged — leaves provider-backed signing, SSH
  authentication, and a fresh `ssh-keygen -K` download all working, even though
  `sc_auth` reports `certificateValid=false`. The replacement was signed by an
  unrelated CA, so OpenSSH is not tolerating an expired certificate; it does not
  consult the certificate here at all. `Valid=NO` is not a signal that a key
  stopped working, and never a reason to delete it.
- **`-t none` needs a console session, but it may be locked.** From an SSH
  session, signing and a real public-key SSH authentication both succeed while
  the console is logged in — unlocked or locked. Once the account is **logged
  out of the GUI they both fail**: the identity still lists, and OpenSSH still
  offers the key and has it accepted, but the provider cannot reach the enclave
  and reports `device not found`.

  This is the tool's central operational constraint. The remote-Mac workflow
  `-t none` exists for works, provided somebody stays logged in at the console.
  Locking the screen is fine. Logging out is not.

  `doctor` reports the console session for this reason: every other check it
  makes inspects a binary, and all of them pass on a logged-out Mac where
  nothing can sign.

Full records, including what each run did not cover, are in
[`docs/HARDWARE_VERIFICATION.md`](docs/HARDWARE_VERIFICATION.md).

## Development

```sh
swift build
swift run se-sshctl --help
swift test
```

## Acknowledgements

Inspired by:

- [Hacker News: native Secure Enclave-backed SSH keys on macOS](https://news.ycombinator.com/item?id=46025721)
- [sekey](https://github.com/sekey/sekey)
- [Secretive](https://github.com/maxgoedjen/secretive)

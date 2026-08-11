# se-sshctl

`se-sshctl` is a dependency-free Swift CLI for managing and verifying Apple's
CryptoTokenKit-backed Secure Enclave SSH identities on macOS.

## Commands

```sh
swift build
swift run se-sshctl --help
swift test
```

The CLI supports:

- environment and provider diagnostics;
- human and schema-versioned JSON identity listing using native `-t sha1|sha256|ssh` and `-e hex|b64` values;
- plumbing identity creation using sc_auth's `-l`, `-k p-256-ne`, and `-t bio|none` vocabulary;
- collision-safe resident-wrapper installation selected by SSH fingerprint;
- SSH config rendering without modifying user files;
- local signing and remote authentication verification;
- native SHA-1 single-identity deletion and policy-bearing retirement, both with post-delete verification.

Run any command with `--help` for its arguments and security effects. Creation
with `-t none` requires `--allow-unattended-signing`. Plumbing deletion preserves
`sc_auth delete-ctk-identity -h` SHA-1 semantics and requires the exact hash twice;
porcelain retirement selects by CTK SHA-256 hash and additionally requires remote
revocation and recovery-access acknowledgements. Labels never select a mutating
target, and there is no bulk-delete command.

`wrapper install` reads the wrapper passphrase twice from the controlling
terminal with echo disabled, following `ssh-keygen` behavior. Two empty entries
select no passphrase; the passphrase is never accepted through argv or environment.

The table parser uses header column boundaries, preserving spaces, Unicode, and
shell metacharacters in labels. Unknown/localized headers and malformed or extra
columns are errors rather than guessed formats. Invoking `identity list` prints
the current user's identity metadata; use it only when that disclosure is
intended.

## Command layers

Plumbing preserves native `sc_auth`, `ssh-keygen`, and SSH vocabulary while
enforcing the SSH-only scope and safety invariants. Porcelain may compose those
commands into user-defined workflows; today `identity retire` is the only porcelain
command. See [ADR 0001](docs/adr/0001-plumbing-preserves-native-vocabulary.md)
and the [domain language](CONTEXT.md).

## Security meaning

The low-level creation parameters are:

```text
-k p-256-ne -t bio
-k p-256-ne -t none --allow-unattended-signing
```

`p-256-ne` means the private key is non-exportable. `none` removes per-use user
authentication; it is not TTY authentication and does not replace Touch ID with
a password. Code running as the user may request signatures without approval.
See [the threat model](docs/THREAT_MODEL.md).

The CLI owns local Secure Enclave SSH identity management and verification only.
It emits machine-readable public-key metadata for external tools but does not
deliver events or integrate with remote automation services.

## CI and hardware boundary

GitHub Actions runs on `macos-latest`, prints `sw_vers`, architecture, Swift, and
OpenSSH versions, then builds, runs all tests/fixtures, and performs non-mutating JSON
smoke checks. This does **not** verify Secure Enclave key creation, provider-backed
signing, biometric behavior, remote/headless sessions, or OpenSSH server
user-presence policy. Those behaviors require separately approved tests on a
controlled physical Mac and are never part of the default suite.

See [the physical-Mac verification record](docs/HARDWARE_VERIFICATION.md) for the
tested create/install/sign/authenticate/revoke/delete canary flow and remaining
session-context gaps.

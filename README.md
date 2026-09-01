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
swift build --configuration release
```

The binary is written to `.build/release/se-sshctl`; copy it onto your `PATH`.

This repository publishes a GitHub Release per tag and nothing else. It no longer
dispatches Homebrew tap updates, so `ajchemist/tap/se-sshctl` is not kept current
from here. See [release automation](docs/RELEASING.md).

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

`p-256-ne` creates a non-exportable private key. `bio` requires user approval
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

### 5. Verify remote authentication

```sh
se-sshctl verify remote --ctk-sha256 "$CTK_SHA256" --identity-file "$IDENTITY_FILE" --target user@host.example
ssh user@host.example
```

The verification command uses only the selected CTK identity. It does not
install or remove an `authorized_keys` entry.

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

This CLI does not delete CTK identities. Secure Enclave deletion is permanent and
the local CLI cannot prove that remote authorization was removed or that recovery
access works, so removal stays with Apple's own `sc_auth delete-ctk-identity`
after you have verified both conditions yourself.

`install` reads the identity-file passphrase from the controlling terminal
with echo disabled. It does not accept the passphrase through command arguments
or the environment.

`identity list` prints identity metadata for the current user. Share this output
only when you intend to disclose its labels and hashes.

The CLI manages local CTK identities and verifies SSH access. It emits public-key
metadata for external tools, but it does not manage remote automation or
authorization.

## CI and hardware boundary

GitHub Actions builds the project, runs all tests and fixtures, and performs
read-only JSON smoke checks on `macos-latest`. CI does not test Secure Enclave
key creation, provider-backed signing, biometric behavior, remote sessions, or
OpenSSH server policy. These tests require a controlled physical Mac.

See the [physical-Mac verification record](docs/HARDWARE_VERIFICATION.md) for
the tested create, install, sign, authenticate, and revoke flow.
Run [`scripts/verify-bio.sh`](scripts/verify-bio.sh) on a MacBook Air with Touch
ID to exercise the current source and append a reviewed `bio` run to that record.

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

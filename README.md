# se-sshctl

`se-sshctl` is a dependency-free Swift CLI for Apple Secure Enclave SSH
identities on macOS. It creates and manages CryptoTokenKit (CTK) identities
that OpenSSH can use through Apple's security-key provider.

## Install

```sh
brew install ajchemist/tap/se-sshctl
```

## Usage

This flow creates a CTK identity with a non-exportable private key. The private
key stays in the Secure Enclave. You cannot export or copy it. The commands
install a resident-key wrapper, authorize its public key on an SSH host, and
verify authentication.

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
WRAPPER="$HOME/.ssh/identities/example/id_ecdsa_sk_rk"
```

### 3. Install the resident-key wrapper

```sh
se-sshctl wrapper install --ctk-sha256 "$CTK_SHA256" --destination "$WRAPPER"
```

The command asks for a wrapper passphrase twice. Enter an empty passphrase
twice if you do not want one. The wrapper is a handle for provider-backed
operations. It does not contain the Secure Enclave private key.

Verify local signing before you change a server:

```sh
se-sshctl verify local --ctk-sha256 "$CTK_SHA256" --wrapper "$WRAPPER"
```

### 4. Authorize the public key on the SSH host

```sh
cat "$WRAPPER.pub"
```

Add the printed public key to `~/.ssh/authorized_keys` for the remote account.
Use your existing access or your normal provisioning system. `se-sshctl` does
not modify remote authorization.

Render the required SSH client configuration:

```sh
se-sshctl config render --identity-file "$WRAPPER" --host-pattern host.example
```

Add the rendered block to `~/.ssh/config`. The command only prints the block;
it does not modify the file.

### 5. Verify remote authentication

```sh
se-sshctl verify remote --ctk-sha256 "$CTK_SHA256" --wrapper "$WRAPPER" --target user@host.example
ssh user@host.example
```

The verification command uses only the selected CTK identity. It does not
install or remove an `authorized_keys` entry.

Run any command with `--help` for all options and security effects.

## Command layers

Plumbing commands preserve native `sc_auth`, `ssh-keygen`, and SSH terms and
values. Porcelain commands can compose them into policy-aware workflows.
`identity retire` is the only porcelain command. See Beads decision
`se-sshctl-1a7` and the [domain language](CONTEXT.md).

The CLI supports:

- environment and provider diagnostics;
- human and versioned JSON identity listing;
- CTK identity creation with `p-256-ne` and `bio` or `none` protection;
- resident-key wrapper installation selected by SSH fingerprint;
- SSH configuration output without changes to user files;
- local signing and remote authentication verification;
- single-identity deletion and policy-aware retirement.

## Security meaning

The supported creation parameters are:

```text
-k p-256-ne -t bio
-k p-256-ne -t none --allow-unattended-signing
```

`none` removes per-use approval. It does not replace Touch ID with a password.
Code running as the user can request signatures without approval. See the
[threat model](docs/THREAT_MODEL.md).

Labels do not select identities for changes. Raw `identity delete` requires the
exact native SHA-1 hash twice. Prefer `identity retire`: it also requires you to
confirm remote revocation and recovery access. Secure Enclave deletion is
permanent. There is no bulk-delete command.

`wrapper install` reads the wrapper passphrase from the controlling terminal
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
the tested create, install, sign, authenticate, revoke, and delete flow.

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

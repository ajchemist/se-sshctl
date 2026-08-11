# se-sshctl

`se-sshctl` is a dependency-free Swift foundation for inspecting Apple's
CryptoTokenKit-backed SSH path on macOS. This first slice is deliberately
read-only: it cannot create, import, export, install, retire, or delete an
identity.

## Commands

```sh
swift build
swift run se-sshctl doctor --json
swift run se-sshctl identity list --json
swift test
```

Both commands emit deterministic, schema-versioned JSON (`schemaVersion: 1`).
`doctor` reports the macOS version/build, architecture, system OpenSSH version,
fixed system-tool paths, and whether `/usr/lib/ssh-keychain.dylib` has a valid
Apple-anchored designated requirement. `identity list` invokes only:

```text
/usr/sbin/sc_auth list-ctk-identities -t sha256 -e hex
```

The table parser uses header column boundaries, preserving spaces, Unicode, and
shell metacharacters in labels. Unknown/localized headers and malformed or extra
columns are errors rather than guessed formats. Invoking `identity list` prints
the current user's identity metadata; use it only when that disclosure is
intended.

## Security meaning

The intended future profiles remain:

```text
interactive = p-256-ne + bio
remote      = p-256-ne + none
```

`p-256-ne` means the private key is non-exportable. `none` removes per-use user
authentication; it is not TTY authentication and does not replace Touch ID with
a password. Code running as the user may request signatures without approval.
See [the threat model](docs/THREAT_MODEL.md).

## `ssh.key.created` v1 foundation

`SSHCTLCore` defines the schema-versioned event, an injectable
`WebhookDelivering` protocol, and an explicit post-creation outcome:

- delivery succeeds: `succeeded` / `delivered`;
- delivery is not configured: `succeeded` / `not-configured`;
- delivery fails after verified creation: `partial-success` / `pending`, with a
  non-secret v1 outbox record and the same idempotent `eventId`.

The event can contain only the label, key type/protection, CTK public-key hash,
SSH fingerprint, public key, and local-signing result. Its type has no fields for
private material, wrapper contents, Keychain data, credentials, tokens, or
environment data.

There is intentionally no HTTP client and no CLI webhook wiring yet. Live
delivery must wait for a separately verified create/discover/wrapper/fingerprint/
local-signing transaction. Before enabling it, the project must decide the HTTPS
endpoint configuration, bounded timeouts, HMAC headers and secret source, retry
policy, and restrictive outbox location. The unit test path uses an injected mock
sink and opens no network socket:

```sh
swift test --filter WebhookTests
```

## CI and hardware boundary

GitHub Actions runs on `macos-latest`, prints `sw_vers`, architecture, Swift, and
OpenSSH versions, then builds, runs all tests/fixtures, and performs read-only JSON
smoke checks. This does **not** verify Secure Enclave key creation, provider-backed
signing, biometric behavior, remote/headless sessions, or OpenSSH server
user-presence policy. Those behaviors require separately approved tests on a
controlled physical Mac and are never part of the default suite.

# se-sshctl implementation handoff

## Purpose

Build a production-oriented macOS CLI that manages and verifies SSH identities created by Apple’s native CryptoTokenKit/Secure Enclave path on macOS Tahoe and newer.

The implementation will be continued in the Orca app with Codex or Claude. Start by reading this file. There is no implementation yet.

The tool is tentatively named `se-sshctl`.

## User requirement driving the design

The primary operational use case is a Mac that is itself accessed remotely and then used to initiate outbound SSH connections.

An Aqua/LocalAuthentication prompt in the middle of that workflow is a blocking dependency: the operator may have only an SSH TTY and no one may be present at the Mac’s console.

Therefore the tool needs a deliberate remote/unattended mode based on:

```text
p-256-ne + sc_auth -t none
```

This has an important security meaning:

```text
p-256-ne  = the private key is non-exportable
auth=none = there is no per-use user authentication
```

`none` does **not** replace Touch ID with a TTY password or PIN. It removes the user-presence gate. A process able to use the provider in the user context can request signatures without approval. Do not describe this as “TTY authentication.”

An interactive mode may also support `bio`, but it must not be silently selected for a remote workflow, and `none` must never be a silent fallback from failed biometric setup.

## Newly accepted distribution and automation requirements

The project will be published as a **public GitHub repository**. Use GitHub Actions with `macos-latest` as the primary hosted CI environment for Swift build, unit tests, parser fixtures, CLI smoke tests, and packaging checks.

Do not claim that GitHub-hosted runners verify real Secure Enclave behavior. Hosted `macos-latest` runners may be virtualized, their image changes over time, and they are not the hardware-backed CTK integration boundary. Keep hardware/Keychain mutation tests opt-in and run them on controlled physical Macs. CI should still record `sw_vers`, Swift, and OpenSSH versions so image drift is visible.

The CLI must support a post-creation automation event that can deliver the generated **public key and key-created metadata** to an HTTPS webhook. The first version should define and test a stable event contract before coupling it to any specific automation platform.

Suggested event name and minimum payload:

```json
{
  "schemaVersion": 1,
  "eventId": "UUID",
  "eventType": "ssh.key.created",
  "occurredAt": "RFC3339 timestamp",
  "identity": {
    "label": "example",
    "keyType": "p-256-ne",
    "protection": "none",
    "ctkPublicKeyHash": "...",
    "sshFingerprint": "SHA256:...",
    "publicKey": "sk-ecdsa-sha2-nistp256@openssh.com ..."
  },
  "verification": {
    "localSigning": "passed"
  }
}
```

Webhook constraints:

- emit only after identity discovery, public-key extraction, fingerprint matching, wrapper installation, and required local verification have completed;
- never include private material, wrapper contents, Keychain data, passphrases, tokens, environment dumps, or unrelated identity inventory;
- use HTTPS, bounded connect/request timeouts, deterministic JSON encoding, an idempotent event ID, and a user-agent/version;
- support request authentication such as an HMAC signature, but keep the signing secret outside repository files and command-line arguments;
- treat “key created, webhook failed” as an explicit partial-success state; never delete the CTK identity as automatic rollback;
- persist enough non-secret outbox state for an explicit retry command, with duplicate delivery made safe by `eventId`;
- make webhook delivery optional and test it against a local mock server in CI;
- design the sink behind a protocol so tests do not require network access.

The exact endpoint configuration, HMAC header names, retry policy, and outbox location are product decisions to document before enabling live delivery. Implement a conservative default and expose the assumptions in help and JSON output.

## Fixed architectural direction

Implement a thin, robust Swift CLI around Apple’s supported system components:

```text
se-sshctl (Swift)
  ├── /usr/sbin/sc_auth
  ├── /usr/bin/ssh-keygen
  ├── /usr/bin/ssh-add       # optional; not the preferred runtime path
  ├── /usr/bin/ssh
  └── /usr/lib/ssh-keychain.dylib
```

Do not implement:

- a new SSH agent;
- the OpenSSH security-key provider ABI;
- Secure Enclave cryptography;
- a private CTK enrollment mechanism;
- a TTY passphrase gate that claims to protect the underlying `none` key.

Use `sc_auth` for CTK identity mutations. Swift should provide safe orchestration, state comparison, filesystem handling, machine-readable output, and verification.

This uses the same Apple system path as [`sekey.sh`](https://github.com/cavoirom/sekey-sh), but the product should not be a renamed shell script. `sekey.sh` is reference material for commands and failure cases.

## Why Swift

- Native fit for macOS process, filesystem, code-signing, and future read-only Security/CryptoTokenKit diagnostics.
- No Python, Ruby, Homebrew, or shell runtime dependency beyond Apple’s system tools.
- Typed state and JSON output.
- Safer argument handling than building shell command strings.
- Straightforward signed/notarized universal binary distribution.

Use Swift Package Manager. Prefer no third-party dependency for the first narrow command set unless a dependency is explicitly justified and accepted.

## Verified development host

Verified on 2026-08-11:

```text
macOS:           26.6.1 (25G76)
architecture:    arm64
Swift:           Apple Swift 6.2.4
OpenSSH:         OpenSSH_10.3p1, LibreSSL 3.3.6
sc_auth:         /usr/sbin/sc_auth
provider:        /usr/lib/ssh-keychain.dylib
provider ID:     com.apple.ssh-keychain
provider signer: Apple system signature
```

The local `sc_auth(8)` page exposes:

- `create-ctk-identity`;
- `delete-ctk-identity`;
- `list-ctk-identities`;
- `p-256-ne`;
- protection modes `bio|none`;
- SSH-compatible fingerprint listing via `list-ctk-identities -t ssh`.

The same man page says that a non-exportable CTK private key is protected by the Secure Enclave and never leaves it in open form.

The `ssh-keychain(8)` page says `/usr/lib/ssh-keychain.dylib` exposes identities from CTK smart cards and persistent tokens. It supports selecting identities by public-key hash through `KEYCHAIN_CERTIFICATES` or `~/.ssh/sshkeychain.plist`.

## Related implementations are not interchangeable

### Secretive Secure Enclave keys

Secretive creates its own Secure Enclave keys through CryptoKit, stores app-scoped opaque representations, and exposes them through Secretive’s own SSH agent socket. Its P-256 keys are regular `ecdsa-sha2-nistp256` SSH keys.

### Apple CTK SSH path

`sc_auth` creates a CTK identity in Apple’s token path. `/usr/lib/ssh-keychain.dylib` adapts compatible CTK identities to OpenSSH as:

```text
sk-ecdsa-sha2-nistp256@openssh.com
```

Do not attempt compatibility with Secretive’s internal key store.

## Recommended command surface

Names may be adjusted, but keep responsibilities separated:

```text
se-sshctl doctor [--json]
se-sshctl identity list [--json]
se-sshctl identity create --label LABEL --profile interactive|remote
se-sshctl wrapper install --identity HASH [--destination PATH]
se-sshctl config render --identity HASH --host-pattern PATTERN
se-sshctl verify local --identity HASH
se-sshctl verify remote --identity HASH --target HOST
```

Defer destructive lifecycle commands until creation, discovery, wrapper handling, and verification are proven:

```text
se-sshctl identity retire ...
se-sshctl identity delete ...
```

Proposed profiles:

```text
interactive → p-256-ne + bio
remote      → p-256-ne + none
```

Require an explicit acknowledgement such as `--allow-unattended-signing` before creating a `none` identity. Do not rely on a generic yes/no prompt alone in non-interactive mode.

## Process execution rules

- Invoke fixed absolute executable paths.
- Use `Process.executableURL` plus an argument array; never invoke `/bin/sh -c`.
- Keep environment changes scoped to the child process.
- Capture stdout, stderr, exit status, termination reason, and timeout separately.
- Never place secrets, passphrases, or key material in command-line arguments or logs.
- Treat unexpected stdout formats as errors; do not guess.
- Do not modify `/usr/sbin/sc_auth`, even though its man page describes it as a script administrators may customize.

Prefer per-process identity selection using `KEYCHAIN_CERTIFICATES` when calling the provider. Do not globally export `SSH_SK_PROVIDER` or change `.zprofile` by default.

For generated SSH configuration, prefer an explicit wrapper and provider:

```sshconfig
Host example-pattern
    IdentityFile ~/.ssh/secure-enclave/<stable-name>
    SecurityKeyProvider /usr/lib/ssh-keychain.dylib
    IdentitiesOnly yes
    ForwardAgent no
```

Do not make `ssh-agent` resident-key discovery the normal runtime path.

## Identity and state model

Keep these identifiers distinct:

```text
label                   human-readable mutable metadata
CTK public-key hash     local lookup/deletion/provider-selection locator
SSH SHA-256 fingerprint server deployment/rotation/audit identity
```

The SSH SHA-256 fingerprint should be the canonical operational identity. Labels may contain spaces or Unicode and may be duplicated.

A machine-readable manifest should include at least:

```json
{
  "schemaVersion": 1,
  "label": "example",
  "ctkPublicKeyHash": "...",
  "sshFingerprint": "SHA256:...",
  "keyType": "p-256-ne",
  "protection": "none",
  "provider": "/usr/lib/ssh-keychain.dylib",
  "macOSBuild": "25G76",
  "verification": {
    "providerLoad": "not-run",
    "localSigning": "not-run",
    "remoteAuthentication": "not-run"
  }
}
```

Represent `passed`, `failed`, and `not-run` separately. Never turn “not tested” into success.

## Safe creation transaction

The create workflow should be treated as a transaction with evidence:

1. Acquire a per-user operation lock.
2. Record the pre-create CTK identity set.
3. Show the requested plan and protection semantics.
4. Invoke `sc_auth create-ctk-identity`.
5. Record the post-create identity set.
6. Require exactly one new identity matching the requested key type and protection.
7. Generate resident wrapper output inside a new `0700` temporary directory.
8. Inspect every generated file; do not trust default filenames.
9. Match the new CTK identity to the OpenSSH wrapper by fingerprint.
10. Install with non-overwriting, atomic filesystem operations and restrictive permissions.
11. Perform an actual signing test.
12. Write the manifest only after state and fingerprint checks pass.

A command returning exit status zero is not sufficient evidence of success.

If creation succeeds but a later step fails, report the exact partial state and recovery command. Do not automatically delete a newly created CTK identity as rollback without explicit approval.

## Resident wrapper handling

`ssh-keygen -K` writes resident-key wrapper files in its current directory and may encounter default-name collisions when multiple identities exist.

Requirements:

- always run it in an isolated temporary directory;
- never run it directly in `~/.ssh`;
- detect prompts and timeouts;
- never overwrite an existing file;
- match by fingerprint, not filename or list order;
- install the wrapper with mode `0600` and parent directory `0700`;
- install the public key separately;
- use an atomic move after verification.

The OpenSSH `Enter PIN for authenticator:` prompt during resident-key download may be a generic provider prompt rather than a real CTK PIN. `-N ""` controls the wrapper-file passphrase, not the Secure Enclave key’s access policy. Establish a tested non-Aqua way to handle the provider’s empty/dummy PIN prompt; do not assume it from documentation.

A wrapper passphrase is not a strong gate for an underlying `none` identity because a process with provider access may rediscover the resident identity and create another wrapper. Document this honestly.

## `none` and remote-session verification

`none` is expected to remove LocalAuthentication/Touch ID Aqua prompts from signing. This does not prove that all remote launch contexts can access the CTK identity.

Build an opt-in integration matrix covering:

1. local terminal with GUI session unlocked;
2. remote SSH while the same user is logged into the GUI and unlocked;
3. remote SSH while the console is locked;
4. remote SSH while the user is logged out of the GUI;
5. after reboot before first GUI login/unlock;
6. non-interactive remote command execution;
7. a launchd/automation context if it is in scope.

Record whether failure occurs in wrapper loading, provider loading, CTK lookup, signing, or server authentication.

Do not claim “headless supported” until this matrix has real results.

## OpenSSH user-presence compatibility question

The CTK key is presented as an OpenSSH `sk-*` key. OpenSSH servers can enforce the security-key user-presence and user-verification flags. `authorized_keys` supports `no-touch-required`, but it is not yet verified whether Apple’s provider maps a `none` identity to a signature that passes the default server policy.

Do not add `no-touch-required` speculatively. Test both:

- a default OpenSSH canary server policy;
- an explicitly scoped `no-touch-required` policy when necessary.

Capture client verbose logs and server authentication logs. Make the result part of `verify remote` diagnostics.

## Security boundaries

A `p-256-ne + none` identity protects against private-key extraction and cloning. It does not protect against signing abuse by malware or an attacker already executing in the user context.

Treat remote-profile identities as device-bound machine credentials:

- one independent key per Mac and role;
- no key copying between Macs;
- no agent forwarding;
- avoid one universal key with broad root access;
- prefer non-root accounts and narrowly scoped sudo;
- preserve a separate break-glass path;
- support explicit remote revocation;
- consider short-lived SSH certificates and scoped principals as a later integration.

Do not promise remote attestation of Apple Secure Enclave provenance. No verified attestation artifact has been identified in this SSH provider path.

## Deletion/retirement safety

Do not implement `delete-all-ctk-identities` in the product.

A future single-identity deletion should require this order:

```text
remove remote authorization
→ verify the old key is rejected
→ verify a replacement/break-glass key succeeds
→ display the exact SSH fingerprint and CTK hash
→ explicit deletion approval
→ delete local CTK identity
→ verify absence
```

Never infer that an identity is safe to delete merely because its certificate appears expired. Verify the real SSH authorization state.

## Suggested first milestone

Deliver a non-destructive Swift package first:

1. `doctor` with human and JSON output;
2. a reusable, tested subprocess runner;
3. read-only CTK identity listing and normalized model;
4. fixture tests for `sc_auth` outputs, including labels with spaces and Unicode;
5. provider signature/path/version checks;
6. SSH configuration rendering without modifying user files;
7. a documented opt-in integration-test harness.

Then add one canary-only create/install/verify vertical slice. Do not add deletion in the same milestone.

## Required test classes

- zero, one, and multiple CTK identities;
- duplicate labels;
- labels with spaces, Unicode, and shell metacharacters;
- localized or changed `sc_auth` table output;
- unexpected extra columns and malformed rows;
- process timeout, signal termination, and partial output;
- concurrent create/install attempts;
- default wrapper filename collision and overwrite prompt;
- wrapper/CTK fingerprint mismatch;
- provider absent or no longer Apple-signed;
- system SSH versus Homebrew SSH mismatch;
- `bio` cancellation;
- `none` signing from remote session contexts;
- server user-presence policy mismatch;
- stale SSH-agent identity;
- interrupted atomic install.

Use protocol boundaries and fake process results for unit tests. Real CTK mutation tests must be separately gated, visibly labelled, and never run by the default test suite.

## Definition of done for the canary slice

A canary implementation is complete only when it can demonstrate with real output:

- exact OS/OpenSSH/provider capabilities;
- pre/post CTK identity diff;
- one newly created `p-256-ne` identity with the requested protection;
- collision-safe wrapper installation;
- canonical fingerprint agreement among CTK listing, wrapper, and public key;
- local provider-backed signing success;
- remote canary authentication success or a precisely identified policy failure;
- no Aqua prompt in the tested `none` remote path;
- documented residual trust and untested session states.

## Side-effect policy for coding agents

Until the user explicitly approves an integration run:

- do not create, import, export, or delete CTK identities;
- do not enumerate or print existing identity labels unnecessarily;
- do not modify `~/.ssh/config`, shell profiles, Keychain, or SSH agent state;
- do not connect to production infrastructure;
- do not sign, notarize, install, publish, commit, or push releases.

Unit tests and fixtures must not depend on existing user credentials.

## Source references

Primary and near-primary references:

- Local `man sc_auth` on the target macOS host.
- Online rendering of `sc_auth(8)`: <https://keith.github.io/xcode-man-pages/sc_auth.8.html>
- Online rendering of `ssh-keychain(8)`: <https://keith.github.io/xcode-man-pages/ssh-keychain.8.html>
- Apple CryptoTokenKit: <https://developer.apple.com/documentation/cryptotokenkit>
- Apple Secure Enclave key protection: <https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave>
- OpenSSH `SecurityKeyProvider`: <https://man.openbsd.org/ssh_config.5#SecurityKeyProvider>
- OpenSSH resident-key behavior: <https://man.openbsd.org/ssh-keygen.1#K>
- OpenSSH authorized-key security-key options: <https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT>
- Apple/OpenSSH CTK investigation: <https://lists.mindrot.org/pipermail/openssh-unix-dev/2024-July/041451.html>

Reference implementation, not production authority:

- `sekey.sh`: <https://github.com/cavoirom/sekey-sh>
- Native CTK SSH discovery notes: <https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf>

## Suggested skills / working mode

If the coding environment provides equivalent workflows, use:

- test-driven development for the subprocess, parser, and filesystem transaction boundaries;
- systematic debugging for real CTK/provider failures;
- code review before any canary mutation run;
- macOS Security/CryptoTokenKit documentation lookup rather than reverse-engineering private APIs;
- small vertical slices with explicit verification evidence.

## Immediate next action for the implementation agent

Create a Swift package and implement only the non-destructive first milestone. Before choosing a parser strategy, capture and redact representative `sc_auth list-ctk-identities -t ssh` output fixtures from controlled test identities or synthetic fixtures. Do not design parsing around whitespace splitting without tests for labels containing spaces.

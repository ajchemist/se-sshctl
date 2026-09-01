# Threat model

## Scope and assets

This document covers local Secure Enclave SSH identity management and
verification. The protected assets are CTK private-key operations, identity
locators and labels, SSH public keys/fingerprints, identity file references, and remote
SSH authorization.

Private CTK key material, identity file contents, Keychain records, passphrases,
tokens, and environment dumps must never appear in command output.

## Trust boundaries

1. `se-sshctl` invokes fixed absolute Apple system executables with argument
   arrays. Identity-file download additionally re-executes the current native
   `se-sshctl` executable as OpenSSH's askpass responder; it never builds a shell
   command.
2. `/usr/sbin/sc_auth` and `/usr/lib/ssh-keychain.dylib` are external system
   boundaries. `doctor` reports path, signature validity, identifier, and Apple
   anchor evidence without claiming hardware-backed operation.
3. `sc_auth` table output is untrusted input. The parser rejects changed headers,
   malformed rows, and extra columns rather than shifting fields.
4. GitHub-hosted macOS runners are build/test environments, not trusted evidence
   of physical Secure Enclave or remote-session behavior.

## `-t none` semantics

`p-256-ne + none` prevents private-key export but removes the per-use
LocalAuthentication gate. It does not provide a TTY password/PIN challenge.
Malware or an attacker executing in the user's context may request signatures.
Identities created with `-t none` should therefore be device- and purpose-specific, avoid
agent forwarding and broad root access, retain an independent break-glass path,
and support remote revocation.

An identity-file passphrase does not restore a strong gate for a `none` identity because
a process with provider access may rediscover the resident identity. No Secure
Enclave provenance attestation is claimed.

## Threats and current controls

| Threat | Current control | Residual risk |
| --- | --- | --- |
| Shell/argument injection through labels | No shell; fixed executables and argument arrays; fixture coverage | Bugs in Apple system tools remain external |
| Identity file passphrase disclosure | Echo-disabled controlling-terminal input; tagged replies over an anonymous stdin pipe to a native prompt-validating askpass responder; no secret in argv, environment values, persistent files, or command output | Same-user memory inspection and a compromised executable remain outside this boundary |
| Hung or unexpected askpass prompt | Each native responder consumes one bounded matching reply, reports unknown prompts through a non-secret failure marker, and fails at EOF; timeout kills descendants and escalates the direct child from SIGTERM to SIGKILL | Apple/OpenSSH prompt wording and process behavior still need physical-Mac regression coverage |
| Parser field confusion | Header-boundary parsing and strict validation | A legitimate future/localized format requires an explicit parser update |
| Malicious provider replacement | Signature validation plus `identifier` and `anchor apple` evidence | Hosted CI does not prove the local provider actually signs with Secure Enclave |
| Unauthorized unattended signing | Clear `-t none` semantics and mandatory explicit acknowledgement during creation | This is intrinsic to `none` protection |
| Wrong-key identity file installation | Separate SHA-256/SHA-1/SSH identifiers; isolated overwrite-position downloads plus fingerprint matching; ambiguous metadata is rejected | Large or mixed-token inventories need more physical-Mac coverage |
| Accidental identity deletion | Full CTK SHA-256 selection with the SHA-1 locator resolved internally; ambiguous metadata rejected; SSH fingerprint displayed before approval; exact confirmation required; post-delete absence checked in both hash formats; no bulk delete | The CLI cannot prove remote authorization was removed or that recovery access works, and an operator who runs `sc_auth delete-ctk-identity` directly gets none of these checks |

## Supported platform

macOS 26 and later, which is the range with physical evidence. `doctor` reports
`platform.verifiedRelease` and warns on older releases without blocking them,
because reports about Sequoia conflict and a refusal would be as unfounded as a
silent pass. Anything run below that line carries no evidence from this project.

## Operational constraint

Provider-backed signing requires a console session. Measured on macOS 26.6.2:
with the account logged in, signing and SSH authentication work from an SSH
session whether the screen is unlocked or locked; once logged out they fail with
`device not found`, even though `sc_auth` still enumerates the identity and
OpenSSH still gets the public key accepted by the server.

`sc_auth create-ctk-identity` is worse in that state: it exits 0 and creates
nothing.

An unattended Mac therefore has to stay logged in. That is a real exposure to
weigh against `-t none` itself: a logged-in console session plus `-t none` means
any process running as that user can request signatures with no approval.

## Unverified behaviors

The `p-256-ne + none` canary covers creation, multiple identity-file selection,
local signing, localhost authentication under the default server policy,
revocation, recovery, and signing inside an SSH session while the GUI session is
unlocked. The `-t bio` path and locked-console, logged-out,
reboot-before-first-unlock, and launchd contexts remain unverified.

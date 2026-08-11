# Threat model

## Scope and assets

This document covers the read-only CLI/core foundation and the model for a future
post-creation webhook. The protected assets are CTK private-key operations,
identity locators and labels, SSH public keys/fingerprints, wrapper references,
webhook credentials, and remote SSH authorization.

Private CTK key material, wrapper contents, Keychain records, passphrases,
tokens, and environment dumps are outside every event schema.

## Trust boundaries

1. `se-sshctl` invokes only fixed absolute Apple system executables with argument
   arrays; it never builds a shell command.
2. `/usr/sbin/sc_auth` and `/usr/lib/ssh-keychain.dylib` are external system
   boundaries. `doctor` reports path, signature validity, identifier, and Apple
   anchor evidence without claiming hardware-backed operation.
3. `sc_auth` table output is untrusted input. The parser rejects changed headers,
   malformed rows, and extra columns rather than shifting fields.
4. A future HTTPS endpoint is an external trust boundary. No network adapter is
   currently implemented or wired to the CLI.
5. GitHub-hosted macOS runners are build/test environments, not trusted evidence
   of physical Secure Enclave or remote-session behavior.

## Remote-profile semantics

`p-256-ne + none` prevents private-key export but removes the per-use
LocalAuthentication gate. It does not provide a TTY password/PIN challenge.
Malware or an attacker executing in the user's context may request signatures.
Remote-profile identities should therefore be device- and role-specific, avoid
agent forwarding and broad root access, retain an independent break-glass path,
and support remote revocation.

A wrapper passphrase does not restore a strong gate for a `none` identity because
a process with provider access may rediscover the resident identity. No Secure
Enclave provenance attestation is claimed.

## Creation and webhook boundary

Webhook delivery may occur only after a future creation workflow has verified all
of the following: exact pre/post identity diff, public-key extraction, CTK/wrapper/
public-key fingerprint agreement, collision-safe wrapper installation, and a real
local provider-backed signing operation.

The `ssh.key.created` v1 event contains only public material and creation metadata.
Its UUID is the idempotency key. A delivery failure after verified creation is a
`partial-success` with a non-secret pending outbox record; it must never trigger
automatic CTK identity deletion. Retry must reuse the same event ID.

Before live delivery, require HTTPS, bounded connect/request timeouts, a stable
user-agent/version, authenticated requests (for example HMAC), secrets sourced
outside repository files and command-line arguments, restrictive outbox
permissions, and documented retry/duplicate semantics. Error records must use
sanitized codes rather than endpoint responses that may contain secrets.

## Threats and current controls

| Threat | Current control | Residual risk |
| --- | --- | --- |
| Shell/argument injection through labels | No shell; fixed executables and argument arrays; fixture coverage | Bugs in Apple system tools remain external |
| Parser field confusion | Header-boundary parsing and strict validation | A legitimate future/localized format requires an explicit parser update |
| Malicious provider replacement | Signature validation plus `identifier` and `anchor apple` evidence | Hosted CI does not prove the local provider actually signs with Secure Enclave |
| Sensitive webhook disclosure | Closed event field set; deterministic JSON test | Future HTTP headers/logging/outbox storage need separate review |
| Webhook failure causing key loss | Explicit partial success and pending outbox; no rollback deletion | Persistence and retry are not implemented |
| Unauthorized unattended signing | Clear `none` semantics; no creation command in this slice | This is intrinsic to the future remote profile |

## Unverified behaviors

No current test creates or deletes an identity, downloads or installs a wrapper,
uses the provider to sign, opens a biometric prompt, authenticates to a server, or
tests locked/logged-out/reboot/launchd contexts. Default versus
`no-touch-required` OpenSSH server behavior is also unknown. These checks require
explicit approval and controlled physical hardware.

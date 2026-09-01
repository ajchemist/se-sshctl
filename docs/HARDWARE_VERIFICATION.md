# Hardware verification

## Add a MacBook Air Touch ID run

Run this repeatable wizard from the repository root on a physical MacBook Air
with Touch ID enrolled:

```sh
./scripts/verify-bio.sh
```

The wizard builds the current source, creates one temporary `p-256-ne + bio`
identity, installs an identity file, requires an observed Touch ID approval for
local signing, optionally verifies localhost SSH authentication, restores
`~/.ssh/authorized_keys` byte-for-byte, and deletes the test identity. Only
after cleanup does it offer to append a non-secret Markdown record below. Review
the resulting diff before committing it. It does not exercise locked, logged-out,
pre-first-unlock, or launchd contexts.

## Verified runs

Verified on a physical Apple silicon Mac on 2026-08-11:

```text
macOS:    26.6.1 (25G76)
OpenSSH:  10.3p1
provider: /usr/lib/ssh-keychain.dylib, Apple-anchored signature verified
params:   -k p-256-ne -t none
```

The canary run demonstrated:

- creation identified exactly one new CTK identity by pre/post SHA-256 diff;
- two simultaneous CTK identities were listed and independently selected;
- identity-file installation matched the CTK SSH fingerprint;
- local provider-backed signing and `ssh-keygen -Y verify` passed;
- localhost OpenSSH authentication passed under its default security-key policy,
  without `no-touch-required`;
- after removing the canary authorization, the same identity file was rejected;
- a separate CTK identity provided verified recovery authentication;
- signing from inside an SSH session passed while the GUI session was unlocked;
- single-identity deletion succeeded through the SHA-1 `pkhh`, and post-delete
  SHA-256 listing proved the canary absent;
- the original `authorized_keys` content was restored byte-for-byte.

Two Apple/OpenSSH behaviors required implementation changes:

1. `ssh-keygen -K` required a non-empty dummy PIN (`0`) even for a `none`
   identity, followed by an empty identity-file passphrase.
2. `KEYCHAIN_CERTIFICATES` did not filter the security-key resident download.
   Multiple CTK identities collided on `id_ecdsa_sk_rk`, so `se-sshctl` now
   downloads isolated overwrite positions and accepts only the identity file whose SSH
   fingerprint matches the requested identity.

This verifies one local and one SSH-session context with the GUI session unlocked.
It does not yet prove behavior while the console is locked, logged out, before the
first unlock after reboot, or under launchd.

## MacBook Air Touch ID verification — 2026-08-12

Verified on physical Touch ID hardware:

```text
model:     MacBook Air (MacBookAir10,1)
chip:      Apple M1
macOS:     26.6.1 (25G76)
OpenSSH:   OpenSSH_10.3p1, LibreSSL 3.3.6
provider:  /usr/lib/ssh-keychain.dylib, Apple-anchored signature verified
source:    v0.1.4-1-gcb5247f
params:    -k p-256-ne -t bio
```

The wizard recorded:

- identity creation: passed; Touch ID prompt observed: no;
- identity-file installation with an empty passphrase: passed; Touch ID prompt observed: no;
- local provider-backed signing and signature verification: passed; Touch ID prompt observed: yes;
- localhost authentication: passed; Touch ID prompt observed: yes;
- the temporary CTK identity was deleted and local authorization was restored.

This run covers an unlocked GUI session. It does not prove behavior while the console is locked, logged out, before first unlock after reboot, or under launchd.

## Certificate expiry measurement — 2026-09-01

```text
macOS:    26.6.2
OpenSSH:  OpenSSH_10.3p1, LibreSSL 3.3.6
source:   9eadfdbccffefe052fb0474ff362ff8b2d96fc22
notAfter: 20260831060234Z (in the past)
```

| Certificate | sc_auth Valid | local signing | localhost authentication |
| --- | --- | --- | --- |
| as issued by sc_auth | YES | passed | passed |
| backdated, re-imported | false | passed | passed |

import-ctk-certificate: passed

The certificate was replaced through create-ctk-csr and
import-ctk-certificate, so the non-exportable private key is unchanged
between the two rows.

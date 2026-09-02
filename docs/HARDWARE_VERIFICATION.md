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
source:   fb9b4e5fdaf03ee1dbadac5fe906f8576663998f
notAfter: 20260831062608Z (in the past)
```

| Certificate | sc_auth Valid | local signing | localhost authentication |
| --- | --- | --- | --- |
| as issued by sc_auth | YES | passed | passed |
| backdated, re-imported | false | passed | passed |

With the certificate expired:

- import-ctk-certificate: passed
- fresh identity-file download (ssh-keygen -K): passed
- signing with that freshly downloaded file: passed

The certificate was replaced through create-ctk-csr and
import-ctk-certificate, so the non-exportable private key is unchanged
between the two rows. That the identity file kept verifying after the swap is
itself evidence of this: the fingerprint preflight would have refused a
different key.

Run twice, once without the download step and once with it. Both runs produced
the same results for the rows they shared.

**Conclusion: an expired X.509 certificate does not affect this path.** `sc_auth`
sees the expiry and reports `certificateValid=false`, yet provider-backed
signing, localhost authentication, and a fresh `ssh-keygen -K` identity-file
download all still succeed. The replacement certificate was also signed by an
unrelated throwaway CA, so OpenSSH is not merely tolerating an expired
certificate; it does not consult the certificate at all here.

This confirms the handoff's warning not to infer that an identity is safe to
delete because its certificate appears expired. Certificate validity is not a
signal about SSH usability, and `se-sshctl` should not present it as one.

Not covered: whether macOS itself expires or renews these certificates over
time, and whether any other Apple subsystem that consumes CTK identities cares.
This measured OpenSSH.

## -t none remote-session verification — 2026-09-01

Measured from an SSH session on physical hardware:

```text
host:       mac-studio-m1u
model:      Mac Studio (Mac13,2)
chip:       Apple M1 Ultra
macOS:      26.6.2
OpenSSH:    OpenSSH_10.3p1, LibreSSL 3.3.6
source:     33cef63a2cc7dbef6683f2126975e0060fac08c7
params:     -k p-256-ne -t none --allow-unattended-signing
```

| Console state | local signing | localhost authentication |
| --- | --- | --- |
| unlocked | passed | passed |
| locked | passed | passed |
| logged-out | not-run | not-run |
| pre-first-unlock | not-run | not-run |

Each row is one SSH session into this Mac. "local signing" is
ssh-keygen -Y sign through the Apple provider; "localhost
authentication" is a real public-key SSH authentication using only
the Secure Enclave identity file, with the agent, user config, and
every password method disabled.

A `not-run` row was never attempted and says nothing about that context.

## Identity creation while logged out — 2026-09-01

```text
host:   macbookair-m1
model:  MacBook Air (MacBookAir10,1), Apple M1
macOS:  26.6.2
```

Observed by accident, while trying to start the `-t none` sequence in the
logged-out context on a machine that had no test identity yet.

`sc_auth create-ctk-identity -l LABEL -k p-256-ne -t none` **exited 0 and created
nothing.** `se-sshctl identity create` caught it, because it compares the
inventory before and after rather than trusting the exit status, and reported
"creation returned success but discovered 0 new identities; no rollback was
performed".

Confirmed afterwards from a logged-in session: no identity with that label
existed. So this was a silent creation failure, not an inventory that could not
be read — had the identity been created and merely been invisible at the time,
it would have shown up later. It did not.

Independently confirmed later in the same logged-out state: `sc_auth
list-ctk-identities` enumerates normally there. Enumeration was never the
problem, so the before/after comparison that caught this was reading a true
inventory.

Consequence for this tool: creating a CTK identity requires a console session.
`scripts/verify-none-remote.sh` now refuses to create outside its baseline
context, so a setup failure in a degraded context cannot be mistaken for a
measurement of whether an existing key can still sign.

Not established: whether `sc_auth list-ctk-identities` can enumerate while
logged out, and whether an already-created identity can sign there. Those are
what the `logged-out` row of the `-t none` table measures, and it is still
unmeasured.

## -t none remote-session verification — 2026-09-01

Measured from an SSH session on physical hardware:

```text
host:       macbookair-m1
model:      MacBook Air (MacBookAir10,1)
chip:       Apple M1
macOS:      26.6.2
OpenSSH:    OpenSSH_10.3p1, LibreSSL 3.3.6
params:     -k p-256-ne -t none --allow-unattended-signing
```

| Console state | local signing | localhost authentication |
| --- | --- | --- |
| unlocked | passed | passed |
| locked | passed | passed |
| logged-out | **failed** | **failed** |
| pre-first-unlock | not-run | not-run |

Each row is one SSH session into this Mac. "local signing" is `ssh-keygen -Y
sign` through the Apple provider; "localhost authentication" is a real
public-key SSH authentication using only the Secure Enclave identity file, with
the agent, user config, and every password method disabled.

The rows were measured across source revisions `b067142`…`d35f90d`, minutes
apart. The wizard now records the revision per row; this table predates that, so
it is stated here instead of implied.

### Why logged-out failed

Not a missing identity and not a refused approval. `sc_auth` still enumerated
the identity, OpenSSH still loaded the key and had the server accept it, and the
provider still opened. The signature itself could not be produced:

```text
debug1: Server accepts key: ... ECDSA-SK SHA256:4sByC0sk... explicit authenticator
debug1: sshsk_open: provider /usr/lib/ssh-keychain.dylib implements version 0x000a0000
debug1: sshsk_sign: sk_sign failed with code -4
debug1: ssh-sk-helper: Signing failed: device not found
sign_and_send_pubkey: signing failed for ECDSA-SK "...": device not found
```

`verify local` failed the same way: `Couldn't sign message: device not found`.

**The Secure Enclave token requires a console session.** Locking the screen keeps
it; logging out removes it.

### Why pre-first-unlock is not-run

FileVault is enabled on this Mac. Reaching that context requires SSH to be
answering after a reboot with nobody having authenticated, and with FileVault the
pre-boot authentication that starts the system is itself a login. It was not
attempted, so nothing is claimed about it.

Its outcome is strongly implied by the logged-out row — a state with no session
at all cannot do what a logged-out one already cannot — but an implication is not
a measurement, so the row stays `not-run`.

### What this establishes

The workflow `-t none` exists for — a remote Mac initiating outbound SSH with
nobody at its console — works, on the condition that the account stays logged in.
The screen may be locked. This is the tool's central operational constraint and
is recorded in README.md and docs/THREAT_MODEL.md.

## Identity-file download refused on one Mac — 2026-09-02

Observed, not yet explained:

```text
host:       mac-studio-m4m (Mac16,9, Apple M4 Max), macOS 26.6.1 (25G76)
control:    mac-studio-m1u (Mac13,2, Apple M1 Ultra), macOS 26.6.2
OpenSSH:    OpenSSH_10.3p1 on both
params:     -k p-256-ne -t none --allow-unattended-signing
```

On the M4 Max, `ssh-keygen -K -w /usr/lib/ssh-keychain.dylib` fails for every
`none` identity — ones created from a home-manager activation and one created
from an interactive shell alike — with `Provider "/usr/lib/ssh-keychain.dylib"
returned failure -1` / `Unable to load resident keys: invalid format`, right
after the PIN prompt. The unified log shows the provider's own lookup missing:

```text
ssh-sk-helper [com.apple.CryptoTokenKit:sshkeychain] SecItemCopyMatching failed with: -25300
```

(-25300 is errSecItemNotFound.) `sc_auth list-ctk-identities` lists the
identities normally, and the console session is logged in. The same download,
same askpass script, same parameters succeeds on the M1 Ultra over SSH. macOS
26.6.2 was pending on the M4 Max at the time; whether the release or the
hardware is the difference is not yet measured.

`install` used to report this as "native askpass rejected an unexpected
OpenSSH prompt", because the provider failure cuts the prompt sequence short.
It now reports OpenSSH's own message.

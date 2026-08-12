# Hardware verification

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

# Plumbing preserves native security-tool vocabulary

`se-sshctl` separates low-level plumbing from policy-bearing porcelain. When a plumbing input represents a `sc_auth`, `ssh-keygen`, or SSH parameter, it keeps the native option name and value vocabulary instead of translating it into deployment-specific profiles; porcelain may compose those primitives for user-defined workflows without changing plumbing semantics.

## Consequences

- Plumbing may validate the SSH-only scope, fix trusted executable/provider paths, require destructive or unattended-signing acknowledgement, and verify postconditions. These are safety invariants, not deployment policy.
- Plumbing does not have to expose every native flag. A deep command may hide several native calls, but any native concept it does expose keeps the native spelling and semantics.
- Native identifiers remain distinct: `sc_auth delete-ctk-identity -h` consumes a SHA-1 CTK public-key hash, operational selection uses a SHA-256 CTK public-key hash, and wrapper matching uses an SSH fingerprint.
- Remote revocation and recovery checks belong to porcelain retirement, not the native delete primitive. External delivery, webhooks, and remote authorization mutation remain outside this CLI.

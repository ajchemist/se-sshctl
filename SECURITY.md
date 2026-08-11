# Security policy

Please report vulnerabilities privately through GitHub's security advisory
feature for this repository. Do not include real private keys, wrapper files,
Keychain exports, webhook secrets, identity inventories, or production host data
in a report.

The current executable is read-only. It does not modify `~/.ssh`, Keychain/CTK
identities, SSH agent state, shell profiles, or remote authorization. A report
from `identity list` still contains identity metadata and should be redacted
before sharing.

Security-sensitive future changes require tests at the system boundary and an
explicit physical-Mac integration run. In particular, identity creation,
wrapper installation, signing, webhook networking/authentication, outbox
persistence, retry, and deletion must not be inferred as covered by hosted CI.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the current trust boundaries
and residual risks.

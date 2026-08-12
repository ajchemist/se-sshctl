# Security policy

Please report vulnerabilities privately through GitHub's security advisory
feature for this repository. Do not include real private keys, identity files,
Keychain exports, identity inventories, or production host data
in a report.

The executable can create or delete one CTK identity and install an identity file only
when those commands and their explicit confirmation are supplied. It does not
import/export identities, bulk-delete identities, edit `~/.ssh/config`, change
SSH agent or shell-profile state, or modify remote authorization. Output from
`identity list` still contains identity metadata and should be redacted before
sharing.

Identity-file passphrases are read twice from the controlling terminal with echo
disabled. They are passed to OpenSSH through an anonymous pipe and a native
prompt-validating askpass responder; they are not accepted in command arguments
or environment variables and are not written to persistent files.

Identity creation, identity-file installation, signing, remote authentication, and
deletion require an explicit physical-Mac integration run and must not be
inferred as covered by hosted CI or mock-based unit tests.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the current trust boundaries
and residual risks.

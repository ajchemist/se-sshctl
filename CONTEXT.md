# Secure Enclave SSH Identity Management

This context manages Apple CryptoTokenKit identities that OpenSSH can use through Apple's security-key provider without exporting private-key material.

## Language

**CTK identity**:
An Apple CryptoTokenKit certificate and private-key identity. In this project, SSH-capable identities use the non-exportable `p-256-ne` key type.
_Avoid_: SSH key, key file

**Protection**:
The native `sc_auth -t` value controlling per-use private-key authorization: `bio` or `none`.
_Avoid_: Interactive profile, remote profile

**CTK public-key hash**:
The value printed in the `Public Key Hash` column by `sc_auth list-ctk-identities`; its meaning depends on the native `-t` hash type and `-e` encoding.
_Avoid_: Identity ID, fingerprint

**SSH fingerprint**:
The `SHA256:` fingerprint used to match a CTK identity, an identity file, and remote authorization.
_Avoid_: CTK hash

**Identity file**:
An OpenSSH private key file containing a key handle and public metadata for provider-backed operations, but no exported Secure Enclave private-key material.
_Avoid_: Wrapper, private key

**Identity deletion**:
Permanent removal of one CTK identity through Apple's `sc_auth delete-ctk-identity`. This tool does not perform it; remote authorization and recovery readiness remain external operator responsibilities.
_Avoid_: Retirement, remote revocation

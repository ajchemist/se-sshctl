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
The `SHA256:` fingerprint used to match a CTK identity, a resident-key wrapper, and remote authorization.
_Avoid_: CTK hash

**Resident-key wrapper**:
The OpenSSH private-key handle downloaded by `ssh-keygen -K`; it references provider-backed key operations but contains no exported Secure Enclave private key.
_Avoid_: Private key

**Retirement**:
The porcelain workflow that verifies remote authorization removal and recovery access before permanently deleting one CTK identity.
_Avoid_: Delete

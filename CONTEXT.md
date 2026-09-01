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

**Certificate validity**:
The `Valid` and `Valid To` columns of `sc_auth list-ctk-identities`, describing the identity's X.509 certificate. Measured on 2026-09-01 to have no effect on provider-backed signing, SSH authentication, or identity-file download; it is metadata, not a usability signal.
_Avoid_: Key expiry, key lifetime

**Identity deletion**:
Permanent removal of one CTK identity selected by its CTK SHA-256 public-key hash, together with the identity files and verification records that depended on it. The underlying operation is `sc_auth delete-ctk-identity -h SHA1`. Remote authorization and recovery readiness remain external operator responsibilities.
_Avoid_: Retirement, remote revocation

# ADR 0009: OpenSSH migration compatibility

Status: accepted with a temporary upstream advisory exception

`nix-seal` must migrate the existing repository's OpenSSH Ed25519 and RSA age
ciphertext without a separate scripting runtime. The pinned `age` crate's `ssh`
feature is therefore enabled only in `nix-seal-crypto`.

Native X25519 age recipients and reviewed age plugins remain the default and the
only supported choices for new plans. OpenSSH comments are normalized away
before authorization comparison or fingerprinting. The non-interactive CLI
accepts only unencrypted OpenSSH identities; it rejects encrypted identities
instead of presenting a prompt or attempting agent integration.

The `ssh` feature brings in RustCrypto `rsa` for legacy OpenSSH RSA support.
That crate is subject to unfixed `RUSTSEC-2023-0071` (Marvin timing attack).
`cargo-deny` records a narrowly scoped exception because no safe upgrade is
available and dropping the feature would break the required migration path. The
compensating controls are:

- The tool has no network listener, daemon, or remote decryption API.
- RSA is never generated or recommended for new configurations.
- No encrypted SSH key is prompted for or passed to a background process.
- SSH support is assessed on every `age` or `rsa` update and must be removed or
  redesigned before any network-facing secret provider is introduced.

This exception is not a finding closure. It is a documented release blocker for
any future deployment that could expose RSA decryption timing to an attacker.

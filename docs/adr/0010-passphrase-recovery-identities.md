# ADR 0010: Passphrase-protected recovery identities

Status: accepted; implemented for human authoring

Recovery identities may be stored as standard age scrypt-encrypted identity
files. This uses age's existing passphrase format rather than a nix-seal
container or password-encryption primitive. `key generate --passphrase` obtains
the passphrase only from a hidden controlling terminal, confirms new values,
and enforces a minimum length. Identity-consuming commands decrypt the file
only after an explicit terminal prompt; no passphrase is accepted through
argv, stdin, or ordinary environment variables.

Passphrase-protected files are intentionally unsuitable for unattended
activation because activation has no interactive prompt. Targets should use
native age plugin, agent, or hardware-backed identities instead. A passphrase
is a human recovery control, not a replacement for multiple independent
recovery paths or artifact approval signatures.

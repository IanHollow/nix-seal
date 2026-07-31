# ADR 0001: Standard age ciphertext

Status: accepted

Use standard age files and recipient/plugin protocols. Isolate exactly pinned
Rust `age` behind `nix-seal-crypto`; never invent a container or primitive.
Upgrades require advisory/license review, official vector tests, and
differential compatibility with reference `age` and `rage`. PGP is
migration-only.

Native X25519 recipients are the default. OpenSSH Ed25519 and RSA recipients
are accepted only to migrate established deployments. Their parser is contained
inside the adapter, OpenSSH comments are excluded from policy comparison, and
encrypted private keys are rejected by non-interactive commands. New
configuration must prefer native age or reviewed hardware-backed age plugins.

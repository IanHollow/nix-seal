# ADR 0001: Standard age ciphertext

Status: accepted

Use standard age files and recipient/plugin protocols. Isolate exactly pinned
Rust `age` behind `nix-seal-crypto`; never invent a container or primitive.
Upgrades require advisory/license review, official vector tests, and
differential compatibility with reference `age` and `rage`. PGP is
migration-only.

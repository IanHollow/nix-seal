# ADR 0006: Non-destructive migrations

Status: accepted; implementation pending

Migration is dry-run-first, preserves the source manager, streams plaintext into
native age encryption, verifies every result by round trip, and supports
side-by-side runtime directories. Adapters cover secretctl, agenix/ragenix,
agenix-rekey, SOPS/sops-nix, and Clan Vars/Facts. Removal is a separate explicit
operation after build, activation, rollback, rotation, and recovery verification.

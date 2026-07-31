# ADR 0006: Non-destructive migrations

Status: accepted; initial dry-run inventory and verified ciphertext streaming
implemented

Migration is dry-run-first, preserves the source manager, streams plaintext into
native age encryption, verifies every result by round trip, and supports
side-by-side runtime directories. The initial implementation inventories
`secretctl` public indexes and agenix/ragenix age trees, then provides an
explicit `migrate ciphertext --execute` path that streams a reviewed source
ciphertext through replacement recipients without materializing plaintext. The
`secretctl` adapter validates group membership, target recipient expansion, and
every secret's direct recipient set against its declared consumers before it
emits a mapping report.

Adapters for agenix-rekey metadata, SOPS/sops-nix, and Clan Vars/Facts remain
planned. Their format-specific policy mapping must be reviewed before any
mutation path is added. Removal of a source manager is a separate explicit
operation after build, activation, rollback, rotation, and recovery
verification.

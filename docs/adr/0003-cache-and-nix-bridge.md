# ADR 0003: Ciphertext cache and Nix bridge

Status: accepted; partial implementation

Target artifacts live in a content-addressed XDG cache and fixed-output Nix
derivations, never Git by default. Rekey is an explicit impure preparation step;
Nix builds fail safely when an expected object is absent. Transactions use
private same-filesystem temporary files, locks, fsync, content verification, and
atomic rename. Cache export/import carries ciphertext and public signed
metadata.

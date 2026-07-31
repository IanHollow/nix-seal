# ADR 0003: Ciphertext cache and Nix bridge

Status: accepted; rekey/cache transaction foundation implemented

Target artifacts live in a content-addressed XDG cache and fixed-output Nix
derivations, never Git by default. Rekey is an explicit impure preparation step;
Nix builds fail safely when an expected object is absent. Transactions use
private same-filesystem temporary files, locks, fsync, content verification, and
atomic rename. Cache export/import carries ciphertext and public signed
metadata.

The v1 implementation streams administrator plaintext directly from the age
decryptor into target age encryption. It copies canonical ciphertext into a
private transaction file so its signed source hash and decrypted bytes cannot
diverge during a concurrent source change. Target ciphertext and its signed
manifest are committed as one directory under a domain-separated address of the
plan hash, source ciphertext hash, recipient fingerprint, and cache format.
Existing entries are reused only after recalculating the ciphertext hash and
verifying every signed binding. No plaintext transaction file is created.

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
manifest are committed as one directory. Cache address v2 is domain-separated
over the cache format, plan and target-policy hashes, source ciphertext hash,
recipient fingerprint, target and secret IDs, and artifact generation. Including
all target-bound envelope identity fields prevents otherwise-valid targets that
share a recipient or source from colliding on one incompatible signed envelope.
Existing entries are reused only after recalculating the ciphertext hash and
verifying every signed binding. No plaintext transaction file is created.

Cache reads are fail-closed. The cache root and every artifact bundle must have
private permissions; generic objects, target ciphertext, and envelopes are
opened with no-follow semantics and must be single-link regular files. Inventory
validates each content hash, artifact bundle name, exact bundle member set, byte
bound, and private metadata before reporting aggregate counts. This deliberately
makes `cache status` fail on unexpected cache mutations instead of presenting a
misleading count. Cache lifecycle operations build on this verified inventory.

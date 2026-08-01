# ADR 0003: Ciphertext cache and Nix bridge

Status: accepted; rekey/cache transaction and Nix import bridge implemented

Target artifacts live in a content-addressed XDG cache and ciphertext-only Nix
store imports, never Git by default. Rekey is an explicit impure preparation
step; Nix evaluation fails safely when an expected object is absent.
Transactions use private same-filesystem temporary files, locks, fsync, content
verification, and atomic rename. Cache export/import carries ciphertext and
public signed metadata.

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

`cache gc` is dry-run-first. It retains a target artifact only after compiling
the current plan, deriving the target projection, hashing the current canonical
ciphertext through a no-follow descriptor, reconstructing the cache address, and
verifying the signed envelope against the target secret's current approval keys
and threshold. Expired, stale, malformed, source-mismatched, target-mismatched,
and untrusted artifacts are candidates; they are removed only with `--execute`.
Generic v1 objects have no authenticated reachability edge, so GC deliberately
treats all of them as candidates rather than guessing from filenames or public
metadata. The current GC compatibility rule accepts a signed producer version
because v1 has no producer-version allow-list; future policy must add an
explicit allow-list before it can tighten this decision.

The v1 cache exchange format is a directory containing only the verified
`objects/` and `artifacts/` layouts. Export stages a new private directory and
publishes it with one rename, refusing to replace an existing destination. It
does not copy identities, plaintext, locks, or transactions. Import is
append-only and idempotent for byte-identical entries; a matching address with
different ciphertext or envelope fails closed. Artifact authorization remains a
policy/activation operation, so importing an artifact never by itself grants it
runtime use.

The public Nix library's `artifactBundle` helper consumes one exported target
artifact directory and requires the exact two-member set
`ciphertext.age`/`manifest.dsse.json`. It copies ciphertext and signed public
metadata through `builtins.path`, derives module paths from the bundle, and
rejects malformed layouts before store import. The helper emits the complete
operator-supplied `nix-seal rekey` command when the bundle is missing. It never
reads an identity, invokes a process, or performs rekeying in a derivation;
artifact signatures and target bindings remain verified by the Rust activation
runtime.

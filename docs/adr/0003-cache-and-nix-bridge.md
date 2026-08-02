# ADR 0003: Ciphertext cache and Nix bridge

Status: accepted; rekey/cache transaction, interruption recovery, target-local
cache bridge, and optional Nix-store bridge implemented

Target artifacts live in a content-addressed cache, never Git by default. System
artifacts belong in a system-owned cache such as `/var/lib/nix-seal/cache/v1`;
Home Manager artifacts belong in the owning user's cache. Rekey is an explicit
impure preparation step. The normal Nix module interface carries only the
absolute local cache path, so it neither imports artifacts into the store nor
makes a cache export a flake input. Transactions use private same-filesystem
temporary files, locks, fsync, content verification, and atomic rename.
Temporary entries use an explicit private transaction prefix. Cache open takes
the cache lock before removing only owner-validated abandoned transaction files,
so an interrupted writer cannot poison inventory while unexpected names and
links still fail closed. Cache open/write concurrency is lock-serialized and
covered by an inventory consistency test. Cache export/import carries ciphertext
and public signed metadata.

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

Cache reads are fail-closed. The cache root and every artifact bundle must be
owned by the invoking user and have private permissions; generic objects, target
ciphertext, and envelopes are opened with no-follow semantics and must be
single-link regular files. Cache locks and transaction files use close-on-exec
descriptor creation, so a substituted lock or symlink cannot redirect a write.
Cache paths are canonicalized through existing directory ancestry before
creation, rejecting a symlink at the configured root while resolving normal
platform aliases such as macOS `/var`; export destinations apply the same rule
to their parent and publish with an atomic no-replace rename. Artifact bundle
publication uses the same primitive, so a destination substituted after the
initial existence check cannot be overwritten. A regression test swaps the
destination parent for a symlink after both directory descriptors are open and
verifies that the descriptor-relative rename still writes only to the original
directory. This prevents a symlinked spelling from silently redirecting cache
state while preserving portable cache locations. Inventory validates each
content hash, artifact bundle name, exact bundle member set, byte bound, and
private metadata before reporting aggregate counts. This deliberately makes
`cache status` fail on unexpected cache mutations instead of presenting a
misleading count. Every bounded cache read also applies the limit to the stream
itself rather than trusting a prior metadata length, so a concurrent file growth
race cannot turn a malformed entry into an unbounded allocation. Cache lifecycle
operations build on this verified inventory.

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
publishes it with one atomic no-replace rename, refusing to replace an existing
destination. It does not copy identities, plaintext, locks, or transactions.
Import is append-only and idempotent for byte-identical entries; a matching
address with different ciphertext or envelope fails closed. Artifact
authorization remains a policy/activation operation, so importing an artifact
never by itself grants it runtime use.

The module's `artifactDirectory` option is the normal bridge. It derives the two
fixed paths from an absolute out-of-store bundle directory, refuses a Nix store
path or traversal spelling, and leaves all existence, no-follow, and signature
checks to Rust activation. `artifactBundle` remains a compatibility helper for
deployments that deliberately need a fixed ciphertext-only store closure. It
consumes one exported target artifact directory with the exact two-member set
`ciphertext.age`/`manifest.dsse.json`, copies public ciphertext and metadata
through `builtins.path`, and derives module paths from it. Neither bridge reads
an identity, invokes a process, or rekeys in a derivation; artifact signatures
and target bindings remain verified by the Rust activation runtime.

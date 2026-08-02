# ADR 0006: Non-destructive migrations

Status: accepted; dry-run inventory, verified single-file streaming, and
side-by-side age-tree and agenix-rekey migration implemented

Migration is dry-run-first, preserves the source manager, streams plaintext into
native age encryption, verifies every result by round trip, and supports
side-by-side runtime directories. The initial implementation inventories
`secretctl` public indexes and agenix/ragenix age trees, then provides explicit
single-file and bulk age-tree paths that stream reviewed source ciphertexts
through replacement recipients without materializing plaintext. The bulk path
requires an explicit repository-relative destination, identity, and recipient
set; it reports the complete mapping before execution and opens the identity
only for `--execute`. Every source is staged and round-trip verified before any
destination is changed, then destinations are committed with private backups and
rollback on failure. Legacy files remain untouched for side-by-side activation
and rollback verification. The `secretctl` adapter validates group membership,
target recipient expansion, and every secret's direct recipient set against its
declared consumers before it emits a mapping report. With explicit target-system,
approval-signer, and administrator-recipient mappings it writes a separate valid
administrator-backed rekeyed candidate plan by default; the legacy direct-
delivery model is available only through an explicit `--delivery direct` opt-in.
It never mutates the legacy configuration or ciphertext. With an
explicit repository-relative destination, private identity, and replacement
recipient set, `--execute` additionally performs a side-by-side bulk rekey of
the validated `secrets/*.age` sources. It streams and round-trip verifies every
file in one transaction and leaves the legacy tree untouched.

Age-ciphertext migrations distinguish the legacy source identity from the
destination verification identity. `--identity` decrypts the source; the
optional `--verification-identity` (defaulting to it) must match a replacement
recipient and authenticates every staged destination before commit. This keeps
key replacement usable when an old SSH/age identity is intentionally retired,
without weakening the recipient-binding check. Both identities are opened only
for an explicit `--execute`; dry runs never read private key files.

SOPS JSON inspection is similarly non-destructive: it validates bounded
cleartext metadata (including provider and age-recipient declarations) without
decrypting values or invoking SOPS. Structured extraction and mutation remain
separate, explicit operations. The explicit single-document SOPS migration path
uses an absolute non-symlink SOPS binary with an empty environment and an
optional private `SOPS_AGE_KEY_FILE` path. It streams a bounded plaintext stdout
directly into staged native-age encryption and performs its successful-exit
check before the atomic ciphertext commit. A watchdog terminates a stalled
process; SOPS stderr is intentionally discarded so it cannot leak plaintext. The
opt-in single-document PGP bridge is likewise migration-only: it requires an
explicit absolute non-symlink `gpg` executable and an existing owner-only
`GNUPGHOME`, clears the inherited environment, and accepts no passphrase or
secret material in arguments. It runs `gpg` with option-file loading and
automatic key location, import, and retrieval disabled, discards diagnostics,
and streams bounded stdout directly into the same verified native-age
transaction. This does not make PGP a native encryption backend. Cloud/KMS
migrations are not silently enabled through inherited environments and require
their own reviewed capability design.

Clan Vars inspection recognizes the documented per-machine output layout and
never reads values. Because the filesystem leaves do not authoritatively encode
the storage backend, secrecy classification, target selection, or runtime
policy, importing a value requires an explicit reviewed mapping. With an
explicit repository-relative destination, private verification identity, and
replacement recipients, `--execute` streams every value into a staged age
ciphertext batch, verifies each result, and commits side-by-side while leaving
the legacy tree untouched.

Clan Facts inspection recognizes only public `machines/<machine>/facts/<fact>`
leaves. A repository-relative destination plus `--execute` enables a bounded,
no-follow, side-by-side public copy transaction; the source tree remains
available for rollback. Secret facts are backend-defined and require an explicit
reviewed export rather than path inference.

The agenix-rekey adapter consumes an explicit public evaluated export instead of
guessing policy from filenames. It checks the master-to-target boundary,
canonical source paths, target platform, storage mode, recipients, and
repository-only intermediaries. Supplying a separate repository-relative
destination, an absolute private identity, and explicit replacement recipients
enables a side-by-side bulk rekey. As with agenix/ragenix trees, the command
reports its complete mapping first, opens the identity only for `--execute`,
round-trip verifies every staged source, and preserves the legacy tree for
rollback. Clan Facts public leaves are inventoried without reading values;
configurable secret fact stores still require explicit policy mapping. Removal
of a source manager is a separate explicit operation after build, activation,
rollback, rotation, and recovery verification.

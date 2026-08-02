# Roadmap

- Phase 0: repository foundation, specification, governance, Rust workspace,
  flake/modules, schema, CI, and release scaffolding. No secret migration.
- Phase 1: complete Nix/TOML frontends and selectors; age/plugin adapter;
  Ed25519/SSH DSSE approvals, including explicit bounded local SSH-agent Ed25519
  signing; signed manifests; official/differential vectors; deterministic
  property suites for IDs, canonical plans, merge semantics, and selector
  monotonicity; and fuzz foundations.
- Phase 2: administrator-to-target rekey, deterministic Nix bridge,
  transactional cache, verified activation/switch/rollback, systemd credentials,
  and full platform modules. Deterministic cache state-machine coverage now
  exercises repeated object/artifact writes, inventory/retention checks, and
  export/import equivalence; interrupted-operation and activation state-machine
  coverage now exercises idempotent activation, generation repair, failed
  authentication, collision refusal, post-switch failure, and retry; interrupted
  cache-operation recovery is now lock-protected and link-safe; concurrent cache
  open/write coverage now verifies serialized recovery and inventory
  consistency; cache roots and export parents are canonicalized before writes;
  artifact and export publication now use atomic no-replace renames with
  regression coverage; a descriptor-relative parent-substitution race regression
  verifies that an attacker cannot redirect publication through a swapped
  symlink. Pending post-switch action markers now fail closed when a later
  activation supplies a different or missing policy, preserving durable retry
  semantics. The Linux NixOS VM now exercises a real systemd credential consumer
  and post-switch restart after activation; service actions now reject untrusted
  manager paths. Every authoring and migration transaction now serializes on a
  descriptor-safe, owner-only repository lock in addition to the cache lock.
  Runtime secrets now support optional compatibility symlinks bound to the
  stable `current/<secret>` path. Existing parents and links are validated by
  no-follow descriptors, publication is atomic no-replace, mismatches fail
  closed, and rollback follows the same `current` switch. Generic cache
  insertion now enforces the same bounded ciphertext limit as artifact and
  export paths before hashing or publication, preventing an untrusted caller
  from using the cache as an unbounded local sink. Activation source paths are
  normalized before validation; parent ancestry rejects user-owned symlinks and
  is reopened descriptor-relatively with no-follow operations, with regression
  coverage for ancestry substitution and dot-segment traversal. Runtime-root
  creation now validates existing ancestors before directory creation, so a
  user-owned symlink cannot redirect the root through `create_dir_all`.
  Compatibility-link parents now reject user-owned symlink ancestry before
  platform-alias canonicalization, preventing legacy paths from redirecting
  publication into an attacker-selected directory.
- Phase 3: authoring and lifecycle commands, identity/value rotation,
  generators, prompts, templates, and provisioning phases. Private identity,
  prompt-state, generator dependency, and generator-output permissions now use
  descriptor-relative hardening with regression coverage against pathname
  substitution races. Canonical authoring staging, editor values, public-output
  staging, and deletion tombstone metadata now apply permissions through
  already-open descriptors; compatibility path helpers verify no-follow type,
  ownership, and link count before changing modes. NixOS exposes an explicit
  installer-mode opt-in for partitioning activation specs while keeping that
  phase out of the normal activation graph. Generator ciphertext, public
  outputs, persistent prompts, and validation state now share one bounded,
  owner-only transaction, so metadata failures cannot leave a generation's
  outputs and regeneration state out of sync. Logical collection batch authoring
  now accepts bounded JSON, TOML, YAML, and dotenv inputs through a strict
  public mapping, supports explicit binary encodings and private editor staging,
  and commits each mapped secret through one all-or-recover ciphertext
  transaction. The built-in SSH Ed25519 generator can now commit its encrypted
  private key and one separately declared derived public OpenSSH key as one
  validated transaction. The WireGuard generator can likewise commit its
  encrypted private scalar and one derived public key as one validated
  transaction. Generated private identities are created through no-follow,
  descriptor-relative opens with exclusive creation and owner/link checks;
  user-owned symlinked parents fail closed while root-owned platform aliases are
  canonicalized safely.
- Phase 4: dry-run migration adapters and side-by-side dogfooding in nix-conf,
  starting with a synthetic low-risk secret. Public migration compatibility
  goldens now cover agenix/ragenix, agenix-rekey, SOPS metadata, Clan
  Vars/Facts, and the current secretctl index. The parent nix-conf flake now
  runs a disposable end-to-end dogfood check covering generated identities,
  canonical authoring, deep validation, signed provisioning, cache
  export/import, activation, and template rendering without copying plaintext
  into its output. Negative migration fixtures now cover path traversal,
  malformed age recipients, inconsistent recipient sets, and symlinked legacy
  trees. The dogfood migration also exercises a legacy OpenSSH source identity
  re-encrypted to a distinct native-age administrator identity, proving the
  explicit source/verification-key split. Secretctl candidate plans now default
  to administrator-backed rekeyed delivery, require an explicit post-migration
  canonical source prefix, and require an explicit opt-in for legacy direct
  delivery. Deep candidate-plan validation now runs against the side-by-side
  re-encrypted sources rather than legacy target-addressed ciphertext. Migration
  of actual nix-conf secrets remains required.
- Phase 5: attack-path review, sustained fuzz/mutation/platform/performance work
  (the reproducible scale benchmark protocol and scheduled Miri, sanitizer, and
  mutation jobs are now published), release build/SBOM/attestation scaffolding,
  operational runbooks, release candidate, independent audit and remediation,
  then 1.0.

## Verified supply-chain follow-ups

- `spin 0.9.8` is a yanked transitive dependency of the pinned `age` stack.
  Update it only with a reviewed Cargo Vet record and compatibility checks; do
  not add a blanket exemption merely to silence the yanked-package check.
- `rsa` is required by `age` only for the documented OpenSSH RSA migration
  compatibility path. Its unfixed timing advisory remains constrained by ADR
  0009 and must be reassessed on every `age`/`rsa` update.

Post-1.0 candidates include remote provider SDK/daemon, Vault and cloud/password
manager providers, dynamic leases, SPIFFE, reviewed threshold decryption,
attested TPM-bound delivery, and organization-wide tamper-evident audit.

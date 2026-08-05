# nix-seal product specification

Status: accepted design, implementation in progress. Version: plan v1 / artifact
v2 / activation v2. The normative requirements below use “must”; incomplete
items are tracked in the roadmap and must not be represented as implemented.

## Mission and boundaries

`nix-seal` is an offline-first, Git-friendly secret manager for NixOS,
nix-darwin, and standalone or integrated Home Manager on Linux and macOS. All
shipped executables, helpers, generators, and migration orchestration are Rust;
Nix modules remain Nix. User hooks are direct, declared Nix-package executables,
never inline shell.

The project uses standard age ciphertext and does not design encryption
primitives. PGP and external SOPS are migration-only. Hosted control planes,
dynamic leases, cloud/Vault providers, and SPIFFE are post-1.0. M-of-N artifact
approval is in v1; threshold decryption requires a separately reviewed design.
Root on an activated target can read that target's plaintext. `rekey` changes
encryption recipients; `rotate` changes the application credential.

## Platforms and public interface

Required release platforms are x86_64/aarch64 NixOS, available x86_64/aarch64
nix-darwin runners, and Home Manager on Linux/macOS in standalone and integrated
modes. The flake exports `packages`, `apps`, NixOS, Darwin, Home Manager and
flake-parts modules, `lib`, and checks. Runtime paths are
`config.nixSeal.secrets.<local-name>.path` and
`config.nixSeal.templates.<local-name>.path`. In scoped mode, target-local names
are qualified into canonical administrator/target IDs and the read-only `id`
field exposes that canonical value for CLI and rekey workflows.

Typed Nix options and `nix-seal.toml` compile into strict, versioned
`plan.v2.json`. Unknown fields and overlapping IDs are fatal. Ordering and
canonicalization are deterministic. IDs are lowercase slugs with `.`, `/`, `-`,
and `_`; absolute paths, `.`/`..` segments, empty segments, and controls are
rejected. Only public metadata may enter the Nix store.

The object model includes identities, groups, targets, secrets, generators,
templates, approval policies, and versioned backends. Secrets support binary or
text values; groups/selectors; rekeyed or advanced direct delivery;
partitioning, users, activation, or services phases; owner/group/mode (with
validated per-target runtime overrides for platform account conventions);
systemd credential mapping; optional compatibility symlinks bound to the active
generation; reload/restart lists; lifecycle and incident metadata; generators
and dependencies; public/secret/intermediary outputs; and runtime templates.
Structured JSON/TOML/YAML/dotenv editing is a logical authoring view. Storage is
one interoperable age file per secret/output.

## Trust and artifact model

The secure default is administrator-to-target rekeying. Canonical sources are
encrypted to administrator/recovery/hardware recipients. A policy plan produces
separate target ciphertext objects. Objects are kept only in the ciphertext
cache and deterministic Nix store derivations. A signed manifest binds the plan
hash, canonical ciphertext hash, target and secret IDs, recipient fingerprint,
artifact generation, tool version, and schema version. Activation verifies all
bindings before decryption.

Direct mode addresses canonical Git ciphertext to consumers. It requires an
explicit opt-in and warns that a stolen target key can decrypt matching current
and historical Git objects.

Approvals use a DSSE/in-toto-style signed envelope with Ed25519 or SSH signing
and distinct signing/decryption keys. At least one trusted signature is the
default, with N-of-M distinct signers supported. Missing, duplicate, untrusted,
expired, malformed, replayed, downgraded, or target-mismatched signatures fail.
The CLI supports explicit local SSH-agent Ed25519 signing through a public-key
descriptor and `SSH_AUTH_SOCK`; agent requests are bounded, timeout-limited,
key-selected, and never fall back to another identity or an interactive prompt.

## CLI contract

The stable hierarchy covers init, plan, check/doctor, keys, identities, groups,
secret CRUD/import/edit/reveal, recipients, generation, rekey, rotation,
templates, cache, provisioning, migration, schema, completions, and internal
activation. Commands are introduced only when functional.

Metadata goes to stdout and diagnostics to stderr. Human and versioned JSON
modes have stable exit categories. Plaintext JSON is forbidden; plaintext output
requires `secret reveal`. Non-interactive commands never unexpectedly prompt.
Secret values are not accepted in argv or ordinary environment variables. Errors
may identify a secret but never contain values or decrypted fragments.

## Cache, Nix bridge, and activation

The Nix front end exposes a typed `flake.nixSeal.administrators` catalog. Each
NixOS, nix-darwin, or Home Manager target selects one administrator with
`nixSeal.administrator`; the module projects only that administrator's
identities, groups, and approval policies into its plan. Framework-provided
target metadata derives host and user scopes, with explicit `targetId` and
`secretScope` overrides for standalone or unusual layouts. The optional
`nix-seal.flakeModules.nix-config-framework` adapter forwards the catalog via
the framework's generic `extraSpecialArgs`, while the framework itself only
provides a reusable `targetName` argument. Omitting the selector preserves the
legacy explicit-identity mode.

The cache is `$XDG_CACHE_HOME/nix-seal/v1`, contains only ciphertext, signed
manifests, and public metadata, and addresses objects by plan, target policy,
source, recipient, target, secret, generation, and format bindings. Transactions
use private same-filesystem directories, locks, fsync, and atomic rename.
Rekeying never occurs in Nix builds. Missing fixed-output objects fail with the
exact safe rekey command. Export/import and encrypted closure copy support
remote builds. GC is dry-run-first and retains only target artifacts that are
authenticated by the active plan, target policy, canonical source hash,
deterministic address, and current approval threshold. Generic v1 cache objects
have no authenticated reachability edge and are candidates until a future format
introduces one. Cache export/import exchanges a staged, ciphertext-only
directory with verified generic objects and target artifact bundles; it excludes
identities, plaintext, locks, and transactions, and import rejects conflicting
same-address content.

Activation verifies schema, signatures, hashes, target, and recipient metadata;
decrypts a complete restrictive generation; and switches only after every value
is ready. It rejects traversal, links, non-regular files, unsafe parents,
ownership, and modes. File operations must be directory-relative with no-follow,
exclusive, close-on-exec, restrictive umask, fsync, and atomic switching.
Compatibility symlinks are created only below an existing owner-only,
non-group/world-writable directory. User-owned symlink components in the parent
ancestry are rejected before platform aliases are canonicalized; the resulting
directory is opened descriptor-relatively with no-follow operations. Links are
published with no-replace semantics and must already point to the exact stable
`runtimeRoot/current/<secret>` path or activation fails. They never point at a
generation directly, so rollback updates the compatibility view with the same
`current` switch. Old or mismatched links are never silently overwritten.
Failure keeps the old generation. Old generations retain old plaintext until
removed or rebooted. NixOS prefers systemd credentials; compatibility files use
`/run/nix-seal`. Home Manager uses its runtime directory and macOS reports when
it is not memory-backed. Units change only after a complete switch.

## Generators, templates, and migration

Built-in Rust generators include random bytes, encoded tokens, passphrases, SSH
Ed25519 and WireGuard keys, accepted password hashes, UUIDs, and service-safe
tokens. Generators have multi-output transactions, a cycle-checked dependency
graph, typed prompts, declared runtime inputs, direct execution, sanitized
environment, private workspace, resource limits, network isolation where
enforceable, least-secret dependency exposure, validation fingerprints, and
all-output validation before replacement. The built-in SSH Ed25519 generator may
expose one separately declared public OpenSSH key derived from its encrypted
private output, and the WireGuard generator may expose one separately declared
public WireGuard key derived from its encrypted private scalar. Other built-ins
reject public outputs until a safe derivation is defined.

Templates use strict placeholders; missing/unused placeholders fail. Templates
remain public in the store and render at activation. Binary interpolation needs
an explicit encoding transform.

Dry-run-first, non-destructive migration adapters cover agenix/ragenix,
agenix-rekey, sops-nix/SOPS, and Clan Vars/Facts. They report mappings first,
stream plaintext directly into age, round-trip every ciphertext, preserve
IDs/scopes where possible, and support side-by-side runtime directories. Source
managers are never rewritten or removed automatically.

## Rust and security policy

Project crates forbid unsafe Rust. Any exception requires a small isolated
crate, an ADR, a documented invariant, and independent review. Secret-bearing
values use `secrecy`/`zeroize`, lack plaintext `Debug`/`Display`, and minimize
copies. Crypto is streamed with bounds. User input must not panic. Arithmetic,
recursion, collections, and external processes are bounded. Errors are
structured and redacted. The application commits `Cargo.lock`, documents an
MSRV, applies SemVer to CLI/IR/config/protocol/options, and retains deprecations
for at least one minor release. The pre-1.0 age crate is pinned behind an
adapter; upgrades require audit and reference/vector interoperability tests.

NIST SSDF is the lifecycle baseline. Required controls include disclosure and
support policies, threat model and compromise runbooks, security ADRs, DCO and
dual license, protected main/reviews/checks, security CODEOWNERS, individually
reviewed updates, cargo-deny/vet/RustSec, Scorecard, secret scanning and CodeQL,
OIDC/keyless publication, reproducible Nix builds, SBOMs, checksums, signed
artifacts, and SLSA provenance. An independent audit is a hard 1.0 gate.

## Verification and release gates

Testing includes unit/property/state-machine tests; official age vectors and
age/rage differential tests; parser and stateful fuzzing; Miri, sanitizers, and
mutation tests; lock/race/interruption tests; migration goldens; NixOS VMs and
real macOS CI; store/log/argv leakage canaries; hostile filesystem and plugin
tests; and approval replay/expiry/rotation/substitution/downgrade tests.

Benchmarks cover 1, 100, 1,000, and 10,000 secrets/targets with streaming
memory, bounded parallelism, serialized hardware identities, incremental hashes,
and published hardware. Compatibility fixtures are retained for every release.

1.0 requires the complete platform matrix, dogfooding and rollback in nix-conf,
all migration fixtures, no plaintext leakage, sustained fuzzing without open
high-severity findings, current threat model/ADRs, completed external audit and
remediation, a public release-candidate compatibility cycle, and exercised
recovery/key-compromise/signer-rotation/target-loss/cache-loss/rollback
runbooks.

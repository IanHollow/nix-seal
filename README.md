# nix-seal

`nix-seal` is a security-first, offline-first secret manager for NixOS,
nix-darwin, and Home Manager. It stores standard age ciphertext in Git, builds a
strict deterministic public policy plan, and activates plaintext only in
restricted runtime directories.

The scale benchmark and its reporting protocol are documented in
[`docs/benchmarks.md`](docs/benchmarks.md). CI publishes raw, machine-readable
benchmark output with runner metadata; timing numbers are never presented as
environment-independent claims.

Release build, SBOM, checksum, and OIDC attestation controls are documented in
[`docs/release.md`](docs/release.md).

Operational recovery, compromise, signer-rotation, cache-loss, and rollback
procedures are documented in [`docs/runbooks.md`](docs/runbooks.md).

The target decryption identity is always an absolute out-of-store runtime path;
the Nix modules reject relative paths and `/nix/store` paths for it.

Before parsing private command input, Unix clients disable new core dumps; Linux
clients also mark the process non-dumpable. This is defense in depth, not a
replacement for operating-system policy or the documented target-root boundary.

The validated `plan.v2` is the single policy authority.
`nix-seal plan --target <id>` emits a canonical target-specific projection.
Rekey and activation derive recipients, hashes, authorized secret/template sets,
runtime permissions, service actions, and per-secret approval thresholds from
that projection rather than trusting duplicate command-line or Nix options.
Signed artifact v2 manifests bind its hash, so policy substitution fails before
decryption.

## Activation phases

Each secret belongs to `partitioning`, `users`, `activation`, or `services`. The
Rust activation document carries exactly one phase and rejects an artifact or
template from another phase. Templates may reference only secrets from their own
phase, so one phase cannot read a plaintext generation owned by another. The
normal `activation` phase remains at `/run/nix-seal/current` on NixOS; other
phases use isolated roots such as `/run/nix-seal/users/current`.

NixOS schedules `users` after `specialfs` and before account creation,
`activation` after account creation, and `services` after the normal nix-seal
activation step. `users` outputs must remain `root:root` because user accounts
may not exist yet. The generic module rejects `partitioning` unless
`nixSeal.installerMode = true` is explicitly set. Installer mode emits the
public `activationSpecs.partitioning` document but schedules no normal
activation script: reviewed installer orchestration must carry that document and
its ciphertext-only artifacts over a protected channel, then invoke the internal
`nix-seal activate` entrypoint with an out-of-store target identity. nix-darwin
currently rejects non-`activation` phases rather than silently running them at
an unsafe point. Home Manager orders `users`, `activation`, and `services` in
its activation DAG with separate `$XDG_RUNTIME_DIR/nix-seal` roots; it rejects
installer-only `partitioning`.

## Nix plan front-end

The flake library exposes `nixSeal.lib.mkPlan` for public Nix metadata. It has a
closed top-level argument set (`identities`, `groups`, `targets`, `secrets`,
`generators`, `templates`, `approvalPolicies`, and `backends`), rejects unknown
collections and invalid collection IDs during Nix evaluation, and emits the same
`plan.v2.json` object consumed by the Rust policy validator:

```nix
let
  plan = nixSeal.lib.mkPlan {
    identities.admin = {
      kind = "administrator";
      public = "age1example...";
    };
    targets.desktop = {
      kind = "nixOs";
      system = "x86_64-linux";
      identity = "admin";
    };
  };
in
  pkgs.writeText "plan.v2.json" plan
```

Secret `selectors` can select exact targets or groups and filter by target kind,
system, username, configuration, environment, and tags. Non-empty selector
fields are ANDed (values within one field are ORed); tags are all-required, and
the result is unioned with explicit `consumers`. Selector references are
validated against the target/group graph before recipient derivation.

Collection values remain public metadata; plaintext values, prompts, and private
identities must never be placed in a Nix expression. Nested fields are validated
with the versioned JSON schema and policy rules by `nix-seal check`. When a TOML
plan is also supplied, the Rust merge is disjoint by collection and ID, so an
overlap is a fatal error rather than a precedence decision.

Start a repository with an empty, valid public plan; this does not generate keys
or create secrets and refuses to overwrite an existing file:

```console
nix-seal init
```

Canonical authoring is plan-directed and reads values only from stdin or an
explicit editor transaction:

```console
nix-seal secret create --plan plan.v2.json --secret db/password \
  --identity ~/.config/age/keys.txt < password.txt
nix-seal secret edit --plan plan.v2.json --secret db/password \
  --identity ~/.config/age/keys.txt --editor /absolute/path/to/editor
nix-seal secret rekey --plan plan.v2.json --secret db/password \
  --identity ~/.config/age/keys.txt --json
nix-seal secret rekey --plan plan.v2.json --secret db/password \
  --identity ~/.config/age/keys.txt --yes
nix-seal secret delete --plan plan.v2.json --secret db/password --yes
nix-seal rotate --plan plan.v2.json --secret db/password \
  --identity ~/.config/age/keys.txt < replacement.txt
nix-seal secret list --plan plan.v2.json --due
```

`create`, `import`, `rotate`, and `edit` accept `--format json`,
`--format toml`, `--format yaml`, or `--format dotenv` to validate a logical
collection before it is encrypted. The original bytes are retained, so
formatting and ordering are not rewritten. Structured input is limited to 64 MiB
and must be valid UTF-8. dotenv validation accepts only unique shell-compatible
`KEY=VALUE` entries (with an optional `export ` prefix); it does not evaluate
shell syntax. An edit that fails its declared format check never replaces the
existing ciphertext. Each canonical source remains one independent standard age
file. Keep any plaintext input file private and remove it according to your
local storage policy.

For field-level authoring, `secret batch` accepts a bounded JSON/TOML/YAML or
dotenv collection on stdin and a public `nix-seal.collection.v1` mapping. Each
mapped scalar is decoded according to its explicit `utf8`, `base64`, or `hex`
encoding and committed as an independent age ciphertext through one all-or-
recover transaction. `--editor /absolute/path/to/editor` stages the collection
in a mode-0600 ephemeral workspace before extraction; the editor receives no
ambient environment or shell. Omit `--replace` for create-only behavior.

```json
{
  "schema": "nix-seal.collection.v1",
  "entries": [
    { "secret": "service/password", "path": "service.password" },
    { "secret": "service/key", "path": "service.key", "encoding": "hex" }
  ]
}
```

The mapping is public metadata only; values, editor responses, and private
identities never enter the plan or Nix store. Unknown or missing mapped fields,
duplicate keys, unsafe paths, malformed encodings, and any failed ciphertext
write abort the complete batch.

The machine-readable mapping schema is available with
`nix-seal schema --kind collection` and is installed with the flake's generated
schemas.

Generate a native recovery identity with `nix-seal key generate`. For a
human-held recovery copy, `nix-seal key generate --passphrase` writes a standard
age scrypt-encrypted identity file after two hidden terminal prompts. The
passphrase is never accepted from argv, stdin, or the environment and is subject
to a minimum length check. Do not use passphrase-protected identity files for
unattended activation; use an age plugin, agent, or hardware-backed identity
instead. On Unix, generated identity files are created relative to no-follow
directory descriptors and are checked for owner-only access, regular-file type,
and a single link. User-owned symlinked ancestry is rejected; root-owned
platform aliases such as macOS `/tmp` are resolved to their canonical directory
before the final no-follow open.

The plan determines canonical administrator/recovery recipients. Direct mode
additionally includes authorized target recipients and emits a history-exposure
warning. Canonical create, import, edit, rotation, and rekey operations require
an identity declared as an administrator or recovery identity; a target key may
decrypt an authorized delivery artifact but cannot author repository ciphertext.
Every create, import, edit, and rotation is encrypted into a private
same-directory transaction, round-trip decrypted and hashed, then atomically
committed. Editor execution uses no shell, inherits no environment, and runs in
a private ephemeral workspace. `secret rekey` changes canonical encryption
recipients without changing the application credential; `rotate` changes the
application credential. `secret rekey` is dry-run by default and requires
`--yes` for its atomic same-source replacement. The top-level `rekey` command is
separate: it creates signed target artifacts in the ciphertext-only cache.

For the default `rekeyed` delivery, `nix-seal rekey` decrypts canonical
ciphertext with `--identity` and produces a separately target-encrypted, signed
cache artifact. For the explicitly advanced `direct` delivery, the same command
deliberately rejects `--identity`: it validates and copies the already
target-addressed canonical age ciphertext into a signed cache artifact without
decrypting or re-encrypting it. Its source and artifact hashes are identical.
This preserves masterless operation while retaining activation's manifest and
approval verification; it does not reduce the documented
historical-key-compromise risk.

`nix-seal provision` applies that same policy to every secret authorized for one
target. It is dry-run-first: without `--execute`, it validates the complete
artifact set, signing authorization, source headers and hashes, recipient
binding, and required administrator/recovery identity without opening or
changing the cache. With `--execute`, it creates or verifies the signed
ciphertext-only cache artifacts. A mixed target may supply `--identity` for its
rekeyed secrets; direct secrets never receive or use that identity.

```console
nix-seal provision --plan plan.v2.json --target host.example --generation 4 \
  --signing-key /private/release.signing-key --identity /private/admin.agekey
nix-seal provision --plan plan.v2.json --target host.example --generation 4 \
  --signing-key /private/release.signing-key --identity /private/admin.agekey \
  --cache-root /var/lib/nix-seal/cache/v1 --execute
```

Provisioning never transmits plaintext. Use the explicit ciphertext-only cache
export/import flow or `nix copy` for a remote build or deployment transport.

There is no deployment lock file. The compiled plan.v2 pins each canonical
ciphertext's SHA-256 hash, while activation verifies a matching signed bundle
directly from the target-local cache. Private identity locations, signing keys,
and plaintext never enter the plan or Nix store.

### Target-local artifact cache (recommended)

After provisioning, transfer the ciphertext-only artifact to the target and
import it into that target's local cache. This keeps artifacts out of Git, flake
inputs, and the Nix store. A host cache is normally
`/var/lib/nix-seal/cache/v1`; a Home Manager cache is normally
`$XDG_CACHE_HOME/nix-seal/v1`.

```console
nix-seal cache export --destination /tmp/nix-seal-cache-export
nix-seal cache import --source /tmp/nix-seal-cache-export --root /var/lib/nix-seal/cache/v1
```

Each target artifact is a directory containing exactly `ciphertext.age` and
`manifest.dsse.json`. Configure one cache root; Nix does not read the cache
while evaluating or building the configuration:

```nix
{
  nixSeal.artifactCacheRoot = "/var/lib/nix-seal/cache/v1";
}
```

The Rust activation runtime opens this directory with its normal no-follow
checks and verifies the signed manifest, target binding, and hashes before it
decrypts anything. Keep the cache scoped: import host artifacts only into the
host cache and user artifacts only into the owning user's cache.

### Reboot and repository lifecycle

An activated NixOS, nix-darwin, or Home Manager generation does not need the
source repository at runtime. Its `nix-seal` executable, public plan, and
activation specification are retained in the Nix store; the target identity and
its local ciphertext-only artifact cache remain outside it. NixOS installs a
boot-time activation unit, nix-darwin installs a launch daemon, and Home Manager
installs a user service or launch agent. They recreate runtime plaintext after
reboot or login from the target-local artifacts, without consulting Git.
Removing the local artifact cache or target identity prevents future activation
and fails closed; it does not expose plaintext.

Deletion never unlinks canonical ciphertext directly. It requires `--yes` and
atomically moves the ciphertext into a private, collision-safe
`.nix-seal/trash/v1` tombstone containing its public secret ID, original source,
ciphertext hash, and deletion time. The authoritative plan is never rewritten
implicitly, so recovery remains possible and `check --deep` fails until policy
is intentionally updated or the ciphertext is restored.

Cache garbage collection is explicitly dry-run-first and trusts neither cache
names nor unsigned metadata. It recomputes the active plan and target-policy
hashes, hashes the canonical source ciphertext through a no-follow descriptor,
reconstructs the deterministic artifact address, and checks the current approval
threshold before retaining an artifact:

```console
nix-seal cache gc --plan plan.v2.json --repository-root .
nix-seal cache gc --plan plan.v2.json --repository-root . --execute
```

Any malformed, expired, stale, source-mismatched, target-mismatched, or
untrusted artifact is a deletion candidate. Version 1 generic cache objects do
not have an authenticated plan reference, so they are always candidates. The
command never removes anything without `--execute`. Both rekeyed and advanced
direct-delivery artifacts are retained only after the same signed manifest,
source-hash, recipient, policy, and target checks succeed.

For air-gapped or remote deployment workflows, cache exchange is an explicit
ciphertext-only directory operation. Export refuses to overwrite its destination
and atomically publishes only verified generic ciphertext and target-artifact
bundles; identities, plaintext, locks, and transactions are excluded. Import
revalidates every entry and is idempotent, but rejects same-address conflicts:

```console
nix-seal cache export --root "$XDG_CACHE_HOME/nix-seal/v1" --destination ./nix-seal-cache
nix-seal cache import --source ./nix-seal-cache
```

The project is in an early, pre-release foundation phase. The current vertical
slice provides strict plan parsing and validation, canonical plan hashing,
native age X25519 encryption/decryption, signed target artifacts, transactional
ciphertext cache writes, authenticated atomic activation, ownership-aware
generation changes, activation-time secret templates, post-switch service
coordination, isolated standard age-plugin operations, Linux generator network
namespace isolation with capability fallback, JSON Schema output, and
NixOS/nix-darwin/Home Manager modules. See [SPEC.md](SPEC.md) and
[ROADMAP.md](ROADMAP.md) before relying on it.

The Nix package check requires round-trip interoperability with both the
reference `age` executable and `rage`, in both encryption directions. They are
test-only dependencies; the shipped runtime remains Rust and uses its isolated
age adapter.

It also pins C2SP/CCTV's age corpus in `flake.lock` and runs every supported
unarmored, uncompressed X25519 and parser vector, including expected rejection
and partial-payload cases. Unsupported passphrase, armor, and hybrid-recipient
vectors remain explicitly skipped until their corresponding native adapter
capabilities are implemented. Standard age-plugin recipients and identities are
handled through the isolated worker described in the security section. A bounded
structural preflight rejects malformed recipient stanzas before delegation to
the pinned pre-1.0 age adapter.

## Installed documentation

The flake's `packages.<system>.documentation` output installs the versioned
`plan`, `target-policy`, `secret-recipients`, and `activation` JSON Schemas,
Bash/Zsh/Fish/Nushell completion definitions generated from the released CLI,
and `nix-seal(1)`. Build it directly with:

```console
nix build github:IanHollow/nix-seal#documentation
```

## Fuzzing

The checked-in `fuzz` workspace exercises strict public `plan.v2`,
`activation.v2`, template-parser, signed-artifact-envelope, age
recipient/identity-parser, and ciphertext-cache state boundaries. It
deserializes untrusted bytes, validates successful documents, checks their
public JSON serialization round trips, renders accepted templates through a
bounded writer, and exercises cache import/export and garbage-collection
reachability; the plan target also derives each target projection. Run the short
sanitizer campaigns locally with a nightly Rust toolchain:

```console
cd fuzz
cargo fuzz run plan-v2 -- -max_total_time=60
cargo fuzz run activation-v2 -- -max_total_time=60
cargo fuzz run template-v1 -- -max_total_time=60
cargo fuzz run artifact-envelope-v1 -- -max_total_time=60
cargo fuzz run identity-v1 -- -max_total_time=60
```

The CI smoke run catches regressions quickly; sustained parser, cache, runtime,
signature, and migration campaigns remain a required 1.0 release gate.

## Runtime templates

Public template sources may be stored in the Nix store. Secret values are
streamed into a private candidate generation only during activation:

```nix
nixSeal.templates."application/config" = {
  source = pkgs.writeText "application.conf.template" ''
    password={{nix-seal:database-password}}
  '';
  placeholders.database-password = {
    secret = "db/password";
    encoding = "utf8";
  };
  mode = "0400";
  restartUnits = [ "my-app.service" ];
};
```

The reserved grammar is exactly `{{nix-seal:name}}`, with lowercase stable
placeholder names. Missing, unused, malformed, or undeclared reserved
placeholders fail the whole activation before `current` changes. `utf8` rejects
binary input; explicit `base64` and lowercase `hex` transforms support arbitrary
bytes. Sources, outputs, declaration counts, and secret reads are bounded.
Rendered files use the same owner/group/mode controls, unchanged generation
detection, atomic switch, rollback preservation, and post-switch action protocol
as ordinary secret files.

## Compatibility symlinks

Legacy applications that require a fixed path can opt into a compatibility
symlink on a secret's runtime policy:

```nix
nixSeal.secrets."db/password".compatibilitySymlink = "/run/my-app/database-password";
```

The link always targets the stable `<runtime-root>/current/db/password` path,
never a generation directly, so a rollback changes the compatibility view
together with `current`. Its parent must already exist, be owned by the
activating user, and not be group- or world-writable. A mismatched existing file
or symlink is an error; nix-seal never silently replaces it. The option is
intentionally unavailable for templates and is rejected inside the private
runtime root.

`nix-seal check` and `nix-seal doctor` validate every bounded public template
source and its declared placeholders before a deployment attempt. For a
deliberate local render outside activation, use an absolute, existing private
directory and an explicit output file:

```console
nix-seal template render \
  --plan plan.v2.json \
  --template application/config \
  --repository-root . \
  --identity /private/administrator.agekey \
  --output /private/runtime/application.conf
```

The command checks that the identity is authorized for every referenced
canonical secret, streams plaintext only into a same-directory staging file,
sets the final file to mode `0600`, and atomically creates it. It never prints
the result; replacement requires `--replace`. The destination must be absolute,
outside `/nix/store`, owned by the invoking user, and in a directory that is not
group- or world-writable.

## Systemd service credentials

NixOS system services and Linux Home Manager user services can receive an
activated secret through systemd's per-service credential directory:

```nix
nixSeal.secrets."db/password" = {
  source = "secrets/services/db-password.age";
  serviceCredentials = [
    {
      unit = "my-app.service";
      name = "database-password";
    }
  ];
};

nixSeal.artifactCacheRoot = "/var/lib/nix-seal/cache/v1";
```

The service reads `$CREDENTIALS_DIRECTORY/database-password`. A mapping emits
`LoadCredential=` without putting plaintext in a unit or the Nix store and
automatically adds the service to the changed-generation restart set. NixOS
system services also default to `PrivateMounts=true`, limiting credential
visibility to the service mount namespace. Credential names may have only
portable filename characters, and a `(unit, name)` pair can belong to only one
secret. Darwin configurations reject this systemd-only option.

## Security status

This code has **not** received the independent audit required for 1.0. Do not
use it for production secrets yet. Report vulnerabilities according to
[SECURITY.md](SECURITY.md).

## Diagnostics

`nix-seal doctor --plan plan.v2.json --repository-root .` performs the same deep
public-policy and canonical-ciphertext checks used before deployment, then
reports authenticated and stale cache-artifact counts plus platform/runtime
caveats. An artifact is authenticated only when its current plan, target policy,
source hash, recipient, address, manifest, and approval threshold all verify. It
emits only public metadata and does not decrypt secrets.

Non-usage failures use stable exit categories: `1` operational, `3` policy, `4`
cryptographic or approval verification, `5` cache/canonical-storage, and `6`
runtime activation. Clap reserves `2` for argument/usage errors.

`nix-seal key list --plan plan.v2.json` inventories the identities declared by
that validated public plan. It exposes only each stable ID, role, and public
recipient, signer, or plugin reference; it never searches for or reads private
identity files.

Age-plugin recipients and identities use the standard age plugin protocol
through an isolated internal worker. The worker resolves only the declared
`age-plugin-*` binaries, clears the inherited environment, passes an explicit
allowlist needed by hardware/agent plugins, closes unrelated descriptors,
enforces bounded streaming I/O and a timeout, and terminates the worker process
group on failure. Plugin callbacks are non-interactive in this release, so a
plugin that requires a prompt fails closed. Plugin identities do not expose a
generic public key; authorization prechecks compare the plugin name and the age
stanza decryption remains authoritative.

Approval signer identities may use either the native `nix-seal-ed25519-v1:`
public-key format or a standard `ssh-ed25519` public key. The corresponding
`--signing-key` file may be a native key or an unencrypted OpenSSH Ed25519
private key. SSH approvals use a standard PEM `sshsig`, bound to a dedicated
nix-seal namespace and the same DSSE payload as native approvals; public-key
comments do not affect authorization. For private keys held by a compatible
local agent, the file may instead contain
`NIX-SEAL-SSH-AGENT-ED25519-v1:ssh-ed25519 ...`; nix-seal then requires
`SSH_AUTH_SOCK`, selects the exact public key in the agent sign request, uses
the standard bounded Unix-agent protocol with a ten-second I/O timeout, and
never reads or persists the private key. Agent use is explicit rather than
inferred from the environment. SSH RSA, ECDSA, FIDO/U2F security-key algorithms,
encrypted OpenSSH files, and interactive agent prompts remain rejected until
their own reviewed protocol paths are implemented.

For TOML-managed plans, `nix-seal identity add|remove|rotate` updates only the
public TOML source in a same-directory atomic transaction. It validates the
merged Nix/TOML policy before committing and refuses to remove referenced IDs.
Rotation requires `--yes` and deliberately invalidates old artifacts, so it
reports that rekeying and approval are required. Nix-emitted plan sources are
validation inputs and are never rewritten by these commands.

`nix-seal group add|list|remove` uses the same transaction path for named
administrator or consumer groups. Group creation requires explicit members;
removal requires `--yes` and fails while another group or a secret's
administrator/consumer policy still references it.

## Built-in generation

`nix-seal generate` follows the public plan, derives the canonical recipients,
and encrypts the generated value through the normal verified authoring path. The
current Rust-only built-ins are `builtin:random`, `builtin:hex`,
`builtin:base64`, `builtin:token`, `builtin:passphrase`, `builtin:ssh-ed25519`,
`builtin:argon2id-password-hash`, `builtin:wireguard-private-key`, and
`builtin:uuid`. Random, hex, base64, and token generators accept one public
`bytes` parameter (1–1,048,576; default 32). `builtin:token` emits unpadded
URL-safe base64 for service-safe tokens; `builtin:base64` emits standard padded
base64. `builtin:wireguard-private-key` generates a clamped 32-byte Curve25519
private scalar in the standard WireGuard base64 format and accepts no
parameters; UUID accepts none. `builtin:passphrase` uses 12–64 uniformly
selected, hyphen-separated words from an embedded 64-word list (default 16, 96
bits of selection entropy). `builtin:argon2id-password-hash` accepts exactly one
declared single-line hidden prompt and emits one Argon2id PHC string. It
defaults to 64 MiB, three iterations, one lane, and a 32-byte output; public
bounds are 19–512 MiB, 2–10 iterations, and 16–64 output bytes. The private
prompt value is never put in the plan, arguments, environment, or logs.
`builtin:ssh-ed25519` produces one standard unencrypted OpenSSH Ed25519 private
key, which is immediately encrypted through the normal canonical-secret
transaction; its public key is derivable from that secret. Generation is
create-only unless `--replace` is explicit. Generators may produce multiple
secret outputs and declared public outputs. Every output is validated before any
destination changes; secret outputs are encrypted and round-trip verified,
public outputs are written with mode `0644`, and replacement failures restore
the complete prior set. Direct executable generators use an explicit protocol:
`executable` and every `runtimeInputs` entry must be under `/nix/store`;
`arguments` are literal public values; and the process runs with a cleared
environment, null standard streams, a private workspace, and a bounded timeout.
On Unix it also runs in a dedicated process group, so timeout cleanup terminates
descendants that might otherwise retain staged plaintext. It must write exactly
one regular file named `0`, `1`, and so on for each declared secret output
beneath `$NIX_SEAL_OUTPUT_DIR`, plus the same numbered protocol beneath
`$NIX_SEAL_PUBLIC_OUTPUT_DIR` for declared public outputs. Unlisted files,
links, oversized output, nonzero exits, and timeouts fail the full transaction
without exposing process output. Public destinations are repository-relative,
must not collide with ciphertext sources, and are recorded in the public plan;
built-in generators emit encrypted secret outputs; `builtin:ssh-ed25519` may
additionally emit one derived public OpenSSH key, and
`builtin:wireguard-private-key` may additionally emit one derived public
WireGuard key, without exposing private material.

Private identities, prompt state, generator dependencies, and generator outputs
are permissioned through their already-open descriptors. Generator output paths
are opened with no-follow and single-link checks before mode `0600` is applied,
so a pathname substitution cannot redirect a permission change or the bounded
read to another file.

Set a generator's public `validation` value when its generated credential must
be replaced after a specific non-secret configuration change. nix-seal records
only the generator ID, output IDs, and validation value in a private local
`.nix-seal/generator-state/v1` file. The first matching run creates the outputs;
later matching runs are no-ops, while a changed validation value performs a
transactional replacement. Existing outputs without this state intentionally
require `--replace` to establish a baseline, preventing an unreviewed metadata
file from silently rotating a credential.

Declared external-generator prompts are non-interactive by default. Supply each
response with
`nix-seal generate --prompt-file prompt/id=/absolute/private-file`; the response
file must be owned by the invoking user and mode `0600` (or stricter). The CLI
rejects missing or unused prompt files and copies responses only into numbered
files below `$NIX_SEAL_PROMPT_DIR` in the private workspace. Prompt values never
enter the plan, command arguments, environment, or logs. A prompt marked
`persistent = true` may be initialized from an explicit `--prompt-file`; after a
successful generation its response is atomically retained in the owner-only
repository state path `.nix-seal/prompt-state/v1/<generator>/<prompt>`, and
later runs may use that stored response without passing it again. Nonpersistent
prompts are never retained. Persistent state is plaintext and must be protected
like any other local credential; it is not part of Git, the Nix store, or the
public plan. For an explicitly interactive workflow, pass `--interactive`.
nix-seal then opens the controlling `/dev/tty` rather than stdin/stdout, rejects
non-terminal sessions, sanitizes public prompt labels before display, bounds
each response to 1 MiB, masks `hidden` prompts with terminal settings restored
on all errors, and never places the response in argv, ordinary environment
variables, the plan, or logs. Single-line prompts finish at Enter; multiline
prompts finish with Ctrl-D and preserve entered line endings. Automation should
continue to use private response files, because interactive prompting is never
implicit.

External generators may additionally declare `secretDependencies`. nix-seal
requires every declared ID to be an existing canonical secret, forbids duplicate
or self-output dependencies, verifies that the supplied identity is an
authorized canonical recipient, then streams each dependency into an owned
`0600` file named `0`, `1`, and so on beneath `$NIX_SEAL_SECRET_DIR` in declared
order. `$NIX_SEAL_SECRET_COUNT` is public metadata only. Built-in generators
cannot receive secret dependencies. No undeclared canonical secret is decrypted
for the generator, and the private workspace is removed whether generation
succeeds or fails. If an input is itself produced by another generator, that
producer must be a direct entry in `dependencies`, making generation order
explicit and checkable. On Linux, nix-seal launches the generator through a Rust
worker that attempts a fresh network namespace before execution. If the kernel
or container denies that operation, nix-seal falls back once to the direct
process-group path and emits a diagnostic warning. macOS and other platforms
emit the same capability warning because network isolation is not available
there; generators and their declared runtime inputs must always be treated as
trusted code.

Set a secret's `repositoryOnly` policy bit for an intermediary output that must
remain administrator/recovery-encrypted in the repository and cache but must
never be delivered to a target. Policy validation rejects target consumers and
advanced direct delivery for such secrets; this explicit bit avoids relying on
an empty consumer list as a security signal.

## Migration inspection

Migration begins with a deliberately non-destructive public inventory. Inspect
the stable mapping before touching ciphertext:

```console
nix-seal migrate agenix --directory ./secrets --json
# ragenix uses the same standard age ciphertext inventory format
nix-seal migrate ragenix --directory ./secrets --json
# bulk import is side-by-side and remains dry-run-first
nix-seal migrate agenix --repository-root . --directory legacy/secrets \
  --destination secrets/nix-seal --identity /absolute/private/admin.agekey \
  --verification-identity /absolute/private/nix-seal-admin.agekey \
  --recipient age1admin... --recipient age1recovery... --json
# add --execute only after reviewing every mapping and recipient
nix-seal migrate agenix --repository-root . --directory legacy/secrets \
  --destination secrets/nix-seal --identity /absolute/private/admin.agekey \
  --verification-identity /absolute/private/nix-seal-admin.agekey \
  --recipient age1admin... --recipient age1recovery... --execute
# inspect an evaluated agenix-rekey policy export without decrypting data
nix eval --json .#agenixRekeyMigration > /tmp/agenix-rekey.json
nix-seal migrate agenix-rekey --metadata /tmp/agenix-rekey.json --json
# inspect structured SOPS JSON metadata without decrypting values or invoking SOPS
nix-seal migrate sops-json --directory ./secrets --json
# Convert one SOPS document using only an explicit SOPS binary and private age key file.
nix-seal migrate sops --repository-root . --source legacy/token.yaml \
  --destination secrets/token.age --sops /absolute/path/to/sops \
  --sops-age-key-file /absolute/private/sops-age-key.txt \
  --identity /absolute/private/nix-seal-admin.age --recipient age1... --execute
# inventory Clan's documented per-machine output leaves without reading values
nix-seal migrate clan-vars --directory ./vars/per-machine --json
# after reviewing the mapping, stream values into a side-by-side native age tree
nix-seal migrate clan-vars --directory vars/per-machine \
  --repository-root . --destination nix-seal-vars \
  --identity /absolute/private/nix-seal-admin.age \
  --recipient age1... --execute
# inventory documented Clan Facts public leaves without reading values
nix-seal migrate clan-facts --directory ./machines --json
# after reviewing the mapping, copy public facts side-by-side
nix-seal migrate clan-facts --directory machines --repository-root . \
  --destination nix-seal-public --execute
# First inspect the mutation; then add --execute to stream-reencrypt it.
nix-seal migrate ciphertext --source legacy/token.age --destination secrets/token.age \
  --identity /absolute/path/to/administrator.age --recipient age1... --json
```

It validates legacy paths, IDs, and SSH recipient metadata. An explicit
repository-relative destination, private identity, and replacement recipients
enable a side-by-side bulk rekey; `--execute` is required before ciphertext is
opened, and the source tree remains untouched. Without those import flags it
never decrypts or rewrites legacy files. New plans should use native age
recipients. Existing unencrypted OpenSSH Ed25519/RSA identities are supported
only as a migration compatibility path; encrypted SSH private keys are
deliberately rejected in non-interactive workflows, so convert them to a
reviewed native-age or hardware-backed identity before automated import.

For age-tree, agenix-rekey, and single-file ciphertext migration, `--identity`
is the legacy source/decryption identity. `--verification-identity` is optional
and defaults to `--identity`; when supplied it must be authorized by every
replacement recipient and is used to authenticate the newly written ciphertext.
This explicit split is required when a migration replaces a legacy SSH or age
key with a new administrator or recovery key. Both private identities are opened
only for `--execute`; dry runs inspect public metadata and paths.

PGP is migration-only and never a native nix-seal encryption backend. Its
dry-run-first bridge requires an absolute GnuPG executable and private,
owner-only `GNUPGHOME`; execution clears inherited environment variables,
disables option-file and automatic-key lookup behavior, suppresses GnuPG
diagnostics, bounds the plaintext stream, and encrypts directly into a new
native age file:

```console
nix-seal migrate pgp --repository-root . --source legacy/service.pgp \
  --destination secrets/service.age --gpg /absolute/path/to/gpg \
  --gnupg-home /private/gnupg --identity /private/administrator.agekey \
  --recipient age1example
nix-seal migrate pgp --repository-root . --source legacy/service.pgp \
  --destination secrets/service.age --gpg /absolute/path/to/gpg \
  --gnupg-home /private/gnupg --identity /private/administrator.agekey \
  --recipient age1example --execute
```

The agenix/ragenix adapters recursively inventory only regular `*.age` files,
validate their age headers, and reject symbolic links or unsafe nesting. Because
recipient and Nix module policy are not recoverable from ciphertext paths, their
reports require an explicit nix-seal recipient mapping before import. Supplying
`--destination`, `--identity`, and one or more `--recipient` values enables a
bulk migration preflight; the identity is not opened until `--execute` is
present. The destination must be a separate repository-relative tree. Every
source is streamed and round-trip verified into a private staging file before
any destination changes, then all destination files are committed with backup
and rollback behavior. Existing legacy files and configuration are never
rewritten, so the two managers can run side by side during activation and
rollback verification. `--replace` is explicit and still preserves the legacy
tree. The same flow is available for ragenix because its ciphertext layout is
standard age-compatible.

Public migration compatibility goldens are checked into
`crates/nix-seal-cli/tests/fixtures/migrations` and exercised through the
released binary. They cover agenix, ragenix, agenix-rekey, SOPS JSON metadata,
Clan Vars, and Clan Facts. The fixtures contain only public metadata,
empty/public leaves, or ciphertext without its private identity; mutation
adapters remain dry-run-first and require separate round-trip tests before a 1.0
migration claim.

For agenix-rekey, expose one public evaluated configuration with
`nixSeal.lib.agenixRekeyMigrationExport`. The target must declare `id`, `kind`
(`nixos`, `darwin`, or `home-manager`), `system`, `recipient`, and `storageMode`
(`local` or `derivation`); `masterRecipients` contains only public master
recipients. Each secret maps to a repository-relative string `rekeyFile` and may
set `intermediary = true`. The inventory validates all of those public values,
normalizes recipients, and preserves intermediary secrets as repository-only.
Supplying `--destination`, `--identity`, and one or more `--recipient` values
enables the same dry-run-first, side-by-side bulk rekey flow as agenix/ragenix;
`--verification-identity` may select the new administrator/recovery identity;
`--execute` is required before either private identity is opened. Every source
is staged and round-trip verified before any destination changes, while the
legacy tree remains intact for rollback. It does not infer private runtime
configuration or rewrite the legacy ciphertext.

```nix
nixSeal.lib.agenixRekeyMigrationExport {
  target = {
    id = "desktop";
    kind = "nixOs";
    system = "x86_64-linux";
    recipient = "ssh-ed25519 AAAA...";
    storageMode = "derivation";
  };
  masterRecipients = [ "age1..." ];
  secrets.service-token.rekeyFile = "secrets/service-token.age";
}
```

Build a separate, reviewable `plan.v2.json` with the Nix or TOML frontend before
performing a migration. The plan must name target systems, approval signers,
administrator or recovery recipients, runtime ownership, phases, lifecycle, and
templates explicitly. The default delivery is administrator-backed `rekeyed`;
advanced `direct` delivery is intentionally explicit because a stolen target key
can decrypt historical ciphertext addressed to that target.

When one canonical secret serves targets with different local account-group
conventions, `runtimeOverrides.<target-id>` may replace its public runtime
owner/group/mode for an already-authorized target. The resolved value is part of
that target's signed policy and cannot be changed at activation time.

`migrate sops-json` is intentionally a metadata-only adapter for SOPS JSON
files. It accepts only bounded regular files, validates the top-level `sops`
object, MAC/version fields, provider metadata, age recipients, and SOPS key
groups, then reports public provider types. It does not decrypt or authenticate
the document values; structured extraction and SOPS invocation remain an
explicit later migration step. YAML, dotenv, INI, and binary SOPS inputs are not
silently treated as JSON.

`migrate sops` is the separate mutation path for a single reviewed SOPS
document. It invokes only an absolute, non-symlink SOPS executable with an empty
environment, optionally passing a private `SOPS_AGE_KEY_FILE` path. Its
plaintext stdout is bounded to 64 MiB and streamed directly into a staged native
age ciphertext; no plaintext file is created. The staged result is round-trip
verified and is committed only after SOPS exits successfully. SOPS diagnostics
are deliberately discarded to avoid leaking values into the invoking terminal;
failure is reported as a redacted status error. A 120-second watchdog terminates
a stalled process. This initial mutation path therefore supports SOPS age
identities explicitly; PGP and cloud/KMS SOPS migrations remain a separately
reviewed extension rather than implicitly inheriting credential environments.

`migrate clan-vars` recognizes only the documented
`vars/per-machine/<machine>/<generator>/<output>/value` leaves. It validates the
complete filesystem walk without following links, reports paths and byte counts,
and never reads, decrypts, prints, or passes a value to another process during
inventory. Clan storage backend, secret/public classification, target
authorization, and runtime policy are not encoded by those leaves, so they must
be supplied in a reviewed mapping before import. Supplying `--repository-root`,
`--destination`, `--identity`, and one or more `--recipient` values enables a
side-by-side import; `--execute` is required before values are opened. Every
value is streamed into a staged age ciphertext, round-trip verified, and
committed as one recoverable batch while the legacy Vars tree remains unchanged.

`migrate clan-facts` inventories only documented public
`machines/<machine>/facts/<fact>` leaves, with link/type and 64 MiB bounds. It
never reads their values during inventory. Supplying a repository-relative
destination enables an explicit side-by-side public import; `--execute` streams
each leaf through a bounded no-follow file transaction, verifies the complete
batch, and publishes mode-safe outputs while leaving the legacy tree untouched.
Clan secret facts have configurable stores and paths, so they need an explicit
reviewed export instead of filesystem inference.

## Development

```console
nix develop
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
nix flake check
```

Licensed under either Apache-2.0 or MIT, at your option. Contributions require a
Developer Certificate of Origin sign-off.

# nix-seal

`nix-seal` is a security-first, offline-first secret manager for NixOS,
nix-darwin, and Home Manager. It stores standard age ciphertext in Git, builds a
strict deterministic public policy plan, and activates plaintext only in
restricted runtime directories.

The validated `plan.v1` is the single policy authority.
`nix-seal plan --target <id>` emits a canonical target-specific projection.
Rekey and activation derive recipients, hashes, authorized secret/template sets,
runtime permissions, service actions, and per-secret approval thresholds from
that projection rather than trusting duplicate command-line or Nix options.
Signed artifact v2 manifests bind its hash, so policy substitution fails before
decryption.

Canonical authoring is plan-directed and reads values only from stdin or an
explicit editor transaction:

```console
nix-seal secret create --plan plan.v1.json --secret db/password \
  --identity ~/.config/age/keys.txt < password.txt
nix-seal secret edit --plan plan.v1.json --secret db/password \
  --identity ~/.config/age/keys.txt --editor /absolute/path/to/editor
nix-seal secret delete --plan plan.v1.json --secret db/password --yes
nix-seal rotate --plan plan.v1.json --secret db/password \
  --identity ~/.config/age/keys.txt < replacement.txt
nix-seal secret list --plan plan.v1.json --due
```

The plan determines canonical administrator/recovery recipients. Direct mode
additionally includes authorized target recipients and emits a history-exposure
warning. Every create, import, edit, and rotation is encrypted into a private
same-directory transaction, round-trip decrypted and hashed, then atomically
committed. Editor execution uses no shell, inherits no environment, and runs in
a private ephemeral workspace. `rekey` changes encryption recipients; `rotate`
changes the application credential.

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
nix-seal cache gc --plan plan.v1.json --repository-root .
nix-seal cache gc --plan plan.v1.json --repository-root . --execute
```

Any malformed, expired, stale, source-mismatched, target-mismatched, or
untrusted artifact is a deletion candidate. Version 1 generic cache objects do
not have an authenticated plan reference, so they are always candidates. The
command never removes anything without `--execute`.

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
coordination, JSON Schema output, and NixOS/nix-darwin/Home Manager modules. See
[SPEC.md](SPEC.md) and [ROADMAP.md](ROADMAP.md) before relying on it.

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

## Systemd service credentials

NixOS system services and Linux Home Manager user services can receive an
activated secret through systemd's per-service credential directory:

```nix
nixSeal.secrets."db/password" = {
  ciphertext = ./artifacts/db-password.age;
  envelope = ./artifacts/db-password.envelope.json;
  sourceCiphertextHash = "…64 lowercase hexadecimal characters…";
  serviceCredentials = [
    {
      unit = "my-app.service";
      name = "database-password";
    }
  ];
};
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

`nix-seal doctor --plan plan.v1.json --repository-root .` performs the same deep
public-policy and canonical-ciphertext checks used before deployment, then
reports verified cache inventory and platform/runtime caveats. It emits only
public metadata and does not decrypt secrets.

## Built-in generation

`nix-seal generate` follows the public plan, derives the canonical recipients,
and encrypts the generated value through the normal verified authoring path. The
current Rust-only built-ins are `builtin:random`, `builtin:hex`, and
`builtin:uuid`. Random and hex generators accept one public `bytes` parameter
(1–1,048,576; default 32); UUID accepts none. Generation is create-only unless
`--replace` is explicit. Generators may produce multiple secret outputs: every
output is encrypted and round-trip verified before an existing ciphertext is
changed, and replacement failures restore prior ciphertext. Direct executable
generators use an explicit protocol: `executable` and every `runtimeInputs`
entry must be under `/nix/store`; `arguments` are literal public values; and the
process runs with a cleared environment, null standard streams, a private
workspace, and a bounded timeout. It must write exactly one regular file named
`0`, `1`, and so on for each declared output beneath `$NIX_SEAL_OUTPUT_DIR`.
Unlisted files, links, oversized output, nonzero exits, and timeouts fail the
full transaction without exposing process output.

Declared external-generator prompts are non-interactive by default. Supply each
response with
`nix-seal generate --prompt-file prompt/id=/absolute/private-file`; the response
file must be owned by the invoking user and mode `0600` (or stricter). The CLI
rejects missing or unused prompt files and copies responses only into numbered
files below `$NIX_SEAL_PROMPT_DIR` in the private workspace. Prompt values never
enter the plan, command arguments, environment, or logs. Persistent prompt
storage and terminal prompting remain explicitly unavailable until their
separate storage and TTY hardening designs are complete.

## Migration inspection

The first migration adapter is deliberately report-only. Export the existing
public index and inspect the stable mapping before touching ciphertext:

```console
nix eval --json .#secretIndex > /tmp/secretctl-index.json
nix-seal migrate secretctl --index /tmp/secretctl-index.json --json
nix-seal migrate agenix --directory ./secrets --json
# ragenix uses the same standard age ciphertext inventory format
nix-seal migrate ragenix --directory ./secrets --json
```

It validates legacy paths, scopes, consumers, IDs, and SSH recipient metadata,
then reports normalized nix-seal IDs. It never decrypts or rewrites legacy
files. New plans should use native age recipients. Existing unencrypted OpenSSH
Ed25519/RSA identities are supported only as a migration compatibility path;
encrypted SSH private keys are deliberately rejected in non-interactive
workflows, so convert them to a reviewed native-age or hardware-backed identity
before automated import.

The agenix/ragenix adapters recursively inventory only regular `*.age` files,
validate their age headers, and reject symbolic links or unsafe nesting. Because
recipient and Nix module policy are not recoverable from ciphertext paths, their
reports require an explicit nix-seal target/recipient mapping before import.

## Development

```console
nix develop
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
nix flake check
```

Licensed under either Apache-2.0 or MIT, at your option. Contributions require a
Developer Certificate of Origin sign-off.

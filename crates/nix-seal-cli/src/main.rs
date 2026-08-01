#![forbid(unsafe_code)]
//! Command-line interface. Plaintext output is limited to `secret reveal`.

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use base64::{
    Engine as _,
    engine::general_purpose::{
        STANDARD as BASE64_STANDARD, STANDARD_NO_PAD as BASE64_STANDARD_NO_PAD, URL_SAFE_NO_PAD,
    },
};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command as ProcessCommand, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const EXTERNAL_MIGRATION_MAX_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024;
const EXTERNAL_MIGRATION_TIMEOUT: Duration = Duration::from_mins(2);
const PASSPHRASE_WORDS: [&str; 64] = [
    "amber", "anchor", "april", "arch", "aspen", "atlas", "aurora", "bamboo", "beacon", "birch",
    "blue", "brisk", "canyon", "cedar", "cinder", "cobalt", "comet", "coral", "crystal", "dawn",
    "delta", "dune", "ember", "falcon", "fern", "fjord", "forest", "glacier", "harbor", "hazel",
    "island", "jade", "juniper", "lagoon", "lantern", "lilac", "maple", "meadow", "meteor", "mist",
    "moon", "moss", "oasis", "ocean", "olive", "opal", "orchid", "pearl", "pine", "prairie",
    "quartz", "raven", "river", "sable", "saffron", "sage", "shore", "silver", "solstice",
    "spruce", "stone", "sunset", "thunder", "willow",
];

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

/// A public plan identity suitable for human and machine-readable inventory.
///
/// This intentionally excludes every private identity location and material:
/// the compiled plan is the sole source and contains public references only.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicIdentityRecord {
    id: String,
    kind: &'static str,
    public: String,
}

const GENERATOR_STATE_SCHEMA: &str = "nix-seal.generator-state.v1";

/// Private, non-secret bookkeeping for explicit generator validation values.
/// It never contains generated plaintext, identities, or recipient material.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GeneratorStateV1 {
    schema: String,
    generator_id: nix_seal_core::Id,
    validation: String,
    outputs: Vec<nix_seal_core::Id>,
    #[serde(default)]
    public_outputs: Vec<nix_seal_core::Id>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneratorAction {
    Create,
    Replace,
    Unchanged,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0_u8; 1];
            if self.inner.read(&mut probe)? == 0 {
                return Ok(0);
            }
            return Err(std::io::Error::other(
                "external plaintext producer exceeded the migration size limit",
            ));
        }
        let usable = usize::try_from(self.remaining.min(buffer.len() as u64))
            .map_err(|_| std::io::Error::other("invalid migration input bound"))?;
        let read = self.inner.read(&mut buffer[..usable])?;
        self.remaining = self
            .remaining
            .checked_sub(read as u64)
            .ok_or_else(|| std::io::Error::other("invalid migration input size"))?;
        Ok(read)
    }
}

#[derive(Parser)]
#[command(
    name = "nix-seal",
    version,
    about = "Security-first secret management for Nix"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit versioned `JSON` metadata. Plaintext is never encoded as `JSON`.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create a valid empty public plan without generating keys or secrets.
    Init {
        /// New TOML plan path. The command refuses to overwrite an existing file.
        #[arg(long, default_value = "nix-seal.toml")]
        config: PathBuf,
    },
    /// Compile, validate, hash, and print the public plan.
    Plan {
        #[arg(long, default_value = "nix-seal.toml")]
        toml: PathBuf,
        #[arg(long)]
        nix_plan: Option<PathBuf>,
        /// Emit only the deterministic policy authorized for this target.
        #[arg(long)]
        target: Option<nix_seal_core::Id>,
        /// Write canonical public JSON to a new file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate policy and public references.
    Check {
        #[arg(long, default_value = "nix-seal.toml")]
        toml: PathBuf,
        #[arg(long)]
        nix_plan: Option<PathBuf>,
        #[arg(long)]
        deep: bool,
        /// Repository root used for deep canonical ciphertext checks.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
    },
    /// Diagnose public policy, ciphertext references, and runtime capabilities.
    Doctor {
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
        /// Repository root used to verify canonical ciphertext references.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Override the standard XDG cache root.
        #[arg(long)]
        cache_root: Option<PathBuf>,
    },
    /// Identity operations.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Manage public identities declared by a TOML plan.
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Manage public groups declared by a TOML plan.
    #[command(subcommand)]
    Group(GroupCommand),
    /// Signed target-artifact operations.
    #[command(subcommand)]
    Artifact(ArtifactCommand),
    /// Explicitly create or verify a target-encrypted cache artifact.
    Rekey(RekeyArgs),
    /// Dry-run-first creation or verification of every target artifact.
    Provision(ProvisionArgs),
    /// Generate plan-declared canonical ciphertext using a built-in Rust generator.
    Generate(GenerateArgs),
    /// Internal authenticated runtime activation entrypoint.
    #[command(hide = true)]
    Activate(ActivateArgs),
    /// Internal isolated age-plugin worker. This is not a stable user command.
    #[command(name = "__plugin-worker", hide = true)]
    PluginWorker,
    /// Secret authoring operations.
    #[command(subcommand)]
    Secret(SecretCommand),
    /// Replace an application credential from stdin; this is distinct from rekeying recipients.
    Rotate(SecretWriteArgs),
    /// Print the plan-derived canonical recipients for one secret.
    Recipients(SecretPlanArgs),
    /// Print a versioned public `JSON` Schema.
    Schema {
        #[arg(long, value_enum, default_value_t = SchemaKind::Plan)]
        kind: SchemaKind,
    },
    /// Validate public template sources without decrypting or rendering secrets.
    #[command(subcommand)]
    Template(TemplateCommand),
    /// Generate shell completion definitions.
    Completions { shell: CompletionShell },
    /// Dry-run-first migration inspection adapters.
    #[command(subcommand)]
    Migrate(MigrateCommand),
    /// Ciphertext cache operations.
    #[command(subcommand)]
    Cache(CacheCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// List public identities declared by a compiled plan.
    List {
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
    },
    /// Generate an age `X25519` identity into a new mode-0600 file.
    Generate {
        #[arg(long)]
        identity_out: PathBuf,
    },
    /// Print the public recipient for an age `X25519` identity file.
    Inspect {
        #[arg(long)]
        identity: PathBuf,
    },
    /// Generate a separate Ed25519 artifact-approval key.
    GenerateSigning {
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Print the public key and fingerprint for an approval key.
    InspectSigning {
        #[arg(long)]
        key: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// List identities from the validated merged plan.
    List(IdentityPlanArgs),
    /// Add a new public identity to the TOML plan.
    Add {
        #[command(flatten)]
        plan: IdentityPlanArgs,
        #[arg(long)]
        id: nix_seal_core::Id,
        #[arg(long, value_enum)]
        kind: IdentityRole,
        /// Public age recipient, approval key, or plugin reference.
        #[arg(long)]
        public: String,
    },
    /// Remove an unreferenced public identity from the TOML plan.
    Remove {
        #[command(flatten)]
        plan: IdentityPlanArgs,
        #[arg(long)]
        id: nix_seal_core::Id,
        /// Acknowledge removal of this public policy object.
        #[arg(long)]
        yes: bool,
    },
    /// Replace an existing identity's public value without changing its role.
    Rotate {
        #[command(flatten)]
        plan: IdentityPlanArgs,
        #[arg(long)]
        id: nix_seal_core::Id,
        /// Replacement public age recipient, approval key, or plugin reference.
        #[arg(long)]
        public: String,
        /// Acknowledge that artifacts must be rekeyed or reapproved afterwards.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// List groups from the validated merged plan.
    List(IdentityPlanArgs),
    /// Add a named group with explicit public object IDs.
    Add {
        #[command(flatten)]
        plan: IdentityPlanArgs,
        #[arg(long)]
        id: nix_seal_core::Id,
        /// Identity, target, or existing group member; repeat as needed.
        #[arg(long = "member", required = true)]
        members: Vec<nix_seal_core::Id>,
    },
    /// Remove an unreferenced group from the TOML plan.
    Remove {
        #[command(flatten)]
        plan: IdentityPlanArgs,
        #[arg(long)]
        id: nix_seal_core::Id,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum TemplateCommand {
    /// Check declared placeholders against bounded public template sources.
    Check {
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
    },
    /// Render one template into an explicit private file; plaintext is never printed.
    Render {
        /// Canonical compiled plan.v1 JSON.
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
        /// Declared template ID selected from the plan.
        #[arg(long)]
        template: nix_seal_core::Id,
        /// Repository root used to resolve canonical ciphertext sources.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Administrator or recovery identity authorized for every placeholder secret.
        #[arg(long)]
        identity: PathBuf,
        /// Absolute private output path. It is created with mode 0600.
        #[arg(long)]
        output: PathBuf,
        /// Replace an existing safe regular output file atomically.
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Args)]
struct IdentityPlanArgs {
    /// TOML source that this command is allowed to rewrite.
    #[arg(long, default_value = "nix-seal.toml")]
    toml: PathBuf,
    /// Optional public Nix-emitted plan merged for validation only; it is never rewritten.
    #[arg(long)]
    nix_plan: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum IdentityRole {
    Administrator,
    Target,
    Recovery,
    Signer,
    Plugin,
}

#[derive(Subcommand)]
enum ArtifactCommand {
    /// Canonicalize and sign a strict target-manifest JSON file.
    Sign {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Add a distinct approval signature to an existing envelope.
    Approve {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify signatures and every caller-supplied artifact binding.
    Verify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long = "trusted-key", required = true)]
        trusted_keys: Vec<PathBuf>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long)]
        plan_hash: String,
        #[arg(long)]
        target_policy_hash: String,
        #[arg(long)]
        source_hash: String,
        #[arg(long)]
        artifact_hash: String,
        #[arg(long)]
        target: nix_seal_core::Id,
        #[arg(long)]
        secret: nix_seal_core::Id,
        #[arg(long)]
        recipient_fingerprint: String,
        #[arg(long)]
        generation: u64,
        #[arg(long, default_value_t = 300)]
        allowed_clock_skew: u64,
    },
}

#[derive(Args)]
struct RekeyArgs {
    /// Canonical compiled plan.v1 JSON.
    #[arg(long, default_value = "plan.v1.json")]
    plan: PathBuf,
    /// Repository root used to resolve canonical relative ciphertext paths.
    #[arg(long, default_value = ".")]
    repository_root: PathBuf,
    /// Administrator X25519 identity file. Required for rekeyed delivery;
    /// direct delivery stages canonical ciphertext without decrypting it.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Bound target ID.
    #[arg(long)]
    target: nix_seal_core::Id,
    /// Bound secret ID.
    #[arg(long)]
    secret: nix_seal_core::Id,
    /// Monotonic artifact generation.
    #[arg(long)]
    generation: u64,
    /// Separate Ed25519 artifact-approval key.
    #[arg(long)]
    signing_key: PathBuf,
    /// Optional approval expiry as Unix seconds.
    #[arg(long)]
    expires_at: Option<u64>,
    /// Override the standard XDG cache root.
    #[arg(long)]
    cache_root: Option<PathBuf>,
}

#[derive(Args)]
struct ProvisionArgs {
    /// Canonical compiled plan.v1 JSON.
    #[arg(long, default_value = "plan.v1.json")]
    plan: PathBuf,
    /// Repository root used to resolve canonical relative ciphertext paths.
    #[arg(long, default_value = ".")]
    repository_root: PathBuf,
    /// Administrator X25519 identity. Required only when this target has
    /// rekeyed secrets; direct artifacts are staged without decrypting them.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Bound target ID whose complete artifact set is provisioned.
    #[arg(long)]
    target: nix_seal_core::Id,
    /// Monotonic artifact generation applied to the complete target set.
    #[arg(long)]
    generation: u64,
    /// Separate Ed25519 artifact-approval key.
    #[arg(long)]
    signing_key: PathBuf,
    /// Optional approval expiry as Unix seconds.
    #[arg(long)]
    expires_at: Option<u64>,
    /// Override the standard XDG cache root.
    #[arg(long)]
    cache_root: Option<PathBuf>,
    /// Perform cache writes. Without this flag, validate and print a public
    /// target-wide provisioning plan without changing state.
    #[arg(long)]
    execute: bool,
}

#[derive(Args)]
struct GenerateArgs {
    /// Canonical compiled plan.v1 JSON.
    #[arg(long, default_value = "plan.v1.json")]
    plan: PathBuf,
    /// Generator ID selected from the plan.
    #[arg(long)]
    generator: nix_seal_core::Id,
    /// Repository root used to resolve plan-declared ciphertext destinations.
    #[arg(long, default_value = ".")]
    repository_root: PathBuf,
    /// Administrator/recovery identity authorized to verify each generated output.
    #[arg(long)]
    identity: PathBuf,
    /// Replace existing canonical ciphertext; omission is create-only.
    #[arg(long)]
    replace: bool,
    /// Private response file bound to one declared generator prompt as `ID=PATH`.
    #[arg(long = "prompt-file", value_name = "ID=PATH")]
    prompt_files: Vec<String>,
    /// Read missing prompt responses from the controlling terminal. This is
    /// explicit because interactive input is never appropriate for automation.
    #[arg(long)]
    interactive: bool,
}

#[derive(Args)]
struct ActivateArgs {
    /// Strict public activation specification; safe for the Nix store.
    #[arg(long)]
    spec: PathBuf,
    /// Target age identity path; must remain outside the Nix store.
    #[arg(long)]
    identity: PathBuf,
    /// Override the public runtime root, primarily for Home Manager runtime directories.
    #[arg(long)]
    runtime_root: Option<PathBuf>,
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Create a new plan-declared canonical ciphertext from stdin.
    Create(SecretWriteArgs),
    /// Import an existing value from stdin into a new plan-declared canonical ciphertext.
    Import(SecretWriteArgs),
    /// Edit through an explicit executable in a private ephemeral workspace.
    Edit(SecretEditArgs),
    /// Move canonical ciphertext into a private recoverable quarantine.
    Delete(SecretDeleteArgs),
    /// Decrypt to stdout. This is the only command that emits plaintext.
    Reveal(SecretWriteArgs),
    /// List plan-declared secret IDs without reading ciphertext.
    List {
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
        /// Show only expired or rotation-due secrets with calculated lifecycle metadata.
        #[arg(long)]
        due: bool,
    },
    /// Show public policy metadata for one secret.
    Show(SecretPlanArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SecretFormat {
    /// Validate stdin as a strict JSON document before encrypting its original bytes.
    Json,
    /// Validate stdin as a strict TOML document before encrypting its original bytes.
    Toml,
    /// Validate stdin as a bounded YAML document before encrypting its original bytes.
    Yaml,
    /// Validate stdin as a bounded dotenv collection before encrypting its original bytes.
    Dotenv,
}

#[derive(Clone, Args)]
struct SecretPlanArgs {
    /// Canonical compiled plan.v1 JSON.
    #[arg(long, default_value = "plan.v1.json")]
    plan: PathBuf,
    /// Secret ID selected from the plan.
    #[arg(long)]
    secret: nix_seal_core::Id,
}

#[derive(Clone, Args)]
struct SecretWriteArgs {
    #[command(flatten)]
    policy: SecretPlanArgs,
    /// Repository root used to resolve the plan's canonical ciphertext source.
    #[arg(long, default_value = ".")]
    repository_root: PathBuf,
    /// Administrator/recovery identity used to verify encryption or reveal plaintext.
    #[arg(long)]
    identity: PathBuf,
    /// Optional logical collection format to validate before encryption.
    #[arg(long, value_enum)]
    format: Option<SecretFormat>,
}

#[derive(Args)]
struct SecretEditArgs {
    #[command(flatten)]
    secret: SecretWriteArgs,
    /// Absolute editor executable; no shell is invoked.
    #[arg(long)]
    editor: PathBuf,
    /// Explicit editor argument placed before the private temporary filename.
    #[arg(long = "editor-arg")]
    editor_arguments: Vec<String>,
    /// Existing private/runtime directory used as the temporary workspace parent.
    #[arg(long)]
    workspace_root: Option<PathBuf>,
}

#[derive(Args)]
struct SecretDeleteArgs {
    #[command(flatten)]
    policy: SecretPlanArgs,
    /// Repository root used to resolve the plan's canonical ciphertext source.
    #[arg(long, default_value = ".")]
    repository_root: PathBuf,
    /// Repository-relative private tombstone directory.
    #[arg(long, default_value = ".nix-seal/trash/v1")]
    quarantine_root: PathBuf,
    /// Required non-interactive acknowledgement that policy must be updated separately.
    #[arg(long, required = true)]
    yes: bool,
}

#[derive(Subcommand)]
enum CacheCommand {
    /// Print cache location and object count.
    Status {
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Report or remove cache entries not authenticated by the current plan.
    Gc {
        /// Canonical compiled plan.v1 JSON used to authenticate retained artifacts.
        #[arg(long, default_value = "plan.v1.json")]
        plan: PathBuf,
        /// Repository root used to hash canonical ciphertext sources.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Override the standard XDG cache root.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Remove candidates after the authenticated dry-run calculation.
        #[arg(long)]
        execute: bool,
    },
    /// Create a new ciphertext-only cache exchange directory.
    Export {
        /// New destination directory. It must not already exist.
        #[arg(long)]
        destination: PathBuf,
        /// Override the standard XDG cache root.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Import a ciphertext-only cache exchange directory.
    Import {
        /// Existing exchange directory created by `cache export`.
        #[arg(long)]
        source: PathBuf,
        /// Override the standard XDG cache root.
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MigrateCommand {
    /// Inspect a public secretctl `secretIndex` JSON export and optionally write a new candidate plan.
    Secretctl {
        /// `nix eval --json .#secretIndex` output saved to a public JSON file.
        #[arg(long)]
        index: PathBuf,
        /// Write a new canonical public `plan.v1.json` candidate; refuses to overwrite.
        #[arg(long)]
        plan_output: Option<PathBuf>,
        /// Required target-system mapping for a candidate plan as `LEGACY_TARGET=SYSTEM`.
        #[arg(long = "target-system", value_name = "LEGACY_TARGET=SYSTEM")]
        target_systems: Vec<String>,
        /// Trusted approval signer for a candidate plan as `ID=PUBLIC_KEY`; repeat as needed.
        #[arg(long = "signer", value_name = "ID=PUBLIC_KEY")]
        signers: Vec<String>,
    },
    /// Inspect an agenix ciphertext tree without changing files or decrypting data.
    Agenix {
        /// Existing directory containing canonical `*.age` ciphertext files.
        #[arg(long, default_value = "secrets")]
        directory: PathBuf,
    },
    /// Inspect a ragenix ciphertext tree; its ciphertext layout is agenix-compatible.
    Ragenix {
        /// Existing directory containing canonical `*.age` ciphertext files.
        #[arg(long, default_value = "secrets")]
        directory: PathBuf,
    },
    /// Inspect a strict public agenix-rekey configuration export without decrypting data.
    AgenixRekey {
        /// JSON produced by `nixSeal.lib.agenixRekeyMigrationExport`.
        #[arg(long)]
        metadata: PathBuf,
    },
    /// Inspect structured SOPS JSON files without decrypting values or invoking SOPS.
    SopsJson {
        /// Existing directory containing SOPS-encrypted `*.json` files.
        #[arg(long, default_value = "secrets")]
        directory: PathBuf,
    },
    /// Stream-decrypt one SOPS document into a new native age ciphertext.
    Sops {
        /// Existing repository root; source and destination must remain below it.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Repository-relative SOPS-encrypted source document.
        #[arg(long)]
        source: PathBuf,
        /// Repository-relative native nix-seal ciphertext destination.
        #[arg(long)]
        destination: PathBuf,
        /// Absolute path to the external SOPS executable used only for this migration.
        #[arg(long)]
        sops: PathBuf,
        /// Optional private age identity file passed only to SOPS as `SOPS_AGE_KEY_FILE`.
        #[arg(long)]
        sops_age_key_file: Option<PathBuf>,
        /// Private identity authorized to verify the replacement ciphertext.
        #[arg(long)]
        identity: PathBuf,
        /// Explicit canonical age recipient for the replacement; repeat as needed.
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        /// Replace an existing destination; omission is create-only.
        #[arg(long)]
        replace: bool,
        /// Required acknowledgement that this performs the reported mutation.
        #[arg(long)]
        execute: bool,
    },
    /// Stream-decrypt one legacy PGP file into a new native age ciphertext.
    Pgp {
        /// Existing repository root; source and destination must remain below it.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Repository-relative PGP-encrypted source document.
        #[arg(long)]
        source: PathBuf,
        /// Repository-relative native nix-seal ciphertext destination.
        #[arg(long)]
        destination: PathBuf,
        /// Absolute path to `GnuPG`, used only for this migration.
        #[arg(long)]
        gpg: PathBuf,
        /// Private `GnuPG` home directory containing the migration identity.
        #[arg(long)]
        gnupg_home: PathBuf,
        /// Private age identity authorized to verify the replacement ciphertext.
        #[arg(long)]
        identity: PathBuf,
        /// Explicit canonical age recipient for the replacement; repeat as needed.
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        /// Replace an existing destination; omission is create-only.
        #[arg(long)]
        replace: bool,
        /// Required acknowledgement that this performs the reported mutation.
        #[arg(long)]
        execute: bool,
    },
    /// Inspect Clan Vars per-machine output leaves without reading their values.
    ClanVars {
        /// Clan's `vars/per-machine` directory.
        #[arg(long, default_value = "vars/per-machine")]
        directory: PathBuf,
    },
    /// Inspect Clan Facts public leaves without reading their values.
    ClanFacts {
        /// Clan `machines` directory containing per-machine `facts` directories.
        #[arg(long, default_value = "machines")]
        directory: PathBuf,
    },
    /// Stream one legacy age ciphertext into explicit new recipients.
    Ciphertext {
        /// Existing repository root; source and destination must remain below it.
        #[arg(long, default_value = ".")]
        repository_root: PathBuf,
        /// Repository-relative legacy age ciphertext source.
        #[arg(long)]
        source: PathBuf,
        /// Repository-relative native nix-seal ciphertext destination.
        #[arg(long)]
        destination: PathBuf,
        /// Private identity authorized to decrypt the legacy source and verify the result.
        #[arg(long)]
        identity: PathBuf,
        /// Explicit canonical age recipient for the replacement; repeat as needed.
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        /// Replace an existing destination; omission is create-only.
        #[arg(long)]
        replace: bool,
        /// Required acknowledgement that this performs the reported mutation.
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Nushell,
}

#[derive(Clone, Copy, ValueEnum)]
enum SchemaKind {
    Plan,
    TargetPolicy,
    SecretRecipients,
    Activation,
}

fn main() {
    if let Err(error) = harden_process() {
        eprintln!("nix-seal: warning: could not fully disable process core dumps: {error}");
    }
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("nix-seal: {error:#}");
        std::process::exit(exit_category(&error));
    }
}

/// Reduces process-level plaintext exposure before command-line parsing reads
/// any private identity or prompt material. This is defense in depth only:
/// operating-system policy and privileged debuggers remain outside its scope.
#[cfg(unix)]
fn harden_process() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(std::io::Error::from)?;
    let existing = rustix::process::getrlimit(rustix::process::Resource::Core);
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        disabled_core_limit(existing),
    )
    .map_err(std::io::Error::from)
}

/// Preserves the administrator-controlled hard limit while disabling new core
/// dumps for the current process.
#[cfg(unix)]
const fn disabled_core_limit(existing: rustix::process::Rlimit) -> rustix::process::Rlimit {
    rustix::process::Rlimit {
        current: Some(0),
        maximum: existing.maximum,
    }
}

#[cfg(not(unix))]
fn harden_process() -> std::io::Result<()> {
    Ok(())
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { config } => run_init(&config, cli.json)?,
        Command::Plan {
            toml,
            nix_plan,
            target,
            output,
        } => run_plan(
            &toml,
            nix_plan.as_deref(),
            target,
            output.as_deref(),
            cli.json,
        )?,
        Command::Check {
            toml,
            nix_plan,
            deep,
            repository_root,
        } => run_check(&toml, nix_plan.as_deref(), deep, &repository_root, cli.json)?,
        Command::Doctor {
            plan,
            repository_root,
            cache_root,
        } => run_doctor(&plan, &repository_root, cache_root, cli.json)?,
        Command::Key(command) => run_key(command, cli.json)?,
        Command::Identity(command) => run_identity(command, cli.json)?,
        Command::Group(command) => run_group(command, cli.json)?,
        Command::Artifact(command) => run_artifact(command, cli.json)?,
        Command::Rekey(arguments) => run_rekey(arguments, cli.json)?,
        Command::Provision(arguments) => run_provision(arguments, cli.json)?,
        Command::Generate(arguments) => run_generate(&arguments, cli.json)?,
        Command::Activate(arguments) => run_activate(&arguments, cli.json)?,
        Command::PluginWorker => run_plugin_worker()?,
        Command::Secret(command) => run_secret(command, cli.json)?,
        Command::Rotate(arguments) => run_secret_write(
            &arguments,
            nix_seal_authoring::WriteMode::Replace,
            cli.json,
            "rotated",
        )?,
        Command::Recipients(arguments) => run_recipients(&arguments, cli.json)?,
        Command::Schema { kind } => run_schema(kind)?,
        Command::Template(TemplateCommand::Check { plan }) => run_template_check(&plan, cli.json)?,
        Command::Template(TemplateCommand::Render {
            plan,
            template,
            repository_root,
            identity,
            output,
            replace,
        }) => run_template_render(
            &plan,
            &template,
            &repository_root,
            &identity,
            &output,
            replace,
            cli.json,
        )?,
        Command::Completions { shell } => completions(shell),
        Command::Migrate(command) => run_migrate(command, cli.json)?,
        Command::Cache(CacheCommand::Status { root }) => cache_status(root, cli.json)?,
        Command::Cache(CacheCommand::Gc {
            plan,
            repository_root,
            root,
            execute,
        }) => cache_gc(&plan, &repository_root, root, execute, cli.json)?,
        Command::Cache(CacheCommand::Export { destination, root }) => {
            cache_export(&destination, root, cli.json)?;
        }
        Command::Cache(CacheCommand::Import { source, root }) => {
            cache_import(&source, root, cli.json)?;
        }
    }
    Ok(())
}

fn exit_category(error: &anyhow::Error) -> i32 {
    for cause in error.chain() {
        if cause.is::<nix_seal_policy::PolicyError>() {
            return 3;
        }
        if cause.is::<nix_seal_crypto::CryptoError>()
            || cause.is::<nix_seal_manifest::ManifestError>()
        {
            return 4;
        }
        if cause.is::<nix_seal_cache::CacheError>()
            || cause.is::<nix_seal_authoring::AuthoringError>()
        {
            return 5;
        }
        if cause.is::<nix_seal_runtime::RuntimeError>() {
            return 6;
        }
    }
    1
}

fn run_init(config: &Path, json: bool) -> Result<()> {
    if config
        .extension()
        .is_none_or(|extension| extension != "toml")
    {
        bail!("initial plan path must use a .toml extension");
    }
    let parent = config.parent().context("initial plan path has no parent")?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("initial plan parent {} does not exist", parent.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("initial plan parent must be an existing non-symlink directory");
    }
    let plan = nix_seal_core::PlanV1::default();
    nix_seal_policy::validate(&plan)?;
    let text = toml::to_string_pretty(&plan).context("could not encode initial public plan")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(config)
        .with_context(|| format!("refusing to overwrite {}", config.display()))?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("initial plan was written but directory durability could not be confirmed")?;
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","initialized":true,"planPath":config})
        );
    } else {
        println!("initialized public plan at {}", config.display());
    }
    Ok(())
}

fn run_plan(
    toml: &Path,
    nix_plan: Option<&Path>,
    target: Option<nix_seal_core::Id>,
    output: Option<&Path>,
    json: bool,
) -> Result<()> {
    let plan = load_plan(toml, nix_plan)?;
    nix_seal_policy::validate(&plan)?;
    validate_plan_identity_material(&plan)?;
    let plan_hash = nix_seal_policy::plan_hash(&plan)?;
    if let Some(target) = target {
        let policy = nix_seal_policy::target_policy(&plan, &target)?;
        let policy_hash = nix_seal_policy::target_policy_hash(&policy)?;
        let canonical = nix_seal_policy::canonical_target_policy_json(&policy)?;
        eprintln!("plan hash: {plan_hash}");
        eprintln!("target policy hash: {policy_hash}");
        if json {
            if let Some(output) = output {
                emit_canonical_public_json(Some(output), &canonical)?;
            }
            println!(
                "{}",
                serde_json::json!({
                    "schema":"nix-seal.output.v1",
                    "planHash":plan_hash,
                    "targetPolicyHash":policy_hash,
                    "target":target,
                    "targetPolicy":output.is_none().then_some(&policy),
                    "output":output
                })
            );
        } else {
            emit_canonical_public_json(output, &canonical)?;
        }
    } else {
        let canonical = nix_seal_policy::canonical_json(&plan)?;
        eprintln!("plan hash: {plan_hash}");
        if json {
            if let Some(output) = output {
                emit_canonical_public_json(Some(output), &canonical)?;
            }
            println!(
                "{}",
                serde_json::json!({
                    "schema":"nix-seal.output.v1",
                    "planHash":plan_hash,
                    "plan":output.is_none().then_some(&plan),
                    "output":output
                })
            );
        } else {
            emit_canonical_public_json(output, &canonical)?;
        }
    }
    Ok(())
}

fn run_check(
    toml: &Path,
    nix_plan: Option<&Path>,
    deep: bool,
    repository_root: &Path,
    json: bool,
) -> Result<()> {
    let plan = load_plan(toml, nix_plan)?;
    nix_seal_policy::validate(&plan)?;
    validate_plan_identity_material(&plan)?;
    validate_plan_templates(&plan, toml)?;
    let hash = nix_seal_policy::plan_hash(&plan)?;
    if deep {
        deep_check_plan(&plan, repository_root)?;
    }
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","ok":true,"deep":deep,"planHash":hash})
        );
    } else {
        println!(
            "plan {hash} is valid{}",
            if deep {
                " (deep checks are incremental)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn run_doctor(
    plan_path: &Path,
    repository_root: &Path,
    cache_root: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let plan = read_plan_bounded(plan_path)?;
    validate_plan_templates(&plan, plan_path)?;
    deep_check_plan(&plan, repository_root)?;
    let plan_hash = nix_seal_policy::plan_hash(&plan)?;
    let cache = nix_seal_cache::Cache::open(cache_root.unwrap_or_else(default_cache_root))?;
    let inventory = cache.inventory()?;
    let retention = authenticated_gc_retention(&cache, &plan, repository_root)?;
    let authenticated_artifacts = u64::try_from(retention.artifact_keys.len())
        .context("authenticated artifact count exceeds supported range")?;
    let stale_artifacts = inventory
        .artifact_count
        .saturating_sub(authenticated_artifacts);
    let mut warnings = Vec::new();
    if cfg!(target_os = "macos") {
        warnings.push(
            "macOS runtime directories are not guaranteed to be memory-backed; review the selected Home Manager runtime directory"
                .to_owned(),
        );
    }
    if !cfg!(target_os = "linux") {
        warnings.push(
            "systemd credentials are unavailable on this platform; use ordinary restrictive runtime files"
                .to_owned(),
        );
    }
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        warnings.push(
            "XDG_RUNTIME_DIR is unset; standalone Home Manager activation needs an explicit secure runtime directory"
                .to_owned(),
        );
    }
    if plan
        .secrets
        .values()
        .any(|secret| matches!(secret.delivery, nix_seal_core::DeliveryMode::Direct))
    {
        warnings.push(
            "the plan contains advanced direct-delivery secrets; matching target keys can decrypt current and historical canonical ciphertext"
                .to_owned(),
        );
    }
    if stale_artifacts > 0 {
        warnings.push(format!(
            "{stale_artifacts} cache artifact(s) do not match the current authenticated plan and are garbage-collection candidates"
        ));
    }
    if retention.unavailable_sources > 0 {
        warnings.push(format!(
            "{} canonical ciphertext source(s) were unavailable while authenticating cache artifacts",
            retention.unavailable_sources
        ));
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.doctor.v1",
                "ok":true,
                "planHash":plan_hash,
                "secrets":plan.secrets.len(),
                "targets":plan.targets.len(),
                "cache":{
                    "root":cache.root(),
                    "objects":inventory.object_count,
                    "artifacts":inventory.artifact_count,
                    "authenticatedArtifacts":authenticated_artifacts,
                    "staleArtifacts":stale_artifacts,
                    "unavailableSources":retention.unavailable_sources
                },
                "warnings":warnings
            })
        );
    } else {
        println!(
            "doctor: plan {plan_hash} is deeply valid; {} secrets, {} targets; cache has {} objects, {} authenticated artifacts, and {} stale artifacts",
            plan.secrets.len(),
            plan.targets.len(),
            inventory.object_count,
            authenticated_artifacts,
            stale_artifacts,
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

fn run_schema(kind: SchemaKind) -> Result<()> {
    println!(
        "{}",
        match kind {
            SchemaKind::Plan => nix_seal_policy::json_schema()?,
            SchemaKind::TargetPolicy => nix_seal_policy::target_policy_json_schema()?,
            SchemaKind::SecretRecipients => nix_seal_policy::secret_recipients_json_schema()?,
            SchemaKind::Activation => nix_seal_runtime::activation_json_schema()?,
        }
    );
    Ok(())
}

fn run_template_check(plan_path: &Path, json: bool) -> Result<()> {
    let plan = read_plan_bounded(plan_path)?;
    validate_plan_templates(&plan, plan_path)?;
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","ok":true,"templates":plan.templates.len()})
        );
    } else {
        println!("{} public templates are valid", plan.templates.len());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_template_render(
    plan_path: &Path,
    template_id: &nix_seal_core::Id,
    repository_root: &Path,
    identity_path: &Path,
    output: &Path,
    replace: bool,
    json: bool,
) -> Result<()> {
    let plan = read_plan_bounded(plan_path)?;
    let template = plan
        .templates
        .get(template_id)
        .with_context(|| format!("template {template_id} is absent from plan"))?;
    let source = read_template_source(template_id, template, plan_path)?;
    let placeholders = runtime_template_placeholders(template);
    nix_seal_runtime::validate_template_source(&source, &placeholders)
        .with_context(|| format!("public template source for {template_id} is invalid"))?;

    let identity = read_identity(identity_path)?;
    let mut secret_paths = BTreeMap::new();
    for placeholder in template.placeholders.values() {
        let recipients = nix_seal_policy::secret_recipients(&plan, &placeholder.secret)?;
        if !recipients
            .recipients
            .values()
            .any(|recipient| nix_seal_crypto::identity_matches_recipient(&identity, recipient))
        {
            bail!(
                "render identity is not authorized by canonical recipient policy for {}",
                placeholder.secret
            );
        }
        let secret = plan
            .secrets
            .get(&placeholder.secret)
            .context("template placeholder secret is absent from plan")?;
        secret_paths
            .entry(placeholder.secret.clone())
            .or_insert(existing_secret_path(repository_root, &secret.source)?);
    }

    let (destination, parent) = prepare_private_template_destination(output, replace)?;
    let mut staged = tempfile::NamedTempFile::new_in(&parent)
        .context("could not create a private template output transaction")?;
    set_private_template_output(staged.as_file())?;
    nix_seal_runtime::render_template_into(
        &source,
        &placeholders,
        staged.as_file_mut(),
        |placeholder, writer| {
            let path = secret_paths
                .get(&placeholder.secret_id)
                .ok_or(nix_seal_runtime::RuntimeError::InvalidSpec)?;
            let ciphertext = open_public_ciphertext(path)
                .map_err(|_| nix_seal_runtime::RuntimeError::InvalidSpec)?;
            nix_seal_crypto::decrypt(ciphertext, writer, &identity)?;
            Ok(())
        },
    )?;
    staged
        .as_file()
        .sync_all()
        .context("could not durably stage private template output")?;
    if replace {
        staged
            .persist(&destination)
            .map_err(|error| error.error)
            .context("could not atomically replace private template output")?;
    } else {
        staged
            .persist_noclobber(&destination)
            .map_err(|error| error.error)
            .context("refusing to overwrite private template output")?;
    }
    fs::File::open(&parent)
        .and_then(|directory| directory.sync_all())
        .context(
            "template output changed atomically but directory durability could not be confirmed",
        )?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "rendered":true,
                "templateId":template_id,
                "output":output
            })
        );
    } else {
        println!("rendered template {template_id} to {}", output.display());
    }
    Ok(())
}

/// Validates bounded public template sources relative to a plan location.
///
/// Sources are intentionally public, but strict validation still belongs in
/// routine preflight: an undeclared, missing, or malformed placeholder must
/// fail before an activation attempt can decrypt any dependent secret.
fn validate_plan_templates(plan: &nix_seal_core::PlanV1, plan_path: &Path) -> Result<()> {
    for (template_id, template) in &plan.templates {
        let bytes = read_template_source(template_id, template, plan_path)?;
        let placeholders = runtime_template_placeholders(template);
        nix_seal_runtime::validate_template_source(&bytes, &placeholders)
            .with_context(|| format!("public template source for {template_id} is invalid"))?;
    }
    Ok(())
}

fn read_template_source(
    template_id: &nix_seal_core::Id,
    template: &nix_seal_core::Template,
    plan_path: &Path,
) -> Result<Vec<u8>> {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let parent = plan_path
        .parent()
        .context("compiled plan path has no parent")?;
    let source = Path::new(&template.source);
    let source = if source.is_absolute() {
        source.to_owned()
    } else {
        parent.join(source)
    };
    let mut bytes = Vec::new();
    fs::File::open(&source)
        .with_context(|| format!("could not open public template source for {template_id}"))?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("public template source for {template_id} exceeds the 2 MiB safety limit");
    }
    Ok(bytes)
}

fn runtime_template_placeholders(
    template: &nix_seal_core::Template,
) -> BTreeMap<String, nix_seal_runtime::TemplatePlaceholderSpecV1> {
    template
        .placeholders
        .iter()
        .map(|(name, placeholder)| {
            let encoding = match placeholder.encoding {
                nix_seal_core::TemplateEncoding::Utf8 => nix_seal_runtime::TemplateEncodingV1::Utf8,
                nix_seal_core::TemplateEncoding::Base64 => {
                    nix_seal_runtime::TemplateEncodingV1::Base64
                }
                nix_seal_core::TemplateEncoding::Hex => nix_seal_runtime::TemplateEncodingV1::Hex,
            };
            (
                name.clone(),
                nix_seal_runtime::TemplatePlaceholderSpecV1 {
                    secret_id: placeholder.secret.clone(),
                    encoding,
                },
            )
        })
        .collect()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretctlIndexV1 {
    version: u64,
    groups: BTreeMap<String, Vec<String>>,
    targets: BTreeMap<String, SecretctlTargetV1>,
    secrets: BTreeMap<String, SecretctlSecretV1>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretctlTargetV1 {
    #[serde(rename = "type")]
    target_type: String,
    groups: Vec<String>,
    public_key: String,
    recipients: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretctlSecretV1 {
    id: String,
    group: String,
    scope: String,
    selector: Option<String>,
    agenix_name: String,
    file: String,
    recipients: Vec<String>,
    consumers: Vec<String>,
}

struct SecretctlMigrationReport {
    groups: Vec<serde_json::Value>,
    secrets: Vec<serde_json::Value>,
    targets: Vec<serde_json::Value>,
    ssh_recipient_count: usize,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgenixRekeyExportV1 {
    schema: String,
    target: AgenixRekeyTargetV1,
    master_recipients: Vec<String>,
    secrets: BTreeMap<String, AgenixRekeySecretV1>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgenixRekeyTargetV1 {
    id: String,
    kind: String,
    system: String,
    recipient: String,
    storage_mode: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgenixRekeySecretV1 {
    rekey_file: String,
    #[serde(default)]
    intermediary: bool,
}

struct ValidatedSecretctlGroups {
    groups: BTreeMap<String, BTreeSet<String>>,
    ssh_recipients: BTreeSet<String>,
}

struct ValidatedSecretctlTargets {
    recipients: BTreeMap<String, String>,
    mappings: Vec<serde_json::Value>,
    ssh_recipients: BTreeSet<String>,
}

struct ValidatedSecretctlSecrets {
    mappings: Vec<serde_json::Value>,
    ssh_recipients: BTreeSet<String>,
}

fn run_migrate(command: MigrateCommand, json: bool) -> Result<()> {
    match command {
        MigrateCommand::Secretctl {
            index,
            plan_output,
            target_systems,
            signers,
        } => migrate_secretctl(
            &index,
            plan_output.as_deref(),
            &target_systems,
            &signers,
            json,
        ),
        MigrateCommand::Agenix { directory } => migrate_agenix_tree(&directory, "agenix", json),
        MigrateCommand::Ragenix { directory } => migrate_agenix_tree(&directory, "ragenix", json),
        MigrateCommand::AgenixRekey { metadata } => migrate_agenix_rekey_export(&metadata, json),
        MigrateCommand::SopsJson { directory } => migrate_sops_json_tree(&directory, json),
        MigrateCommand::Sops {
            repository_root,
            source,
            destination,
            sops,
            sops_age_key_file,
            identity,
            recipients,
            replace,
            execute,
        } => migrate_sops_document(
            &repository_root,
            &source,
            &destination,
            &sops,
            sops_age_key_file.as_deref(),
            &identity,
            &recipients,
            replace,
            execute,
            json,
        ),
        MigrateCommand::Pgp {
            repository_root,
            source,
            destination,
            gpg,
            gnupg_home,
            identity,
            recipients,
            replace,
            execute,
        } => migrate_pgp_document(
            &repository_root,
            &source,
            &destination,
            &gpg,
            &gnupg_home,
            &identity,
            &recipients,
            replace,
            execute,
            json,
        ),
        MigrateCommand::ClanVars { directory } => migrate_clan_vars_tree(&directory, json),
        MigrateCommand::ClanFacts { directory } => migrate_clan_facts_tree(&directory, json),
        MigrateCommand::Ciphertext {
            repository_root,
            source,
            destination,
            identity,
            recipients,
            replace,
            execute,
        } => migrate_ciphertext(
            &repository_root,
            &source,
            &destination,
            &identity,
            &recipients,
            replace,
            execute,
            json,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn migrate_ciphertext(
    repository_root: &Path,
    source: &Path,
    destination: &Path,
    identity_path: &Path,
    recipients: &[String],
    replace: bool,
    execute: bool,
    json: bool,
) -> Result<()> {
    if recipients.is_empty() {
        bail!("migration requires at least one replacement recipient");
    }
    if !execute {
        let report = serde_json::json!({
            "schema":"nix-seal.migration-ciphertext.v1",
            "dryRun":true,
            "source":source,
            "destination":destination,
            "recipientCount":recipients.len(),
            "replace":replace,
        });
        if json {
            println!("{report}");
        } else {
            println!(
                "ciphertext migration dry-run: {} -> {}",
                source.display(),
                destination.display()
            );
            eprintln!(
                "warning: rerun with --execute only after reviewing recipients and destination"
            );
        }
        return Ok(());
    }
    let identity = read_identity(identity_path)?;
    let mode = if replace {
        nix_seal_authoring::WriteMode::Replace
    } else {
        nix_seal_authoring::WriteMode::Create
    };
    let result = nix_seal_authoring::rekey_secret(
        repository_root,
        source,
        destination,
        recipients,
        &identity,
        mode,
    )?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-ciphertext.v1",
                "dryRun":false,
                "source":source,
                "destination":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "plaintextBytes":result.plaintext_bytes,
            })
        );
    } else {
        println!(
            "ciphertext migrated {} -> {}",
            source.display(),
            result.path.display()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn migrate_sops_document(
    repository_root: &Path,
    source: &Path,
    destination: &Path,
    sops: &Path,
    sops_age_key_file: Option<&Path>,
    identity_path: &Path,
    recipients: &[String],
    replace: bool,
    execute: bool,
    json: bool,
) -> Result<()> {
    if recipients.is_empty() {
        bail!("SOPS migration requires at least one replacement recipient");
    }
    if !execute {
        let report = serde_json::json!({
            "schema":"nix-seal.migration-sops.v1",
            "dryRun":true,
            "source":source,
            "destination":destination,
            "sops":sops,
            "recipientCount":recipients.len(),
            "replace":replace,
            "usesExplicitAgeKeyFile":sops_age_key_file.is_some(),
        });
        if json {
            println!("{report}");
        } else {
            println!(
                "SOPS migration dry-run: {} -> {}",
                source.display(),
                destination.display()
            );
            eprintln!(
                "warning: rerun with --execute only after reviewing the source, recipients, and destination"
            );
        }
        return Ok(());
    }

    let source = resolve_migration_regular_file(repository_root, source)?;
    let sops = resolve_external_executable(sops)?;
    let sops_age_key_file = sops_age_key_file
        .map(|path| {
            open_private_identity(path)?;
            path.canonicalize()
                .context("could not canonicalize private SOPS age identity")
        })
        .transpose()?;
    let identity = read_identity(identity_path)?;
    let mode = if replace {
        nix_seal_authoring::WriteMode::Replace
    } else {
        nix_seal_authoring::WriteMode::Create
    };

    let mut command = ProcessCommand::new(sops);
    command
        .arg("--decrypt")
        .arg(&source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    isolate_child_process_group(&mut command);
    if let Some(path) = &sops_age_key_file {
        command.env("SOPS_AGE_KEY_FILE", path);
    }
    let mut child = command
        .spawn()
        .context("could not start the explicit SOPS migration executable")?;
    let stdout = child
        .stdout
        .take()
        .context("SOPS migration stdout was unavailable")?;
    let child = Arc::new(Mutex::new(child));
    let (complete_tx, complete_rx) = mpsc::channel();
    let watchdog_child = Arc::clone(&child);
    let watchdog = thread::spawn(move || {
        if complete_rx
            .recv_timeout(EXTERNAL_MIGRATION_TIMEOUT)
            .is_err()
            && let Ok(mut child) = watchdog_child.lock()
            && child.try_wait().ok().flatten().is_none()
        {
            terminate_child_process_tree(&mut child);
        }
    });
    let result = nix_seal_authoring::write_secret_checked(
        repository_root,
        destination,
        BoundedReader::new(stdout, EXTERNAL_MIGRATION_MAX_PLAINTEXT_BYTES),
        recipients,
        &identity,
        mode,
        || wait_for_external_migration(&child, EXTERNAL_MIGRATION_TIMEOUT),
    );
    let _ = complete_tx.send(());
    let _ = watchdog.join();
    if result.is_err() {
        terminate_external_migration(&child);
    }
    let result = result?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-sops.v1",
                "dryRun":false,
                "source":source,
                "destination":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "plaintextBytes":result.plaintext_bytes,
                "usedExplicitAgeKeyFile":sops_age_key_file.is_some(),
            })
        );
    } else {
        println!(
            "SOPS document migrated {} -> {}",
            source.display(),
            result.path.display()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn migrate_pgp_document(
    repository_root: &Path,
    source: &Path,
    destination: &Path,
    gpg: &Path,
    gnupg_home: &Path,
    identity_path: &Path,
    recipients: &[String],
    replace: bool,
    execute: bool,
    json: bool,
) -> Result<()> {
    if recipients.is_empty() {
        bail!("PGP migration requires at least one replacement recipient");
    }
    if !execute {
        let report = serde_json::json!({
            "schema":"nix-seal.migration-pgp.v1",
            "dryRun":true,
            "source":source,
            "destination":destination,
            "gpg":gpg,
            "gnupgHome":gnupg_home,
            "recipientCount":recipients.len(),
            "replace":replace,
        });
        if json {
            println!("{report}");
        } else {
            println!(
                "PGP migration dry-run: {} -> {}",
                source.display(),
                destination.display()
            );
            eprintln!(
                "warning: rerun with --execute only after reviewing the source, recipients, destination, and private GnuPG home"
            );
        }
        return Ok(());
    }

    let source = resolve_migration_regular_file(repository_root, source)?;
    let gpg = resolve_external_executable(gpg)?;
    let gnupg_home = resolve_private_gnupg_home(gnupg_home)?;
    let identity = read_identity(identity_path)?;
    let mode = if replace {
        nix_seal_authoring::WriteMode::Replace
    } else {
        nix_seal_authoring::WriteMode::Create
    };

    let mut command = pgp_decrypt_command(&gpg, &gnupg_home, &source);
    isolate_child_process_group(&mut command);
    let mut child = command
        .spawn()
        .context("could not start the explicit GnuPG migration executable")?;
    let stdout = child
        .stdout
        .take()
        .context("GnuPG migration stdout was unavailable")?;
    let child = Arc::new(Mutex::new(child));
    let (complete_tx, complete_rx) = mpsc::channel();
    let watchdog_child = Arc::clone(&child);
    let watchdog = thread::spawn(move || {
        if complete_rx
            .recv_timeout(EXTERNAL_MIGRATION_TIMEOUT)
            .is_err()
            && let Ok(mut child) = watchdog_child.lock()
            && child.try_wait().ok().flatten().is_none()
        {
            terminate_child_process_tree(&mut child);
        }
    });
    let result = nix_seal_authoring::write_secret_checked(
        repository_root,
        destination,
        BoundedReader::new(stdout, EXTERNAL_MIGRATION_MAX_PLAINTEXT_BYTES),
        recipients,
        &identity,
        mode,
        || wait_for_external_migration(&child, EXTERNAL_MIGRATION_TIMEOUT),
    );
    let _ = complete_tx.send(());
    let _ = watchdog.join();
    if result.is_err() {
        terminate_external_migration(&child);
    }
    let result = result?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-pgp.v1",
                "dryRun":false,
                "source":source,
                "destination":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "plaintextBytes":result.plaintext_bytes,
            })
        );
    } else {
        println!(
            "PGP document migrated {} -> {}",
            source.display(),
            result.path.display()
        );
    }
    Ok(())
}

fn pgp_decrypt_command(gpg: &Path, gnupg_home: &Path, source: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new(gpg);
    command
        .arg("--no-options")
        .arg("--batch")
        .arg("--quiet")
        .arg("--no-tty")
        .arg("--no-auto-key-locate")
        .arg("--no-auto-key-import")
        .arg("--no-auto-key-retrieve")
        .arg("--decrypt")
        .arg(source)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("GNUPGHOME", gnupg_home)
        .env("LC_ALL", "C");
    command
}

fn resolve_private_gnupg_home(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("GnuPG home must be an absolute private directory path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect GnuPG home {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("GnuPG home must be a non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("GnuPG home has unsafe ownership or permissions");
        }
    }
    path.canonicalize()
        .context("could not canonicalize private GnuPG home")
}

fn wait_for_external_migration(
    child: &Arc<Mutex<Child>>,
    timeout: Duration,
) -> Result<(), nix_seal_authoring::AuthoringError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = child
            .lock()
            .map_err(|_| nix_seal_authoring::AuthoringError::ExternalInput)?
            .try_wait()
            .map_err(nix_seal_authoring::AuthoringError::Io)?;
        if let Some(status) = status {
            return if status.success() {
                Ok(())
            } else {
                Err(nix_seal_authoring::AuthoringError::ExternalInput)
            };
        }
        if Instant::now() >= deadline {
            terminate_external_migration(child);
            return Err(nix_seal_authoring::AuthoringError::ExternalInput);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_external_migration(child: &Arc<Mutex<Child>>) {
    if let Ok(mut child) = child.lock() {
        terminate_child_process_tree(&mut child);
    }
}

/// Starts an explicitly declared external executable in its own process group.
///
/// A generator or migration helper is an untrusted process boundary. Keeping
/// descendants in a private group lets the timeout path terminate the complete
/// tree instead of leaving a helper behind with access to staged plaintext.
#[cfg(unix)]
fn isolate_child_process_group(command: &mut ProcessCommand) {
    use std::os::unix::process::CommandExt;

    // `process_group(0)` asks the child to become the leader of a new group
    // whose ID is its own PID. This is a safe std API and does not require a
    // pre-exec hook (which would require an unsafe block).
    command.process_group(0);
}

#[cfg(not(unix))]
fn isolate_child_process_group(_command: &mut ProcessCommand) {}

fn terminate_child_process_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        // Avoid signalling a reused process-group ID after the child already
        // exited. `try_wait` also makes the subsequent wait deterministic.
        let running = child.try_wait().ok().flatten().is_none();
        if running && let Some(pid) = rustix::process::Pid::from_raw(child.id().cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn resolve_migration_regular_file(repository_root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("migration source must be a non-empty repository-relative normal path");
    }
    let root_metadata = fs::symlink_metadata(repository_root)
        .context("could not inspect migration repository root")?;
    if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
        bail!("migration repository root must be a non-symlink directory");
    }
    let root = repository_root
        .canonicalize()
        .context("could not canonicalize migration repository root")?;
    let mut current = root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("migration source must be a normal repository-relative path");
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("could not inspect migration source {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("migration source path contains a symbolic link");
        }
    }
    let metadata = fs::symlink_metadata(&current)?;
    if !metadata.file_type().is_file() {
        bail!("migration source must be a regular file");
    }
    Ok(current)
}

fn resolve_external_executable(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("external migration executable must be an absolute path");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect external executable {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("external migration executable must be a non-symlink regular file");
    }
    path.canonicalize()
        .context("could not canonicalize external migration executable")
}

fn migrate_agenix_tree(directory: &Path, source: &str, json: bool) -> Result<()> {
    let supplied_metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("could not inspect {source} ciphertext directory"))?;
    if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
        bail!("{source} ciphertext root must be a non-symlink directory");
    }
    let root = directory
        .canonicalize()
        .with_context(|| format!("could not resolve {source} ciphertext directory"))?;
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.file_type().is_dir() {
        bail!("{source} ciphertext root is not a directory");
    }
    let mut ciphertexts = Vec::new();
    scan_agenix_ciphertexts(&root, &root, &mut ciphertexts)?;
    if ciphertexts.is_empty() {
        bail!("{source} ciphertext directory contains no .age files");
    }
    let mappings = ciphertexts
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .context("agenix ciphertext escaped its canonical root")?;
            let stem = relative.with_extension("");
            let legacy_id = stem
                .to_str()
                .context("agenix ciphertext path is not UTF-8")?;
            Ok(serde_json::json!({
                "legacyId":legacy_id,
                "nixSealId":migrated_id(&format!("{source}/{legacy_id}"))?,
                "source":relative,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = vec![
        "dry run only: no ciphertext, configuration, or source manager was changed",
        "ciphertext headers were validated but recipient policy is not encoded in agenix ciphertext paths; supply an explicit nix-seal recipient and target mapping before import",
        "only regular .age files were accepted; symlinks and non-regular entries are rejected",
    ];
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":source,
                "dryRun":true,
                "secrets":mappings,
                "warnings":warnings
            })
        );
    } else {
        println!("{source} dry-run: {} ciphertexts mapped", mappings.len());
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        for mapping in mappings {
            println!(
                "{} -> {} ({})",
                mapping["legacyId"].as_str().unwrap_or("unknown"),
                mapping["nixSealId"].as_str().unwrap_or("unknown"),
                mapping["source"].as_str().unwrap_or("unknown"),
            );
        }
    }
    Ok(())
}

fn migrate_agenix_rekey_export(metadata: &Path, json: bool) -> Result<()> {
    let input = open_public_ciphertext(metadata)
        .context("agenix-rekey metadata must be a regular non-symlink file")?;
    let export: AgenixRekeyExportV1 = serde_json::from_reader(input)
        .context("agenix-rekey metadata is not a valid strict JSON export")?;
    if export.schema != "nix-seal.agenix-rekey-export.v1"
        || export.secrets.is_empty()
        || export.secrets.len() > 10_000
        || export.master_recipients.is_empty()
        || export.master_recipients.len() > 256
    {
        bail!("agenix-rekey metadata has an unsupported schema or unsafe collection size");
    }
    if !matches!(
        export.target.kind.as_str(),
        "nixos" | "darwin" | "home-manager"
    ) || !matches!(
        export.target.system.as_str(),
        "x86_64-linux" | "aarch64-linux" | "x86_64-darwin" | "aarch64-darwin"
    ) || !matches!(export.target.storage_mode.as_str(), "local" | "derivation")
    {
        bail!("agenix-rekey target has unsupported kind, system, or storage mode");
    }
    let target_id = migrated_id(&export.target.id)?;
    let target_recipient = nix_seal_crypto::normalize_recipient(&export.target.recipient)
        .context("agenix-rekey target has an unsupported recipient")?;
    let masters = export
        .master_recipients
        .iter()
        .map(|recipient| {
            nix_seal_crypto::normalize_recipient(recipient)
                .context("agenix-rekey master recipient is unsupported")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if masters.len() != export.master_recipients.len() {
        bail!("agenix-rekey metadata contains duplicate master recipients");
    }
    let mut mappings = Vec::with_capacity(export.secrets.len());
    for (legacy_id, secret) in export.secrets {
        let source = validate_agenix_rekey_source(&secret.rekey_file)?;
        mappings.push(serde_json::json!({
            "legacyId":legacy_id,
            "nixSealId":migrated_id(&legacy_id)?,
            "source":source,
            "consumers":if secret.intermediary { Vec::<String>::new() } else { vec![target_id.to_string()] },
            "repositoryOnly":secret.intermediary,
        }));
    }
    let warnings = vec![
        "dry run only: no ciphertext, configuration, cache, or source manager was changed",
        "the export establishes rekeyed administrator-to-target semantics, but runtime ownership, lifecycle, templates, and approval policy require reviewed nix-seal mappings",
        "intermediary secrets are repository-only and must not be given target consumers without an explicit policy decision",
    ];
    let report = serde_json::json!({
        "schema":"nix-seal.migration-report.v1",
        "source":"agenix-rekey",
        "dryRun":true,
        "target":{
            "legacyId":export.target.id,
            "nixSealId":target_id,
            "kind":export.target.kind,
            "system":export.target.system,
            "recipient":target_recipient,
            "storageMode":export.target.storage_mode,
        },
        "masterRecipientCount":masters.len(),
        "secrets":mappings,
        "warnings":warnings,
    });
    if json {
        println!("{report}");
    } else {
        println!(
            "agenix-rekey dry-run: {} secrets mapped",
            report["secrets"].as_array().map_or(0, Vec::len)
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

fn validate_agenix_rekey_source(value: &str) -> Result<&str> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.as_os_str().is_empty()
        || path.extension().is_none_or(|extension| extension != "age")
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("agenix-rekey rekeyFile must be a normal repository-relative .age path");
    }
    Ok(value)
}

fn scan_agenix_ciphertexts(root: &Path, directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    if output.len() > 10_000 {
        bail!("agenix ciphertext tree exceeds the 10000-file safety limit");
    }
    let mut entries = fs::read_dir(directory)
        .with_context(|| {
            format!(
                "could not read ciphertext directory {}",
                directory.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("agenix ciphertext tree contains a symlink");
        }
        if metadata.file_type().is_dir() {
            scan_agenix_ciphertexts(root, &path, output)?;
        } else if metadata.file_type().is_file() {
            if path.extension().is_some_and(|extension| extension == "age") {
                let relative = path.strip_prefix(root)?;
                if relative.components().count() > 32 {
                    bail!("agenix ciphertext path nesting exceeds the safety limit");
                }
                nix_seal_crypto::validate_ciphertext_header(open_public_ciphertext(&path)?)
                    .context("agenix ciphertext has an invalid age header")?;
                output.push(path);
            }
        } else {
            bail!("agenix ciphertext tree contains a non-regular entry");
        }
    }
    Ok(())
}

struct SopsJsonInventory {
    path: PathBuf,
    providers: BTreeSet<String>,
    age_recipient_count: usize,
}

/// Produces a public-only SOPS JSON inventory. This does not implement SOPS
/// decryption or authenticate encrypted values; it validates only the bounded,
/// cleartext SOPS metadata required to plan a later explicit migration.
fn migrate_sops_json_tree(directory: &Path, json: bool) -> Result<()> {
    let supplied_metadata =
        fs::symlink_metadata(directory).context("could not inspect SOPS JSON directory")?;
    if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
        bail!("SOPS JSON root must be a non-symlink directory");
    }
    let root = directory
        .canonicalize()
        .context("could not resolve SOPS JSON directory")?;
    let mut files = Vec::new();
    scan_sops_json_files(&root, &root, &mut files)?;
    if files.is_empty() {
        bail!("SOPS JSON directory contains no encrypted JSON files");
    }
    let mappings = files
        .iter()
        .map(|entry| {
            let relative = entry
                .path
                .strip_prefix(&root)
                .context("SOPS JSON file escaped its canonical root")?;
            let stem = relative.with_extension("");
            let legacy_id = stem.to_str().context("SOPS JSON path is not UTF-8")?;
            Ok(serde_json::json!({
                "legacyId":legacy_id,
                "nixSealId":migrated_id(&format!("sops/{legacy_id}"))?,
                "source":relative,
                "providers":entry.providers,
                "ageRecipientCount":entry.age_recipient_count,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = vec![
        "dry run only: no ciphertext, configuration, or source manager was changed",
        "this inventory validates cleartext SOPS JSON metadata only; it does not decrypt values or authenticate the SOPS MAC",
        "structured SOPS files may contain multiple logical values; supply an explicit extraction and target-recipient mapping before streaming an individual value into a nix-seal age file",
        "only regular JSON files with bounded, top-level SOPS metadata were accepted; links and non-regular entries are rejected",
    ];
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":"sops-json",
                "dryRun":true,
                "secrets":mappings,
                "warnings":warnings
            })
        );
    } else {
        println!(
            "sops-json dry-run: {} structured files mapped",
            mappings.len()
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        for mapping in mappings {
            println!(
                "{} -> {} ({})",
                mapping["legacyId"].as_str().unwrap_or("unknown"),
                mapping["nixSealId"].as_str().unwrap_or("unknown"),
                mapping["source"].as_str().unwrap_or("unknown"),
            );
        }
    }
    Ok(())
}

fn scan_sops_json_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<SopsJsonInventory>,
) -> Result<()> {
    if output.len() >= 10_000 {
        bail!("SOPS JSON tree exceeds the 10000-file safety limit");
    }
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("could not read SOPS JSON directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("SOPS JSON tree contains a symlink");
        }
        if metadata.file_type().is_dir() {
            let relative = path.strip_prefix(root)?;
            if relative.components().count() > 32 {
                bail!("SOPS JSON path nesting exceeds the safety limit");
            }
            scan_sops_json_files(root, &path, output)?;
        } else if metadata.file_type().is_file() {
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                output.push(inspect_sops_json(&path)?);
            }
        } else {
            bail!("SOPS JSON tree contains a non-regular entry");
        }
    }
    Ok(())
}

fn inspect_sops_json(path: &Path) -> Result<SopsJsonInventory> {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let input = open_public_ciphertext(path).with_context(|| {
        format!(
            "SOPS JSON file {} has unsafe filesystem metadata",
            path.display()
        )
    })?;
    if input.metadata()?.len() > LIMIT {
        bail!("SOPS JSON file exceeds the 2 MiB safety limit");
    }
    let mut bytes = Vec::new();
    input.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("SOPS JSON file exceeds the 2 MiB safety limit");
    }
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).context("SOPS JSON file is malformed")?;
    let root = document
        .as_object()
        .context("SOPS JSON document must be a top-level object")?;
    let metadata = root
        .get("sops")
        .and_then(serde_json::Value::as_object)
        .context("SOPS JSON document lacks top-level sops metadata")?;
    if metadata
        .get("mac")
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("SOPS JSON metadata lacks a nonempty MAC");
    }
    if metadata
        .get("version")
        .and_then(serde_json::Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("SOPS JSON metadata lacks a nonempty version");
    }
    let mut providers = BTreeSet::new();
    let mut age_recipient_count = 0_usize;
    for provider in ["age", "kms", "gcp_kms", "azure_kv", "hc_vault", "pgp"] {
        let Some(entries) = metadata.get(provider) else {
            continue;
        };
        let entries = entries
            .as_array()
            .with_context(|| format!("SOPS JSON {provider} metadata is not an array"))?;
        if entries.is_empty() || entries.len() > 1024 {
            bail!("SOPS JSON {provider} metadata exceeds safety limits");
        }
        if entries.iter().any(|entry| !entry.is_object()) {
            bail!("SOPS JSON {provider} metadata contains a non-object entry");
        }
        if provider == "age" {
            for entry in entries {
                let recipient = entry
                    .as_object()
                    .and_then(|entry| entry.get("recipient"))
                    .and_then(serde_json::Value::as_str)
                    .context("SOPS JSON age metadata lacks a recipient")?;
                nix_seal_crypto::normalize_recipient(recipient)
                    .context("SOPS JSON age metadata has an invalid recipient")?;
            }
            age_recipient_count = entries.len();
        }
        providers.insert(provider.to_owned());
    }
    if let Some(key_groups) = metadata.get("key_groups") {
        let key_groups = key_groups
            .as_array()
            .context("SOPS JSON key_groups metadata is not an array")?;
        if key_groups.is_empty() || key_groups.len() > 1024 {
            bail!("SOPS JSON key_groups metadata exceeds safety limits");
        }
        if key_groups.iter().any(|entry| !entry.is_object()) {
            bail!("SOPS JSON key_groups metadata contains a non-object entry");
        }
        providers.insert("key_groups".to_owned());
    }
    if providers.is_empty() {
        bail!("SOPS JSON metadata has no recognized key provider");
    }
    Ok(SopsJsonInventory {
        path: path.to_owned(),
        providers,
        age_recipient_count,
    })
}

struct ClanVarInventory {
    path: PathBuf,
    machine: String,
    generator: String,
    output: String,
    bytes: u64,
}

/// Inventories Clan Vars' documented `machine/generator/file/value` leaves
/// without opening a value for reading. A Clan store may use SOPS, a password
/// store, or a custom backend, so byte content is intentionally opaque here.
fn migrate_clan_vars_tree(directory: &Path, json: bool) -> Result<()> {
    let supplied_metadata = fs::symlink_metadata(directory)
        .context("could not inspect Clan Vars per-machine directory")?;
    if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
        bail!("Clan Vars root must be a non-symlink directory");
    }
    let root = directory
        .canonicalize()
        .context("could not resolve Clan Vars per-machine directory")?;
    let mut values = Vec::new();
    let mut auxiliary_files = 0_u64;
    scan_clan_vars_files(&root, &root, &mut values, &mut auxiliary_files)?;
    if values.is_empty() {
        bail!("Clan Vars per-machine directory contains no output value files");
    }
    let mut seen_ids = BTreeSet::new();
    let mappings = values
        .iter()
        .map(|entry| {
            let id = migrated_id(&format!(
                "clan-vars/{}/{}/{}",
                entry.machine, entry.generator, entry.output
            ))?;
            if !seen_ids.insert(id.clone()) {
                bail!("Clan Vars paths collide after nix-seal ID normalization");
            }
            let relative = entry
                .path
                .strip_prefix(&root)
                .context("Clan Vars value escaped its canonical root")?;
            Ok(serde_json::json!({
                "legacyId":format!("{}/{}/{}", entry.machine, entry.generator, entry.output),
                "nixSealId":id,
                "source":relative,
                "valueBytes":entry.bytes,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = vec![
        "dry run only: no value, configuration, or source manager was changed",
        "Clan Vars storage backend and secret/public classification are not recoverable from an output leaf; provide explicit target, recipient, runtime, and public-output mappings before import",
        "output values were never read, decrypted, emitted, or passed to an external process",
        "auxiliary regular files were ignored after link/type validation; only machine/generator/output/value leaves are migration candidates",
    ];
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":"clan-vars",
                "dryRun":true,
                "values":mappings,
                "auxiliaryFileCount":auxiliary_files,
                "warnings":warnings
            })
        );
    } else {
        println!("clan-vars dry-run: {} value leaves mapped", mappings.len());
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        for mapping in mappings {
            println!(
                "{} -> {} ({})",
                mapping["legacyId"].as_str().unwrap_or("unknown"),
                mapping["nixSealId"].as_str().unwrap_or("unknown"),
                mapping["source"].as_str().unwrap_or("unknown"),
            );
        }
    }
    Ok(())
}

fn scan_clan_vars_files(
    root: &Path,
    directory: &Path,
    values: &mut Vec<ClanVarInventory>,
    auxiliary_files: &mut u64,
) -> Result<()> {
    if values.len() >= 10_000 || *auxiliary_files >= 10_000 {
        bail!("Clan Vars tree exceeds the 10000-file safety limit");
    }
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("could not read Clan Vars directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("Clan Vars tree contains a symlink");
        }
        let relative = path.strip_prefix(root)?;
        if relative.components().count() > 4 {
            bail!("Clan Vars path nesting exceeds the documented layout");
        }
        if metadata.file_type().is_dir() {
            scan_clan_vars_files(root, &path, values, auxiliary_files)?;
        } else if metadata.file_type().is_file() {
            if entry.file_name() == "value" && relative.components().count() == 4 {
                values.push(inspect_clan_var_value(&path, relative)?);
            } else {
                *auxiliary_files = auxiliary_files
                    .checked_add(1)
                    .context("Clan Vars auxiliary file count overflow")?;
            }
        } else {
            bail!("Clan Vars tree contains a non-regular entry");
        }
    }
    Ok(())
}

fn inspect_clan_var_value(path: &Path, relative: &Path) -> Result<ClanVarInventory> {
    const LIMIT: u64 = 64 * 1024 * 1024;
    let input = open_public_ciphertext(path).with_context(|| {
        format!(
            "Clan Vars value {} has unsafe filesystem metadata",
            path.display()
        )
    })?;
    let bytes = input.metadata()?.len();
    if bytes > LIMIT {
        bail!("Clan Vars value exceeds the 64 MiB safety limit");
    }
    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(value) => value.to_str().map(ToOwned::to_owned),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .context("Clan Vars value has an unsafe or non-UTF-8 path")?;
    let [machine, generator, output, value] = components.as_slice() else {
        bail!("Clan Vars value has an invalid path layout");
    };
    if value != "value" || machine.is_empty() || generator.is_empty() || output.is_empty() {
        bail!("Clan Vars value has an invalid path layout");
    }
    Ok(ClanVarInventory {
        path: path.to_owned(),
        machine: machine.clone(),
        generator: generator.clone(),
        output: output.clone(),
        bytes,
    })
}

/// Inventories Clan Facts' documented `machines/<machine>/facts/<fact>` public
/// leaves without opening their contents. Secret facts deliberately have a
/// configurable store/path function and cannot be inferred safely from disk.
fn migrate_clan_facts_tree(directory: &Path, json: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(directory).context("could not inspect Clan Facts root")?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("Clan Facts root must be a non-symlink directory");
    }
    let root = directory
        .canonicalize()
        .context("could not resolve Clan Facts root")?;
    let mut entries = fs::read_dir(&root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut facts = Vec::new();
    for machine in entries {
        let machine_path = machine.path();
        let machine_metadata = fs::symlink_metadata(&machine_path)?;
        if machine_metadata.file_type().is_symlink() {
            bail!("Clan Facts root contains a symbolic link");
        }
        if !machine_metadata.file_type().is_dir() {
            continue;
        }
        let machine_name = machine
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("Clan Facts machine path is not UTF-8"))?;
        let facts_root = machine_path.join("facts");
        if !facts_root.exists() {
            continue;
        }
        let facts_metadata = fs::symlink_metadata(&facts_root)?;
        if facts_metadata.file_type().is_symlink() || !facts_metadata.file_type().is_dir() {
            bail!("Clan Facts machine facts path must be a non-symlink directory");
        }
        let mut leaves = fs::read_dir(&facts_root)?.collect::<Result<Vec<_>, _>>()?;
        leaves.sort_by_key(fs::DirEntry::file_name);
        for leaf in leaves {
            if facts.len() >= 10_000 {
                bail!("Clan Facts tree exceeds the 10000-file safety limit");
            }
            let path = leaf.path();
            let leaf_metadata = fs::symlink_metadata(&path)?;
            if leaf_metadata.file_type().is_symlink() || !leaf_metadata.file_type().is_file() {
                bail!("Clan Facts public leaves must be non-symlink regular files");
            }
            let name = leaf
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Clan Facts leaf path is not UTF-8"))?;
            if name.is_empty() || leaf_metadata.len() > 64 * 1024 * 1024 {
                bail!("Clan Facts public leaf has an invalid name or exceeds 64 MiB");
            }
            facts.push((machine_name.clone(), name, leaf_metadata.len(), path));
        }
    }
    if facts.is_empty() {
        bail!("Clan Facts root contains no documented public fact leaves");
    }
    let mut seen = BTreeSet::new();
    let mappings = facts.iter().map(|(machine, name, bytes, path)| {
        let id = migrated_id(&format!("clan-facts/{machine}/{name}"))?;
        if !seen.insert(id.clone()) { bail!("Clan Facts paths collide after nix-seal ID normalization"); }
        Ok(serde_json::json!({"legacyId":format!("{machine}/{name}"),"nixSealId":id,"source":path.strip_prefix(&root)?,"valueBytes":bytes}))
    }).collect::<Result<Vec<_>>>()?;
    let warnings = vec![
        "dry run only: no value, configuration, or source manager was changed",
        "only documented public facts were inventoried without reading them; secret facts use configurable stores and require an explicit reviewed export",
    ];
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.migration-report.v1","source":"clan-facts","dryRun":true,"facts":mappings,"warnings":warnings})
        );
    } else {
        println!("clan-facts dry-run: {} public facts mapped", mappings.len());
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

fn migrate_secretctl(
    index_path: &Path,
    plan_output: Option<&Path>,
    target_systems: &[String],
    signers: &[String],
    json: bool,
) -> Result<()> {
    let index: SecretctlIndexV1 =
        read_json_bounded(index_path).context("invalid strict secretctl secretIndex JSON")?;
    let report = build_secretctl_migration_report(&index)?;
    let candidate_plan = if let Some(output) = plan_output {
        let plan = build_secretctl_candidate_plan(&index, target_systems, signers)?;
        let canonical = nix_seal_policy::canonical_json(&plan)?;
        emit_canonical_public_json(Some(output), &canonical)?;
        Some(output)
    } else {
        if !target_systems.is_empty() || !signers.is_empty() {
            bail!("--target-system and --signer require --plan-output");
        }
        None
    };
    let mut warnings = vec![
        "dry run only: no ciphertext, configuration, or source manager was changed".to_owned(),
        "secretctl uses SSH recipients; native age is preferred, while unencrypted OpenSSH identities are available only for reviewed migration compatibility".to_owned(),
        "the reported legacy group memberships and direct-recipient sets were cross-checked; review normalized IDs and scope selectors before generating a nix-seal plan".to_owned(),
    ];
    if candidate_plan.is_some() {
        warnings.push(
            "candidate plans retain legacy direct delivery and use default root-only runtime settings; review runtime ownership, phases, templates, lifecycle metadata, and a rekeyed administrator/recovery policy before activation".to_owned(),
        );
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":"secretctl",
                "dryRun":true,
                "groups":report.groups,
                "secrets":report.secrets,
                "targets":report.targets,
                "sshRecipientCount":report.ssh_recipient_count,
                "candidatePlan":candidate_plan,
                "warnings":warnings
            })
        );
    } else {
        println!(
            "secretctl dry-run: {} groups, {} secrets, and {} targets mapped; {} SSH recipients require a reviewed migration path",
            report.groups.len(),
            report.secrets.len(),
            report.targets.len(),
            report.ssh_recipient_count,
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        if let Some(path) = candidate_plan {
            eprintln!(
                "candidate plan written to {}; review before activation",
                path.display()
            );
        }
        for mapping in report.secrets {
            println!(
                "{} -> {} ({})",
                mapping["legacyId"].as_str().unwrap_or("unknown"),
                mapping["nixSealId"].as_str().unwrap_or("unknown"),
                mapping["source"].as_str().unwrap_or("unknown"),
            );
        }
    }
    Ok(())
}

fn build_secretctl_migration_report(index: &SecretctlIndexV1) -> Result<SecretctlMigrationReport> {
    if index.version != 1 {
        bail!("unsupported secretctl index version; expected 1");
    }
    if index.secrets.is_empty()
        || index.groups.len() > 10_000
        || index.targets.len() > 10_000
        || index.secrets.len() > 10_000
    {
        bail!("secretctl index has unsupported group, target, or secret counts");
    }
    let groups = validate_secretctl_groups(&index.groups)?;
    let targets = validate_secretctl_targets(&index.targets, &groups.groups)?;
    let secrets = validate_secretctl_secrets(&index.secrets, &groups.groups, &targets.recipients)?;
    let mut ssh_recipients = groups.ssh_recipients;
    ssh_recipients.extend(targets.ssh_recipients);
    ssh_recipients.extend(secrets.ssh_recipients);
    let group_mappings = migration_groups(&groups.groups)?;
    Ok(SecretctlMigrationReport {
        groups: group_mappings,
        secrets: secrets.mappings,
        targets: targets.mappings,
        ssh_recipient_count: ssh_recipients.len(),
    })
}

fn build_secretctl_candidate_plan(
    index: &SecretctlIndexV1,
    target_system_specs: &[String],
    signer_specs: &[String],
) -> Result<nix_seal_core::PlanV1> {
    let _ = build_secretctl_migration_report(index)?;
    let systems = parse_target_systems(target_system_specs, &index.targets)?;
    let signers = parse_candidate_signers(signer_specs)?;
    let mut plan = nix_seal_core::PlanV1::default();
    plan.identities.extend(signers);

    let mut target_ids = BTreeMap::new();
    let mut seen_target_recipients = BTreeSet::new();
    for (legacy_id, target) in &index.targets {
        let target_id = migration_prefixed_id("target", legacy_id)?;
        let identity_id = migration_prefixed_id("target-key", legacy_id)?;
        let public = normalize_secretctl_recipient(
            &target.public_key,
            &format!("secretctl target {legacy_id}"),
        )?;
        if !seen_target_recipients.insert(public.clone()) {
            bail!("secretctl candidate cannot represent duplicate target recipient keys");
        }
        let kind = candidate_target_kind(legacy_id, &target.target_type)?;
        let username = candidate_target_username(legacy_id, &target.target_type)?;
        plan.identities.insert(
            identity_id.clone(),
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Target,
                public,
            },
        );
        plan.targets.insert(
            target_id.clone(),
            nix_seal_core::Target {
                kind,
                system: systems
                    .get(legacy_id)
                    .cloned()
                    .with_context(|| format!("missing target-system mapping for {legacy_id}"))?,
                identity: identity_id,
                username,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        target_ids.insert(legacy_id.as_str(), target_id);
    }

    for legacy_group in index.groups.keys() {
        let members = index
            .targets
            .iter()
            .filter_map(|(legacy_target, target)| {
                target
                    .groups
                    .iter()
                    .any(|group| group == legacy_group)
                    .then(|| target_ids.get(legacy_target.as_str()).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();
        if members.is_empty() {
            bail!("secretctl candidate group {legacy_group} has no target members");
        }
        plan.groups.insert(
            migration_prefixed_id("legacy-group", legacy_group)?,
            nix_seal_core::Group { members },
        );
    }

    for (legacy_id, secret) in &index.secrets {
        let consumers = secret
            .consumers
            .iter()
            .map(|consumer| {
                target_ids.get(consumer.as_str()).cloned().with_context(|| {
                    format!("secretctl secret {legacy_id} references missing target {consumer}")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        plan.secrets.insert(
            migrated_id(legacy_id)?,
            nix_seal_core::Secret {
                source: secret.file.clone(),
                delivery: nix_seal_core::DeliveryMode::Direct,
                administrators: Vec::new(),
                consumers,
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
    }
    nix_seal_policy::validate(&plan)?;
    Ok(plan)
}

fn parse_target_systems(
    specs: &[String],
    targets: &BTreeMap<String, SecretctlTargetV1>,
) -> Result<BTreeMap<String, String>> {
    if specs.len() != targets.len() {
        bail!("candidate plan requires exactly one --target-system for every legacy target");
    }
    let mut systems = BTreeMap::new();
    for spec in specs {
        let (target, system) = spec
            .split_once('=')
            .context("target-system must use LEGACY_TARGET=SYSTEM")?;
        if !targets.contains_key(target)
            || !matches!(
                system,
                "x86_64-linux" | "aarch64-linux" | "x86_64-darwin" | "aarch64-darwin"
            )
            || systems
                .insert(target.to_owned(), system.to_owned())
                .is_some()
        {
            bail!(
                "candidate target-system mappings must be unique supported systems for known legacy targets"
            );
        }
    }
    Ok(systems)
}

fn parse_candidate_signers(
    specs: &[String],
) -> Result<BTreeMap<nix_seal_core::Id, nix_seal_core::Identity>> {
    if specs.is_empty() || specs.len() > 256 {
        bail!("candidate plan requires one or more distinct --signer ID=PUBLIC_KEY mappings");
    }
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    let mut signers = BTreeMap::new();
    for spec in specs {
        let (id, public) = spec
            .split_once('=')
            .context("signer must use ID=PUBLIC_KEY")?;
        let id = nix_seal_core::Id::parse(id).context("candidate signer ID is invalid")?;
        trusted
            .insert_encoded(public)
            .context("candidate signer public key is invalid or duplicated")?;
        if signers
            .insert(
                id,
                nix_seal_core::Identity {
                    kind: nix_seal_core::IdentityKind::Signer,
                    public: public.to_owned(),
                },
            )
            .is_some()
        {
            bail!("candidate signer IDs must be distinct");
        }
    }
    Ok(signers)
}

fn migration_prefixed_id(prefix: &str, legacy_id: &str) -> Result<nix_seal_core::Id> {
    nix_seal_core::Id::parse(format!("{prefix}/{}", migrated_id(legacy_id)?))
        .context("legacy migration ID is invalid")
}

fn candidate_target_kind(legacy_id: &str, target_type: &str) -> Result<nix_seal_core::TargetKind> {
    match (target_type, legacy_id) {
        ("home", value) if value.starts_with("home:") => Ok(nix_seal_core::TargetKind::HomeManager),
        ("host", value) if value.starts_with("host:nixos:") => Ok(nix_seal_core::TargetKind::NixOs),
        ("host", value) if value.starts_with("host:darwin:") => {
            Ok(nix_seal_core::TargetKind::Darwin)
        }
        _ => bail!("secretctl candidate cannot infer nix target kind for {legacy_id}"),
    }
}

fn candidate_target_username(legacy_id: &str, target_type: &str) -> Result<Option<String>> {
    if target_type != "home" {
        return Ok(None);
    }
    let value = legacy_id
        .strip_prefix("home:")
        .and_then(|value| value.split_once('@').map(|(username, _)| username))
        .filter(|username| !username.is_empty())
        .context("secretctl home target must use home:USERNAME@CONFIG naming")?;
    Ok(Some(value.to_owned()))
}

fn validate_secretctl_groups(
    source: &BTreeMap<String, Vec<String>>,
) -> Result<ValidatedSecretctlGroups> {
    let mut groups = BTreeMap::new();
    let mut ssh_recipients = BTreeSet::new();
    for (legacy_id, recipients) in source {
        if legacy_id.is_empty() || recipients.is_empty() || recipients.len() > 10_000 {
            bail!("secretctl group {legacy_id} has invalid recipient metadata");
        }
        let normalized =
            normalize_secretctl_recipients(recipients, &format!("secretctl group {legacy_id}"))?;
        if normalized.len() != recipients.len() {
            bail!("secretctl group {legacy_id} contains duplicate recipients");
        }
        ssh_recipients.extend(normalized.iter().cloned());
        groups.insert(legacy_id.clone(), normalized);
    }
    Ok(ValidatedSecretctlGroups {
        groups,
        ssh_recipients,
    })
}

fn validate_secretctl_targets(
    source: &BTreeMap<String, SecretctlTargetV1>,
    groups: &BTreeMap<String, BTreeSet<String>>,
) -> Result<ValidatedSecretctlTargets> {
    let mut targets = Vec::new();
    let mut target_recipients = BTreeMap::new();
    let mut ssh_recipients = BTreeSet::new();
    for (legacy_id, target) in source {
        if target.target_type != "home" && target.target_type != "host" {
            bail!("secretctl target {legacy_id} has an unsupported type");
        }
        if target.groups.is_empty()
            || target.groups.len() > 10_000
            || target.recipients.is_empty()
            || target.recipients.len() > 10_000
        {
            bail!("secretctl target {legacy_id} has invalid group or recipient metadata");
        }
        let public_key = normalize_secretctl_recipient(
            &target.public_key,
            &format!("secretctl target {legacy_id}"),
        )?;
        let mut expected = BTreeSet::from([public_key.clone()]);
        for group in &target.groups {
            let members = groups.get(group).with_context(|| {
                format!("secretctl target {legacy_id} references missing group {group}")
            })?;
            expected.extend(members.iter().cloned());
        }
        if target.groups.iter().collect::<BTreeSet<_>>().len() != target.groups.len() {
            bail!("secretctl target {legacy_id} contains duplicate group references");
        }
        let recipients = normalize_secretctl_recipients(
            &target.recipients,
            &format!("secretctl target {legacy_id}"),
        )?;
        if recipients.len() != target.recipients.len() || recipients != expected {
            bail!("secretctl target {legacy_id} recipient set does not match its public groups");
        }
        ssh_recipients.extend(recipients.iter().cloned());
        target_recipients.insert(legacy_id.clone(), public_key);
        targets.push(serde_json::json!({
            "legacyId":legacy_id,
            "nixSealId":migrated_id(legacy_id)?,
            "type":target.target_type,
            "groups":target.groups,
            "recipientCount":recipients.len()
        }));
    }
    Ok(ValidatedSecretctlTargets {
        recipients: target_recipients,
        mappings: targets,
        ssh_recipients,
    })
}

fn validate_secretctl_secrets(
    source: &BTreeMap<String, SecretctlSecretV1>,
    groups: &BTreeMap<String, BTreeSet<String>>,
    target_recipients: &BTreeMap<String, String>,
) -> Result<ValidatedSecretctlSecrets> {
    let mut secrets = Vec::new();
    let mut ssh_recipients = BTreeSet::new();
    for (legacy_id, secret) in source {
        if secret.id != *legacy_id
            || secret.group.is_empty()
            || secret.agenix_name.is_empty()
            || secret.consumers.is_empty()
            || secret.consumers.len() > 10_000
            || secret.recipients.is_empty()
            || secret.recipients.len() > 10_000
        {
            bail!("secretctl index has inconsistent public secret metadata for {legacy_id}");
        }
        if !groups.contains_key(&secret.group) {
            bail!(
                "secretctl secret {legacy_id} references missing group {}",
                secret.group
            );
        }
        if secret.consumers.iter().collect::<BTreeSet<_>>().len() != secret.consumers.len() {
            bail!("secretctl secret {legacy_id} contains duplicate consumer targets");
        }
        let mut expected = BTreeSet::new();
        for consumer in &secret.consumers {
            let recipient = target_recipients.get(consumer).with_context(|| {
                format!("secretctl secret {legacy_id} references missing target {consumer}")
            })?;
            expected.insert(recipient.clone());
        }
        let recipients = normalize_secretctl_recipients(
            &secret.recipients,
            &format!("secretctl secret {legacy_id}"),
        )?;
        if recipients.len() != secret.recipients.len() || recipients != expected {
            bail!("secretctl secret {legacy_id} recipient set does not match its consumer targets");
        }
        ssh_recipients.extend(recipients);
        let new_id = migrated_id(legacy_id)?;
        let source = migrate_secretctl_source(&secret.file)?;
        secrets.push(serde_json::json!({
            "legacyId":legacy_id,
            "nixSealId":new_id,
            "source":source,
            "scope":secret.scope,
            "selector":secret.selector,
            "agenixName":secret.agenix_name,
            "group":secret.group,
            "consumers":secret.consumers
        }));
    }
    Ok(ValidatedSecretctlSecrets {
        mappings: secrets,
        ssh_recipients,
    })
}

fn migration_groups(groups: &BTreeMap<String, BTreeSet<String>>) -> Result<Vec<serde_json::Value>> {
    let groups = groups
        .iter()
        .map(|(legacy_id, recipients)| {
            Ok(serde_json::json!({
                "legacyId":legacy_id,
                "nixSealId":migrated_id(legacy_id)?,
                "recipientCount":recipients.len()
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(groups)
}

fn normalize_secretctl_recipients(recipients: &[String], owner: &str) -> Result<BTreeSet<String>> {
    recipients
        .iter()
        .map(|recipient| normalize_secretctl_recipient(recipient, owner))
        .collect()
}

fn normalize_secretctl_recipient(recipient: &str, owner: &str) -> Result<String> {
    let normalized = nix_seal_crypto::normalize_recipient(recipient)
        .with_context(|| format!("{owner} has an unsupported recipient format"))?;
    if !(normalized.starts_with("ssh-ed25519 ") || normalized.starts_with("ssh-rsa ")) {
        bail!("{owner} has an unsupported recipient format");
    }
    Ok(normalized)
}

fn migrated_id(value: &str) -> Result<nix_seal_core::Id> {
    let mut normalized = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' => normalized.push(char::from(byte.to_ascii_lowercase())),
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'/' | b'-' | b'_' => {
                normalized.push(char::from(byte));
            }
            b':' | b'@' => normalized.push('-'),
            _ => bail!("legacy secretctl ID cannot be represented safely in nix-seal"),
        }
    }
    nix_seal_core::Id::parse(normalized).context("legacy ID normalization is invalid")
}

fn migrate_secretctl_source(value: &str) -> Result<&str> {
    let path = Path::new(value);
    if path.extension().is_none_or(|extension| extension != "age")
        || !path.starts_with("secrets")
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("secretctl ciphertext source is not a normalized secrets/*.age path");
    }
    Ok(value)
}

fn load_plan(toml: &Path, nix_plan: Option<&Path>) -> Result<nix_seal_core::PlanV1> {
    match (toml.exists(), nix_plan) {
        (true, Some(nix)) => Ok(nix_seal_policy::merge(
            nix_seal_policy::load_toml(toml)?,
            nix_seal_policy::load_json(nix)?,
        )?),
        (true, None) => Ok(nix_seal_policy::load_toml(toml)?),
        (false, Some(nix)) => Ok(nix_seal_policy::load_json(nix)?),
        (false, None) => bail!(
            "no plan source found; expected {} or --nix-plan",
            toml.display()
        ),
    }
}

fn run_key(command: KeyCommand, json: bool) -> Result<()> {
    match command {
        KeyCommand::List { plan } => {
            let plan = read_plan_bounded(&plan)?;
            let identities = public_identity_records(&plan);
            if json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"nix-seal.identities.v1","identities":identities})
                );
            } else {
                for identity in identities {
                    let PublicIdentityRecord { id, kind, public } = identity;
                    println!("{id} {kind} {public}");
                }
            }
        }
        KeyCommand::Generate { identity_out } => {
            let (identity, recipient) = nix_seal_crypto::generate_x25519();
            write_new_private(&identity_out, identity.expose_secret().as_bytes())?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"nix-seal.output.v1","recipient":recipient,"identityPath":identity_out})
                );
            } else {
                println!("{recipient}");
                eprintln!("private identity written to {}", identity_out.display());
            }
        }
        KeyCommand::Inspect { identity } => {
            let secret = read_identity(&identity)?;
            let recipient = nix_seal_crypto::recipient_from_identity(&secret)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"nix-seal.output.v1","recipient":recipient})
                );
            } else {
                println!("{recipient}");
            }
        }
        KeyCommand::GenerateSigning { key_out } => {
            let key = nix_seal_manifest::ApprovalSigningKey::generate()?;
            let private = key.encode_private()?;
            write_new_private(&key_out, private.as_bytes())?;
            print_signing_key(&key, &key_out, json)?;
        }
        KeyCommand::InspectSigning { key } => {
            let signing_key = read_signing_key(&key)?;
            print_signing_key(&signing_key, &key, json)?;
        }
    }
    Ok(())
}

fn run_identity(command: IdentityCommand, json: bool) -> Result<()> {
    match command {
        IdentityCommand::List(plan) => {
            let plan = load_plan(&plan.toml, plan.nix_plan.as_deref())?;
            nix_seal_policy::validate(&plan)?;
            print_identity_records(public_identity_records(&plan), json);
        }
        IdentityCommand::Add {
            plan,
            id,
            kind,
            public,
        } => {
            let kind = identity_role_kind(kind);
            validate_identity_public(&kind, &public)?;
            mutate_toml_plan(&plan, |toml_plan| {
                if toml_plan.identities.contains_key(&id) {
                    bail!("identity {id} already exists in the TOML plan");
                }
                toml_plan
                    .identities
                    .insert(id.clone(), nix_seal_core::Identity { kind, public });
                Ok(())
            })?;
            print_identity_mutation("added", &id, json, false);
        }
        IdentityCommand::Remove { plan, id, yes } => {
            if !yes {
                bail!("identity removal requires --yes");
            }
            mutate_toml_plan(&plan, |toml_plan| {
                if !toml_plan.identities.contains_key(&id) {
                    bail!("identity {id} does not exist in the TOML plan");
                }
                let references = identity_references(toml_plan, &id);
                if !references.is_empty() {
                    bail!(
                        "identity {id} is still referenced by {}",
                        references.join(", ")
                    );
                }
                toml_plan.identities.remove(&id);
                Ok(())
            })?;
            print_identity_mutation("removed", &id, json, false);
        }
        IdentityCommand::Rotate {
            plan,
            id,
            public,
            yes,
        } => {
            if !yes {
                bail!("identity rotation requires --yes");
            }
            mutate_toml_plan(&plan, |toml_plan| {
                let identity = toml_plan
                    .identities
                    .get_mut(&id)
                    .with_context(|| format!("identity {id} does not exist in the TOML plan"))?;
                validate_identity_public(&identity.kind, &public)?;
                identity.public = public;
                Ok(())
            })?;
            print_identity_mutation("rotated", &id, json, true);
        }
    }
    Ok(())
}

fn run_group(command: GroupCommand, json: bool) -> Result<()> {
    match command {
        GroupCommand::List(plan) => {
            let plan = load_plan(&plan.toml, plan.nix_plan.as_deref())?;
            nix_seal_policy::validate(&plan)?;
            let groups = plan
                .groups
                .iter()
                .map(|(id, group)| serde_json::json!({"id":id,"members":group.members}))
                .collect::<Vec<_>>();
            if json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"nix-seal.groups.v1","groups":groups})
                );
            } else {
                for group in groups {
                    println!(
                        "{}\t{}",
                        group["id"].as_str().unwrap_or("unknown"),
                        group["members"]
                    );
                }
            }
        }
        GroupCommand::Add { plan, id, members } => {
            mutate_toml_plan(&plan, |toml_plan| {
                if toml_plan.groups.contains_key(&id) {
                    bail!("group {id} already exists in the TOML plan");
                }
                toml_plan
                    .groups
                    .insert(id.clone(), nix_seal_core::Group { members });
                Ok(())
            })?;
            print_group_mutation("added", &id, json);
        }
        GroupCommand::Remove { plan, id, yes } => {
            if !yes {
                bail!("group removal requires --yes");
            }
            mutate_toml_plan(&plan, |toml_plan| {
                if !toml_plan.groups.contains_key(&id) {
                    bail!("group {id} does not exist in the TOML plan");
                }
                let references = group_references(toml_plan, &id);
                if !references.is_empty() {
                    bail!(
                        "group {id} is still referenced by {}",
                        references.join(", ")
                    );
                }
                toml_plan.groups.remove(&id);
                Ok(())
            })?;
            print_group_mutation("removed", &id, json);
        }
    }
    Ok(())
}

fn print_group_mutation(operation: &str, id: &nix_seal_core::Id, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","operation":operation,"group":id})
        );
    } else {
        println!("group {operation}: {id}");
    }
}

fn group_references(plan: &nix_seal_core::PlanV1, id: &nix_seal_core::Id) -> Vec<String> {
    let mut references = Vec::new();
    for (group_id, group) in &plan.groups {
        if group_id != id && group.members.iter().any(|member| member == id) {
            references.push(format!("group {group_id}"));
        }
    }
    for (secret_id, secret) in &plan.secrets {
        if secret.administrators.iter().any(|member| member == id)
            || secret.consumers.iter().any(|member| member == id)
        {
            references.push(format!("secret {secret_id}"));
        }
    }
    references
}

fn print_identity_records(identities: Vec<PublicIdentityRecord>, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.identities.v1","identities":identities})
        );
    } else {
        for PublicIdentityRecord { id, kind, public } in identities {
            println!("{id} {kind} {public}");
        }
    }
}

fn print_identity_mutation(operation: &str, id: &nix_seal_core::Id, json: bool, rekey: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","operation":operation,"identity":id,"rekeyRequired":rekey})
        );
    } else {
        println!("identity {operation}: {id}");
        if rekey {
            eprintln!(
                "warning: existing artifacts are no longer valid; run nix-seal rekey and obtain required approvals"
            );
        }
    }
}

fn identity_role_kind(role: IdentityRole) -> nix_seal_core::IdentityKind {
    match role {
        IdentityRole::Administrator => nix_seal_core::IdentityKind::Administrator,
        IdentityRole::Target => nix_seal_core::IdentityKind::Target,
        IdentityRole::Recovery => nix_seal_core::IdentityKind::Recovery,
        IdentityRole::Signer => nix_seal_core::IdentityKind::Signer,
        IdentityRole::Plugin => nix_seal_core::IdentityKind::Plugin,
    }
}

fn validate_identity_public(kind: &nix_seal_core::IdentityKind, public: &str) -> Result<()> {
    if public.is_empty()
        || public.len() > 16 * 1024
        || public.bytes().any(|byte| byte.is_ascii_control())
    {
        bail!("identity public value is empty, oversized, or contains control characters");
    }
    match kind {
        nix_seal_core::IdentityKind::Administrator
        | nix_seal_core::IdentityKind::Target
        | nix_seal_core::IdentityKind::Recovery => {
            nix_seal_crypto::normalize_recipient(public)?;
        }
        nix_seal_core::IdentityKind::Signer => {
            let mut trusted = nix_seal_manifest::TrustedKeys::new();
            trusted.insert_encoded(public)?;
        }
        nix_seal_core::IdentityKind::Plugin => {}
    }
    Ok(())
}

fn identity_references(plan: &nix_seal_core::PlanV1, id: &nix_seal_core::Id) -> Vec<String> {
    let mut references = Vec::new();
    for (group_id, group) in &plan.groups {
        if group.members.iter().any(|member| member == id) {
            references.push(format!("group {group_id}"));
        }
    }
    for (target_id, target) in &plan.targets {
        if &target.identity == id {
            references.push(format!("target {target_id}"));
        }
    }
    for (secret_id, secret) in &plan.secrets {
        if secret
            .administrators
            .iter()
            .any(|administrator| administrator == id)
        {
            references.push(format!("secret {secret_id}"));
        }
    }
    for (policy_id, policy) in &plan.approval_policies {
        if policy.signers.iter().any(|signer| signer == id) {
            references.push(format!("approval policy {policy_id}"));
        }
    }
    references
}

fn mutate_toml_plan<F>(arguments: &IdentityPlanArgs, mutate: F) -> Result<()>
where
    F: FnOnce(&mut nix_seal_core::PlanV1) -> Result<()>,
{
    let parent = arguments
        .toml
        .parent()
        .context("TOML plan path has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        bail!("TOML plan parent must be an existing non-symlink directory");
    }
    let lock_path = parent.join(".nix-seal-plan.lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .context("could not open the public plan lock")?;
    lock.lock_exclusive()
        .context("could not acquire the public plan lock")?;
    let result = mutate_toml_plan_locked(arguments, mutate);
    lock.unlock()
        .context("could not release the public plan lock")?;
    result
}

fn mutate_toml_plan_locked<F>(arguments: &IdentityPlanArgs, mutate: F) -> Result<()>
where
    F: FnOnce(&mut nix_seal_core::PlanV1) -> Result<()>,
{
    let metadata = fs::symlink_metadata(&arguments.toml)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("TOML plan must be a non-symlink regular file");
    }
    let mut plan = nix_seal_policy::load_toml(&arguments.toml)?;
    mutate(&mut plan)?;
    let merged = if let Some(nix_plan) = arguments.nix_plan.as_deref() {
        nix_seal_policy::merge(plan.clone(), nix_seal_policy::load_json(nix_plan)?)?
    } else {
        plan.clone()
    };
    nix_seal_policy::validate(&merged)?;
    let text = toml::to_string_pretty(&plan).context("could not encode canonical TOML plan")?;
    let parent = arguments
        .toml
        .parent()
        .context("TOML plan path has no parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged
        .as_file_mut()
        .set_permissions(metadata.permissions())?;
    staged.write_all(text.as_bytes())?;
    staged.write_all(b"\n")?;
    staged.as_file().sync_all()?;
    let current = fs::symlink_metadata(&arguments.toml)?;
    if !current.file_type().is_file() || current.file_type().is_symlink() {
        bail!("TOML plan changed to an unsafe file during the transaction");
    }
    staged
        .persist(&arguments.toml)
        .map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn public_identity_records(plan: &nix_seal_core::PlanV1) -> Vec<PublicIdentityRecord> {
    plan.identities
        .iter()
        .map(|(id, identity)| PublicIdentityRecord {
            id: id.as_str().to_owned(),
            kind: identity_kind_name(&identity.kind),
            public: identity.public.clone(),
        })
        .collect()
}

fn identity_kind_name(kind: &nix_seal_core::IdentityKind) -> &'static str {
    match kind {
        nix_seal_core::IdentityKind::Administrator => "administrator",
        nix_seal_core::IdentityKind::Target => "target",
        nix_seal_core::IdentityKind::Recovery => "recovery",
        nix_seal_core::IdentityKind::Signer => "signer",
        nix_seal_core::IdentityKind::Plugin => "plugin",
    }
}

fn print_signing_key(
    key: &nix_seal_manifest::ApprovalSigningKey,
    path: &Path,
    json: bool,
) -> Result<()> {
    let public = key.encode_public()?;
    let key_id = key.key_id()?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "publicKey":public,
                "keyId":key_id,
                "keyPath":path
            })
        );
    } else {
        println!("{public}");
        eprintln!("key ID: {key_id}");
    }
    Ok(())
}

fn run_artifact(command: ArtifactCommand, json: bool) -> Result<()> {
    match command {
        ArtifactCommand::Sign {
            manifest,
            signing_key,
            output,
        } => {
            let manifest: nix_seal_manifest::TargetManifestV2 = read_json_bounded(&manifest)?;
            let key = read_signing_key(&signing_key)?;
            let envelope = nix_seal_manifest::sign_manifest(&manifest, &key)?;
            write_new_json(&output, &envelope)?;
            artifact_written(&output, envelope.signatures.len(), json);
        }
        ArtifactCommand::Approve {
            input,
            signing_key,
            output,
        } => {
            let mut envelope: nix_seal_manifest::SignedEnvelopeV1 = read_json_bounded(&input)?;
            let key = read_signing_key(&signing_key)?;
            nix_seal_manifest::add_signature(&mut envelope, &key)?;
            write_new_json(&output, &envelope)?;
            artifact_written(&output, envelope.signatures.len(), json);
        }
        ArtifactCommand::Verify {
            input,
            trusted_keys,
            threshold,
            plan_hash,
            target_policy_hash,
            source_hash,
            artifact_hash,
            target,
            secret,
            recipient_fingerprint,
            generation,
            allowed_clock_skew,
        } => {
            let envelope: nix_seal_manifest::SignedEnvelopeV1 = read_json_bounded(&input)?;
            let trusted = read_trusted_keys(&trusted_keys)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before the Unix epoch")?
                .as_secs();
            let expected = nix_seal_manifest::ExpectedBinding {
                tool_version: env!("CARGO_PKG_VERSION"),
                plan_hash: &plan_hash,
                target_policy_hash: &target_policy_hash,
                source_ciphertext_hash: &source_hash,
                artifact_ciphertext_hash: &artifact_hash,
                target_id: &target,
                secret_id: &secret,
                recipient_fingerprint: &recipient_fingerprint,
                artifact_generation: generation,
                now,
                allowed_clock_skew,
            };
            let verified = nix_seal_manifest::verify(&envelope, &trusted, threshold, &expected)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema":"nix-seal.output.v1",
                        "ok":true,
                        "target":verified.manifest.target_id,
                        "secret":verified.manifest.secret_id,
                        "generation":verified.manifest.artifact_generation,
                        "signers":verified.signers
                    })
                );
            } else {
                println!(
                    "verified {} for {} generation {} with {} distinct signature(s)",
                    verified.manifest.secret_id,
                    verified.manifest.target_id,
                    verified.manifest.artifact_generation,
                    verified.signers.len()
                );
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_rekey(arguments: RekeyArgs, json: bool) -> Result<()> {
    let plan: nix_seal_core::PlanV1 = read_plan_bounded(&arguments.plan)?;
    let policy = nix_seal_policy::target_policy(&plan, &arguments.target)?;
    let target_policy_hash = nix_seal_policy::target_policy_hash(&policy)?;
    let secret_policy = policy.secrets.get(&arguments.secret).with_context(|| {
        format!(
            "secret {} is not authorized for target {}",
            arguments.secret, arguments.target
        )
    })?;
    let signing_key = read_signing_key(&arguments.signing_key)?;
    ensure_signing_key_authorized(secret_policy, &signing_key, &arguments.secret)?;
    let issued_at = issue_time(arguments.expires_at)?;
    if matches!(secret_policy.delivery, nix_seal_core::DeliveryMode::Direct)
        && arguments.identity.is_some()
    {
        bail!(
            "--identity is not accepted for direct delivery; staging never decrypts canonical ciphertext"
        );
    }
    let identity = arguments
        .identity
        .as_deref()
        .map(read_identity)
        .transpose()?;
    if matches!(secret_policy.delivery, nix_seal_core::DeliveryMode::Rekeyed) {
        ensure_rekey_identity_authorized(&plan, &arguments.secret, identity.as_ref())?;
    }
    let root = arguments.cache_root.unwrap_or_else(default_cache_root);
    let cache = nix_seal_cache::Cache::open(root)?;
    let (result, delivery) = create_target_artifact(
        &cache,
        &policy,
        &target_policy_hash,
        secret_policy,
        &arguments.repository_root,
        &arguments.target,
        &arguments.secret,
        identity.as_ref(),
        arguments.generation,
        issued_at,
        arguments.expires_at,
        &signing_key,
    )?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "cacheKey":result.cache_key,
                "sourceCiphertextHash":result.source_ciphertext_hash,
                "artifactCiphertextHash":result.artifact_ciphertext_hash,
                "recipientFingerprint":result.recipient_fingerprint,
                "ciphertextPath":result.ciphertext_path,
                "reused":result.reused,
                "target":arguments.target,
                "secret":arguments.secret,
                "generation":arguments.generation,
                "delivery":delivery
            })
        );
    } else {
        println!("{}", result.cache_key);
        eprintln!(
            "{} {} target artifact for {} on {}: {}",
            if result.reused { "reused" } else { "created" },
            delivery,
            arguments.secret,
            arguments.target,
            result.ciphertext_path.display()
        );
        if delivery == "direct" {
            eprintln!(
                "warning: staged direct-delivery ciphertext without re-encryption; a matching target key can decrypt current and historical canonical Git ciphertext"
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_target_artifact(
    cache: &nix_seal_cache::Cache,
    policy: &nix_seal_policy::TargetPolicyV1,
    target_policy_hash: &str,
    secret_policy: &nix_seal_policy::TargetSecretPolicyV1,
    repository_root: &Path,
    target: &nix_seal_core::Id,
    secret: &nix_seal_core::Id,
    administrator_identity: Option<&SecretString>,
    generation: u64,
    issued_at: u64,
    expires_at: Option<u64>,
    signing_key: &nix_seal_manifest::ApprovalSigningKey,
) -> Result<(nix_seal_rekey::RekeyResult, &'static str)> {
    let source = existing_secret_path(repository_root, &secret_policy.source)?;
    match secret_policy.delivery {
        nix_seal_core::DeliveryMode::Rekeyed => {
            let administrator_identity = administrator_identity.context(
                "--identity is required to rekey administrator-encrypted canonical ciphertext",
            )?;
            let request = nix_seal_rekey::RekeyRequest {
                source: &source,
                administrator_identity,
                target_recipient: &policy.recipient,
                plan_hash: &policy.plan_hash,
                target_policy_hash,
                target_id: target,
                secret_id: secret,
                artifact_generation: generation,
                issued_at,
                expires_at,
                tool_version: env!("CARGO_PKG_VERSION"),
                signing_key,
            };
            Ok((nix_seal_rekey::rekey(cache, &request)?, "rekeyed"))
        }
        nix_seal_core::DeliveryMode::Direct => {
            let request = nix_seal_rekey::DirectRequest {
                source: &source,
                target_recipient: &policy.recipient,
                plan_hash: &policy.plan_hash,
                target_policy_hash,
                target_id: target,
                secret_id: secret,
                artifact_generation: generation,
                issued_at,
                expires_at,
                tool_version: env!("CARGO_PKG_VERSION"),
                signing_key,
            };
            Ok((nix_seal_rekey::stage_direct(cache, &request)?, "direct"))
        }
    }
}

fn ensure_signing_key_authorized(
    secret_policy: &nix_seal_policy::TargetSecretPolicyV1,
    signing_key: &nix_seal_manifest::ApprovalSigningKey,
    secret: &nix_seal_core::Id,
) -> Result<()> {
    if !secret_policy
        .approval
        .signers
        .values()
        .any(|public| signing_key.matches_public_key(public))
    {
        bail!("signing key is not authorized by the approval policy for secret {secret}");
    }
    Ok(())
}

fn ensure_rekey_identity_authorized(
    plan: &nix_seal_core::PlanV1,
    secret: &nix_seal_core::Id,
    identity: Option<&SecretString>,
) -> Result<()> {
    let identity = identity
        .context("--identity is required to rekey administrator-encrypted canonical ciphertext")?;
    let recipients = nix_seal_policy::secret_recipients(plan, secret)?;
    let authorized = recipients
        .recipients
        .values()
        .any(|candidate| nix_seal_crypto::identity_matches_recipient(identity, candidate));
    if !authorized {
        bail!(
            "identity is not an authorized administrator or recovery recipient for secret {secret}"
        );
    }
    Ok(())
}

fn issue_time(expires_at: Option<u64>) -> Result<u64> {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    if expires_at.is_some_and(|expiry| expiry <= issued_at) {
        bail!("--expires-at must be later than the current time");
    }
    Ok(issued_at)
}

#[allow(clippy::too_many_lines)]
fn run_provision(arguments: ProvisionArgs, json: bool) -> Result<()> {
    let plan = read_plan_bounded(&arguments.plan)?;
    let policy = nix_seal_policy::target_policy(&plan, &arguments.target)?;
    let target_policy_hash = nix_seal_policy::target_policy_hash(&policy)?;
    let signing_key = read_signing_key(&arguments.signing_key)?;
    let issued_at = issue_time(arguments.expires_at)?;
    let identity = arguments
        .identity
        .as_deref()
        .map(read_identity)
        .transpose()?;

    let mut prepared = Vec::with_capacity(policy.secrets.len());
    for (secret, secret_policy) in &policy.secrets {
        ensure_signing_key_authorized(secret_policy, &signing_key, secret)?;
        if matches!(secret_policy.delivery, nix_seal_core::DeliveryMode::Rekeyed) {
            ensure_rekey_identity_authorized(&plan, secret, identity.as_ref())?;
        }
        let path = existing_secret_path(&arguments.repository_root, &secret_policy.source)?;
        let file = open_public_ciphertext(&path)?;
        nix_seal_crypto::validate_ciphertext_header(file)
            .with_context(|| format!("canonical ciphertext for {secret} is malformed"))?;
        prepared.push((
            secret.clone(),
            secret_policy,
            canonical_ciphertext_hash(&arguments.repository_root, &secret_policy.source)?,
            nix_seal_crypto::recipient_fingerprint(&policy.recipient)?,
        ));
    }

    if !arguments.execute {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "schema":"nix-seal.provision.v1",
                    "executed":false,
                    "target":arguments.target,
                    "planHash":policy.plan_hash,
                    "generation":arguments.generation,
                    "artifacts":prepared.iter().map(|(secret, secret_policy, source_hash, recipient)| serde_json::json!({
                        "secretId":secret,
                        "delivery":secret_policy.delivery,
                        "sourceCiphertextHash":source_hash,
                        "recipientFingerprint":recipient
                    })).collect::<Vec<_>>()
                })
            );
        } else {
            println!(
                "validated {} target artifact(s) for {}; rerun with --execute to write the ciphertext cache",
                prepared.len(),
                arguments.target
            );
            for (secret, secret_policy, _, _) in &prepared {
                println!("{}\t{}", secret, delivery_name(&secret_policy.delivery));
            }
        }
        return Ok(());
    }

    let root = arguments.cache_root.unwrap_or_else(default_cache_root);
    let cache = nix_seal_cache::Cache::open(root)?;
    let mut artifacts = Vec::with_capacity(prepared.len());
    for (secret, secret_policy, _, _) in prepared {
        let (result, delivery) = create_target_artifact(
            &cache,
            &policy,
            &target_policy_hash,
            secret_policy,
            &arguments.repository_root,
            &arguments.target,
            &secret,
            identity.as_ref(),
            arguments.generation,
            issued_at,
            arguments.expires_at,
            &signing_key,
        )?;
        artifacts.push((secret, delivery, result));
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.provision.v1",
                "executed":true,
                "target":arguments.target,
                "planHash":policy.plan_hash,
                "generation":arguments.generation,
                "artifacts":artifacts.iter().map(|(secret, delivery, result)| serde_json::json!({
                    "secretId":secret,
                    "delivery":delivery,
                    "cacheKey":result.cache_key,
                    "sourceCiphertextHash":result.source_ciphertext_hash,
                    "artifactCiphertextHash":result.artifact_ciphertext_hash,
                    "recipientFingerprint":result.recipient_fingerprint,
                    "ciphertextPath":result.ciphertext_path,
                    "reused":result.reused
                })).collect::<Vec<_>>()
            })
        );
    } else {
        println!(
            "provisioned {} target artifact(s) for {} generation {}",
            artifacts.len(),
            arguments.target,
            arguments.generation
        );
        for (secret, delivery, result) in &artifacts {
            println!("{}\t{}\t{}", secret, delivery, result.cache_key);
        }
    }
    Ok(())
}

fn delivery_name(delivery: &nix_seal_core::DeliveryMode) -> &'static str {
    match delivery {
        nix_seal_core::DeliveryMode::Rekeyed => "rekeyed",
        nix_seal_core::DeliveryMode::Direct => "direct",
    }
}

fn verify_activation_projection(
    spec: &nix_seal_runtime::ActivationSpecV2,
    policy: &nix_seal_policy::TargetPolicyV1,
) -> Result<()> {
    if spec.target_id != policy.target_id {
        bail!("activation metadata does not match the deterministic target policy");
    }

    let artifact_ids: BTreeSet<_> = spec
        .artifacts
        .iter()
        .map(|artifact| &artifact.secret_id)
        .collect();
    let policy_secret_ids: BTreeSet<_> = policy
        .secrets
        .iter()
        .filter_map(|(id, secret)| (secret.phase == spec.phase).then_some(id))
        .collect();
    if artifact_ids != policy_secret_ids {
        bail!("activation artifact set does not exactly match target policy");
    }
    for artifact in &spec.artifacts {
        let secret = policy.secrets.get(&artifact.secret_id).ok_or_else(|| {
            anyhow::anyhow!(
                "artifact secret {} is absent from target policy",
                artifact.secret_id
            )
        })?;
        if artifact.phase != secret.phase
            || artifact.owner != secret.runtime.owner
            || artifact.group != secret.runtime.group
            || artifact.mode != secret.runtime.mode
        {
            bail!(
                "runtime policy for secret {} differs from the canonical plan",
                artifact.secret_id
            );
        }
    }

    let template_ids: BTreeSet<_> = spec
        .templates
        .iter()
        .map(|template| &template.template_id)
        .collect();
    let policy_template_ids: BTreeSet<_> = policy
        .templates
        .iter()
        .filter_map(|(id, template)| (template.phase == spec.phase).then_some(id))
        .collect();
    if template_ids != policy_template_ids {
        bail!("activation template set does not exactly match target policy");
    }
    let plan_parent = spec
        .plan
        .parent()
        .context("compiled plan path has no parent")?;
    for template in &spec.templates {
        let expected = policy.templates.get(&template.template_id).ok_or_else(|| {
            anyhow::anyhow!(
                "template {} is absent from target policy",
                template.template_id
            )
        })?;
        let expected_source = Path::new(&expected.source);
        let expected_source = if expected_source.is_absolute() {
            expected_source.to_owned()
        } else {
            plan_parent.join(expected_source)
        };
        let placeholders_match = template.placeholders.len() == expected.placeholders.len()
            && template.placeholders.iter().all(|(name, actual)| {
                expected.placeholders.get(name).is_some_and(|expected| {
                    actual.secret_id == expected.secret
                        && matches!(
                            (actual.encoding, expected.encoding),
                            (
                                nix_seal_runtime::TemplateEncodingV1::Utf8,
                                nix_seal_core::TemplateEncoding::Utf8
                            ) | (
                                nix_seal_runtime::TemplateEncodingV1::Base64,
                                nix_seal_core::TemplateEncoding::Base64
                            ) | (
                                nix_seal_runtime::TemplateEncodingV1::Hex,
                                nix_seal_core::TemplateEncoding::Hex
                            )
                        )
                })
            });
        if template.phase != expected.phase
            || template.source != expected_source
            || template.owner != expected.runtime.owner
            || template.group != expected.runtime.group
            || template.mode != expected.runtime.mode
            || !placeholders_match
        {
            bail!(
                "runtime policy for template {} differs from the canonical plan",
                template.template_id
            );
        }
    }

    verify_service_projection(spec, policy)
}

fn verify_service_projection(
    spec: &nix_seal_runtime::ActivationSpecV2,
    policy: &nix_seal_policy::TargetPolicyV1,
) -> Result<()> {
    let mut restart_units = BTreeSet::new();
    let mut reload_units = BTreeSet::new();
    for runtime in policy
        .secrets
        .values()
        .filter(|secret| secret.phase == spec.phase)
        .map(|secret| &secret.runtime)
        .chain(
            policy
                .templates
                .values()
                .filter(|template| template.phase == spec.phase)
                .map(|template| &template.runtime),
        )
    {
        restart_units.extend(runtime.restart_units.iter().cloned());
        reload_units.extend(runtime.reload_units.iter().cloned());
    }
    if !restart_units.is_disjoint(&reload_units) {
        bail!("canonical plan assigns a unit to both restart and reload actions");
    }
    if restart_units.is_empty() && reload_units.is_empty() {
        if spec.post_switch.is_some() {
            bail!("activation declares service actions absent from target policy");
        }
        return Ok(());
    }
    let actions = spec
        .post_switch
        .as_ref()
        .context("activation omits service actions required by target policy")?;
    let expected_manager = match policy.target_kind {
        nix_seal_core::TargetKind::NixOs => nix_seal_runtime::ServiceManagerV1::SystemdSystem,
        nix_seal_core::TargetKind::Darwin => nix_seal_runtime::ServiceManagerV1::LaunchdSystem,
        nix_seal_core::TargetKind::HomeManager if policy.system.ends_with("-linux") => {
            nix_seal_runtime::ServiceManagerV1::SystemdUser
        }
        nix_seal_core::TargetKind::HomeManager if policy.system.ends_with("-darwin") => {
            nix_seal_runtime::ServiceManagerV1::LaunchdUser
        }
        nix_seal_core::TargetKind::HomeManager => {
            bail!("Home Manager target has an unsupported system value")
        }
    };
    if actions.manager != expected_manager
        || actions
            .restart_units
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != restart_units
        || actions
            .reload_units
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != reload_units
    {
        bail!("activation service actions differ from the canonical target policy");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_generate(arguments: &GenerateArgs, json: bool) -> Result<()> {
    struct GeneratedSecret {
        id: nix_seal_core::Id,
        source: String,
        plaintext: SecretBox<Vec<u8>>,
        recipients: Vec<String>,
    }
    struct GeneratedPublic {
        id: nix_seal_core::Id,
        destination: String,
        plaintext: SecretBox<Vec<u8>>,
    }

    let plan = read_plan_bounded(&arguments.plan)?;
    let identity = read_identity(&arguments.identity)?;
    let mut order = Vec::new();
    collect_generator_order(
        &plan,
        &arguments.generator,
        &mut BTreeSet::new(),
        &mut order,
    )?;
    let prompt_files = validate_generator_prompt_files(
        &plan,
        &order,
        &arguments.prompt_files,
        &arguments.repository_root,
        arguments.interactive,
    )?;
    let mut outputs = Vec::new();
    for generator_id in order {
        let generator = plan
            .generators
            .get(&generator_id)
            .context("generator disappeared from validated plan")?;
        let action = generator_action(
            &plan,
            &generator_id,
            generator,
            &arguments.repository_root,
            arguments.replace,
        )?;
        if action == GeneratorAction::Unchanged {
            for secret_id in &generator.outputs {
                let secret = plan
                    .secrets
                    .get(secret_id)
                    .context("generator output secret disappeared from validated plan")?;
                outputs.push(serde_json::json!({
                    "generator":generator_id,
                    "secretId":secret_id,
                    "ciphertextPath":existing_secret_path(&arguments.repository_root, &secret.source)?,
                    "action":"unchanged"
                }));
            }
            for public_output in &generator.public_outputs {
                let path = existing_public_output_path(
                    &arguments.repository_root,
                    &public_output.destination,
                )?;
                outputs.push(serde_json::json!({
                    "generator":generator_id,
                    "publicOutputId":public_output.id,
                    "path":path,
                    "action":"unchanged"
                }));
            }
            continue;
        }
        let prompt_values = read_generator_prompts(generator, &prompt_files)?;
        let generated_values = generate_generator_values(
            generator,
            &prompt_values,
            GeneratorSecretInputs::Plan {
                plan: &plan,
                repository_root: &arguments.repository_root,
                identity: &identity,
            },
        )?;
        if generated_values.secrets.len() != generator.outputs.len()
            || generated_values.public.len() != generator.public_outputs.len()
        {
            bail!("generator produced an unexpected output count");
        }
        let generated = generator
            .outputs
            .iter()
            .zip(generated_values.secrets)
            .map(|(secret_id, plaintext)| {
                let secret = plan
                    .secrets
                    .get(secret_id)
                    .context("generator output secret disappeared from validated plan")?;
                let recipients = nix_seal_policy::secret_recipients(&plan, secret_id)?;
                Ok(GeneratedSecret {
                    id: secret_id.clone(),
                    source: secret.source.clone(),
                    plaintext,
                    recipients: recipients.recipients.into_values().collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let generated_public = generator
            .public_outputs
            .iter()
            .zip(generated_values.public)
            .map(|(output, plaintext)| GeneratedPublic {
                id: output.id.clone(),
                destination: output.destination.clone(),
                plaintext,
            })
            .collect::<Vec<_>>();
        let writes = generated
            .iter()
            .map(|output| nix_seal_authoring::BatchSecretWrite {
                relative_destination: Path::new(&output.source),
                plaintext: output.plaintext.expose_secret(),
                recipients: &output.recipients,
            })
            .collect::<Vec<_>>();
        let public_writes = generated_public
            .iter()
            .map(|output| nix_seal_authoring::BatchPublicWrite {
                relative_destination: Path::new(&output.destination),
                plaintext: output.plaintext.expose_secret(),
            })
            .collect::<Vec<_>>();
        let mode = match action {
            GeneratorAction::Create => nix_seal_authoring::WriteMode::Create,
            GeneratorAction::Replace => nix_seal_authoring::WriteMode::Replace,
            GeneratorAction::Unchanged => bail!("unchanged generator reached write transaction"),
        };
        let results = nix_seal_authoring::write_secret_and_public_batch(
            &arguments.repository_root,
            &writes,
            &public_writes,
            &identity,
            mode,
        )?;
        persist_generator_prompts(
            &arguments.repository_root,
            &generator_id,
            generator,
            &prompt_values,
        )?;
        if let Some(validation) = &generator.validation {
            write_generator_state(
                &arguments.repository_root,
                &generator_id,
                validation,
                &generator.outputs,
                &generator
                    .public_outputs
                    .iter()
                    .map(|output| output.id.clone())
                    .collect::<Vec<_>>(),
            )?;
        } else {
            remove_generator_state(&arguments.repository_root, &generator_id)?;
        }
        for (output, result) in generated.iter().zip(results.secrets) {
            outputs.push(serde_json::json!({
                "generator":generator_id,
                "secretId":output.id,
                "ciphertextPath":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "plaintextBytes":result.plaintext_bytes,
                "action":match action { GeneratorAction::Create => "created", GeneratorAction::Replace => "replaced", GeneratorAction::Unchanged => "unchanged" }
            }));
        }
        for (output, result) in generated_public.iter().zip(results.public_outputs) {
            outputs.push(serde_json::json!({
                "generator":generator_id,
                "publicOutputId":output.id,
                "path":result.path,
                "contentHash":result.content_hash,
                "plaintextBytes":result.plaintext_bytes,
                "action":match action { GeneratorAction::Create => "created", GeneratorAction::Replace => "replaced", GeneratorAction::Unchanged => "unchanged" }
            }));
        }
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.generation.v1",
                "replaced":arguments.replace,
                "outputs":outputs
            })
        );
    } else {
        for output in outputs {
            if let (Some(secret_id), Some(path)) = (
                output["secretId"].as_str(),
                output["ciphertextPath"].as_str(),
            ) {
                println!("generated {secret_id} -> {path}");
            } else if let (Some(output_id), Some(path)) =
                (output["publicOutputId"].as_str(), output["path"].as_str())
            {
                println!("generated public output {output_id} -> {path}");
            } else {
                bail!("generation result omitted a stable output identifier or path");
            }
        }
    }
    Ok(())
}

/// Selects a safe generator action from explicit replacement intent, the
/// public validation fingerprint, and complete canonical-output presence.
fn generator_action(
    plan: &nix_seal_core::PlanV1,
    generator_id: &nix_seal_core::Id,
    generator: &nix_seal_core::Generator,
    repository_root: &Path,
    explicit_replace: bool,
) -> Result<GeneratorAction> {
    if explicit_replace {
        return Ok(GeneratorAction::Replace);
    }
    let present = generator
        .outputs
        .iter()
        .map(|secret_id| {
            // Policy validation already guarantees every generator output has a
            // secret. A missing or unsafe ciphertext counts as absent only if
            // it genuinely does not exist; unsafe existing paths fail closed.
            let secret = plan
                .secrets
                .get(secret_id)
                .context("generator output secret disappeared from validated plan")?;
            match existing_secret_path(repository_root, &secret.source) {
                Ok(_) => Ok(Some(secret_id)),
                Err(error) if is_missing_canonical_ciphertext(&error) => Ok(None),
                Err(error) => Err(error),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let public_present = generator
        .public_outputs
        .iter()
        .map(
            |output| match existing_public_output_path(repository_root, &output.destination) {
                Ok(_) => Ok(Some(output)),
                Err(error) if is_missing_canonical_ciphertext(&error) => Ok(None),
                Err(error) => Err(error),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    let present_count = present.iter().flatten().count();
    let public_present_count = public_present.iter().flatten().count();
    let total_outputs = generator
        .outputs
        .len()
        .checked_add(generator.public_outputs.len())
        .context("generator output count overflow")?;
    let total_present = present_count
        .checked_add(public_present_count)
        .context("generator output count overflow")?;
    if total_present != 0 && total_present != total_outputs {
        bail!("generator {generator_id} has a partial output set; repair it with --replace");
    }
    let Some(validation) = generator.validation.as_deref() else {
        return Ok(GeneratorAction::Create);
    };
    let state = read_generator_state(repository_root, generator_id)?;
    match state {
        Some(state)
            if state.validation == validation
                && state.outputs == generator.outputs
                && state.public_outputs
                    == generator
                        .public_outputs
                        .iter()
                        .map(|output| output.id.clone())
                        .collect::<Vec<_>>() =>
        {
            if total_present == total_outputs {
                Ok(GeneratorAction::Unchanged)
            } else {
                Ok(GeneratorAction::Create)
            }
        }
        Some(_) if total_present == total_outputs => Ok(GeneratorAction::Replace),
        Some(_) => Ok(GeneratorAction::Create),
        None if total_present == 0 => Ok(GeneratorAction::Create),
        None => bail!(
            "generator {generator_id} outputs exist without validation state; pass --replace to establish an explicit validation baseline"
        ),
    }
}

fn is_missing_canonical_ciphertext(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

fn generator_state_path(
    repository_root: &Path,
    generator_id: &nix_seal_core::Id,
) -> Result<PathBuf> {
    let root = repository_root
        .canonicalize()
        .context("repository root must exist for generator state")?;
    let mut directory = root;
    for component in [".nix-seal", "generator-state", "v1"] {
        directory.push(component);
        match fs::create_dir(&directory) {
            Ok(()) => set_private_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            bail!("generator state directory has unsafe type");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0
            {
                bail!("generator state directory has unsafe ownership or permissions");
            }
        }
    }
    for component in generator_id.as_str().split('/') {
        directory.push(component);
        match fs::create_dir(&directory) {
            Ok(()) => set_private_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            bail!("generator state directory has unsafe type");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0
            {
                bail!("generator state directory has unsafe ownership or permissions");
            }
        }
    }
    Ok(directory.join("state.json"))
}

fn read_generator_state(
    repository_root: &Path,
    generator_id: &nix_seal_core::Id,
) -> Result<Option<GeneratorStateV1>> {
    let path = generator_state_path(repository_root, generator_id)?;
    if !path.exists() {
        return Ok(None);
    }
    let input = open_private_identity(&path)
        .context("generator validation state has unsafe ownership or permissions")?;
    let mut bytes = Vec::new();
    input
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("could not read generator validation state")?;
    if bytes.len() > 64 * 1024 {
        bail!("generator validation state exceeds the 64 KiB safety limit");
    }
    let state: GeneratorStateV1 =
        serde_json::from_slice(&bytes).context("generator validation state is malformed")?;
    if state.schema != GENERATOR_STATE_SCHEMA || state.generator_id != *generator_id {
        bail!("generator validation state has an incompatible schema or ID");
    }
    Ok(Some(state))
}

fn write_generator_state(
    repository_root: &Path,
    generator_id: &nix_seal_core::Id,
    validation: &str,
    outputs: &[nix_seal_core::Id],
    public_outputs: &[nix_seal_core::Id],
) -> Result<()> {
    let path = generator_state_path(repository_root, generator_id)?;
    let parent = path
        .parent()
        .context("generator state path has no parent")?;
    let bytes = serde_jcs::to_vec(&GeneratorStateV1 {
        schema: GENERATOR_STATE_SCHEMA.to_owned(),
        generator_id: generator_id.clone(),
        validation: validation.to_owned(),
        outputs: outputs.to_vec(),
        public_outputs: public_outputs.to_vec(),
    })?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .context("could not stage generator validation state")?;
    set_private_file(staged.path())?;
    staged
        .write_all(&bytes)
        .and_then(|()| staged.as_file().sync_all())
        .context("could not write generator validation state")?;
    staged
        .persist(&path)
        .map_err(|error| error.error)
        .context("could not atomically publish generator validation state")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("generator validation state changed but directory durability is unknown")?;
    Ok(())
}

fn remove_generator_state(repository_root: &Path, generator_id: &nix_seal_core::Id) -> Result<()> {
    let path = generator_state_path(repository_root, generator_id)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            fs::File::open(
                path.parent()
                    .context("generator state path has no parent")?,
            )?
            .sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Resolves the owner-only repository state path for a persistent prompt.
///
/// Prompt values are deliberately kept outside the public plan and outside
/// canonical ciphertext. The private state tree is created component by
/// component so an attacker cannot replace an ancestor with a symlink between
/// runs. IDs are already validated by the policy layer and therefore provide
/// safe relative components here.
fn generator_prompt_state_path(
    repository_root: &Path,
    generator_id: &nix_seal_core::Id,
    prompt_id: &nix_seal_core::Id,
) -> Result<PathBuf> {
    let root = repository_root
        .canonicalize()
        .context("repository root must exist for persistent prompt state")?;
    let mut directory = root;
    for component in [".nix-seal", "prompt-state", "v1"] {
        directory.push(component);
        ensure_private_directory(&directory)?;
    }
    for component in generator_id.as_str().split('/') {
        directory.push(component);
        ensure_private_directory(&directory)?;
    }
    let mut prompt_components = prompt_id.as_str().split('/').peekable();
    while let Some(component) = prompt_components.next() {
        directory.push(component);
        if prompt_components.peek().is_some() {
            ensure_private_directory(&directory)?;
        }
    }
    Ok(directory)
}

/// Stores declared persistent prompts only after all generated ciphertext
/// outputs have committed. A failed generation therefore cannot update the
/// remembered response. The replacement is staged and durable before rename.
fn persist_generator_prompts(
    repository_root: &Path,
    generator_id: &nix_seal_core::Id,
    generator: &nix_seal_core::Generator,
    prompts: &[SecretBox<Vec<u8>>],
) -> Result<()> {
    if prompts.len() != generator.prompts.len() {
        bail!("generator prompt count changed during generation");
    }
    for (prompt, value) in generator.prompts.iter().zip(prompts) {
        if prompt.persistent {
            let path = generator_prompt_state_path(repository_root, generator_id, &prompt.id)?;
            write_private_bytes_atomic(&path, value.expose_secret())?;
        }
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("persistent prompt state directory has unsafe type");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            bail!("persistent prompt state directory has unsafe ownership or permissions");
        }
    }
    Ok(())
}

fn write_private_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("persistent prompt state path has no parent")?;
    ensure_private_directory(parent)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            // Reject links and hard links before allowing replacement. The
            // rename below replaces the directory entry, never follows a
            // symlink.
            open_private_identity(path)
                .context("persistent prompt state file has unsafe metadata")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .context("could not stage persistent prompt state")?;
    set_private_file(staged.path())?;
    staged
        .write_all(bytes)
        .and_then(|()| staged.as_file().sync_all())
        .context("could not write persistent prompt state")?;
    staged
        .persist(path)
        .map_err(|error| error.error)
        .context("could not atomically publish persistent prompt state")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .context("persistent prompt state changed but directory durability is unknown")?;
    Ok(())
}

fn validate_generator_prompt_files(
    plan: &nix_seal_core::PlanV1,
    order: &[nix_seal_core::Id],
    values: &[String],
    repository_root: &Path,
    interactive: bool,
) -> Result<BTreeMap<nix_seal_core::Id, Option<PathBuf>>> {
    let explicit = parse_prompt_files(values)?;
    let mut declared = BTreeMap::new();
    for generator_id in order {
        for prompt in &plan.generators[generator_id].prompts {
            if declared
                .insert(prompt.id.clone(), (generator_id.clone(), prompt.persistent))
                .is_some()
            {
                bail!("prompt IDs must be unique across the selected generator graph");
            }
        }
    }
    if explicit
        .keys()
        .any(|prompt_id| !declared.contains_key(prompt_id))
    {
        bail!("prompt files must refer only to prompts declared by the selected generator graph");
    }
    let mut resolved = BTreeMap::new();
    for (prompt_id, (generator_id, persistent)) in declared {
        if let Some(path) = explicit.get(&prompt_id) {
            resolved.insert(prompt_id, Some(path.clone()));
        } else if persistent {
            let path = generator_prompt_state_path(repository_root, &generator_id, &prompt_id)?;
            if path.exists() {
                resolved.insert(prompt_id, Some(path));
            } else if interactive {
                resolved.insert(prompt_id, None);
            } else {
                bail!(
                    "persistent prompt {prompt_id} has no stored response; initialize it with --prompt-file {prompt_id}=PATH or pass --interactive"
                );
            }
        } else if interactive {
            resolved.insert(prompt_id, None);
        } else {
            bail!(
                "prompt {prompt_id} requires an explicit private response file (--prompt-file {prompt_id}=PATH) or --interactive"
            );
        }
    }
    Ok(resolved)
}

#[derive(Clone, Copy)]
enum GeneratorSecretInputs<'a> {
    /// Materialize explicitly declared canonical sources from this validated plan.
    Plan {
        plan: &'a nix_seal_core::PlanV1,
        repository_root: &'a Path,
        identity: &'a SecretString,
    },
    /// Test-only or built-in invocation without private canonical inputs.
    #[allow(dead_code)]
    // Used by the in-process generator tests; production always has a plan.
    None,
}

struct GeneratedValues {
    secrets: Vec<SecretBox<Vec<u8>>>,
    public: Vec<SecretBox<Vec<u8>>>,
}

fn generate_generator_values(
    generator: &nix_seal_core::Generator,
    prompts: &[SecretBox<Vec<u8>>],
    secret_inputs: GeneratorSecretInputs<'_>,
) -> Result<GeneratedValues> {
    if generator.executable.starts_with("builtin:") {
        if generator.executable == "builtin:argon2id-password-hash" {
            return Ok(GeneratedValues {
                secrets: vec![generate_argon2id_password_hash(generator, prompts)?],
                public: Vec::new(),
            });
        }
        if !prompts.is_empty() {
            bail!("built-in generators do not accept prompts");
        }
        if !generator.secret_dependencies.is_empty() {
            bail!("built-in generators do not accept secret dependencies");
        }
        return Ok(GeneratedValues {
            secrets: generator
                .outputs
                .iter()
                .map(|_| generate_builtin_value(generator))
                .collect::<Result<Vec<_>>>()?,
            public: Vec::new(),
        });
    }
    generate_external_values(generator, prompts, secret_inputs)
}

#[allow(clippy::too_many_lines)]
fn generate_external_values(
    generator: &nix_seal_core::Generator,
    prompts: &[SecretBox<Vec<u8>>],
    secret_inputs: GeneratorSecretInputs<'_>,
) -> Result<GeneratedValues> {
    let workspace = tempfile::Builder::new()
        .prefix("nix-seal-generator-")
        .tempdir()
        .context("could not create private generator workspace")?;
    set_private_directory(workspace.path())?;
    let output_directory = workspace.path().join("outputs");
    fs::create_dir(&output_directory)
        .context("could not create private generator output directory")?;
    set_private_directory(&output_directory)?;
    let public_output_directory = workspace.path().join("public-outputs");
    fs::create_dir(&public_output_directory)
        .context("could not create private generator public-output directory")?;
    set_private_directory(&public_output_directory)?;
    let prompt_directory = workspace.path().join("prompts");
    fs::create_dir(&prompt_directory)
        .context("could not create private generator prompt directory")?;
    set_private_directory(&prompt_directory)?;
    for (index, value) in prompts.iter().enumerate() {
        write_private_bytes(
            &prompt_directory.join(index.to_string()),
            value.expose_secret(),
        )?;
    }
    let secret_directory = workspace.path().join("secrets");
    fs::create_dir(&secret_directory)
        .context("could not create private generator secret directory")?;
    set_private_directory(&secret_directory)?;
    materialize_generator_secret_dependencies(generator, secret_inputs, &secret_directory)?;
    let runtime_path = std::env::join_paths(
        generator
            .runtime_inputs
            .iter()
            .map(|input| Path::new(input).join("bin")),
    )
    .context("generator runtime inputs cannot form a safe PATH")?;
    let mut command = ProcessCommand::new(&generator.executable);
    command
        .args(&generator.arguments)
        .env_clear()
        .env("PATH", runtime_path)
        .env("HOME", workspace.path())
        .env("TMPDIR", workspace.path())
        .env("NIX_SEAL_OUTPUT_DIR", &output_directory)
        .env("NIX_SEAL_OUTPUT_COUNT", generator.outputs.len().to_string())
        .env("NIX_SEAL_PUBLIC_OUTPUT_DIR", &public_output_directory)
        .env(
            "NIX_SEAL_PUBLIC_OUTPUT_COUNT",
            generator.public_outputs.len().to_string(),
        )
        .env("NIX_SEAL_PROMPT_DIR", &prompt_directory)
        .env("NIX_SEAL_PROMPT_COUNT", prompts.len().to_string())
        .env("NIX_SEAL_SECRET_DIR", &secret_directory)
        .env(
            "NIX_SEAL_SECRET_COUNT",
            generator.secret_dependencies.len().to_string(),
        )
        .current_dir(workspace.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    isolate_child_process_group(&mut command);
    let mut child = command
        .spawn()
        .context("could not start constrained generator")?;
    let deadline = Instant::now() + Duration::from_secs(u64::from(generator.timeout_seconds));
    loop {
        match child
            .try_wait()
            .context("could not observe constrained generator")?
        {
            Some(status) if status.success() => break,
            Some(_) => bail!("constrained generator failed"),
            None if Instant::now() >= deadline => {
                terminate_child_process_tree(&mut child);
                bail!("constrained generator timed out");
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    let expected = (0..generator.outputs.len())
        .map(|index| index.to_string())
        .collect::<BTreeSet<_>>();
    let actual = fs::read_dir(&output_directory)
        .context("could not inspect constrained generator outputs")?
        .map(|entry| {
            let entry = entry.context("could not inspect constrained generator output")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("generator output name is not UTF-8"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .context("could not inspect constrained generator output metadata")?;
            if !metadata.file_type().is_file() {
                bail!("constrained generator created a non-regular output");
            }
            Ok(name)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if actual != expected {
        bail!("constrained generator created undeclared or missing outputs");
    }
    let secrets = expected
        .iter()
        .map(|name| read_generator_output(&output_directory.join(name), generator.max_output_bytes))
        .collect::<Result<Vec<_>>>()?;
    let expected_public = generator
        .public_outputs
        .iter()
        .enumerate()
        .map(|(index, _)| index.to_string())
        .collect::<BTreeSet<_>>();
    let actual_public = fs::read_dir(&public_output_directory)
        .context("could not inspect constrained generator public outputs")?
        .map(|entry| {
            let entry = entry.context("could not inspect constrained generator public output")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("generator public output name is not UTF-8"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .context("could not inspect constrained generator public output metadata")?;
            if !metadata.file_type().is_file() {
                bail!("constrained generator public output is not a regular file");
            }
            Ok(name)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if actual_public != expected_public {
        bail!("constrained generator created undeclared or missing public outputs");
    }
    let public = expected_public
        .iter()
        .map(|name| {
            read_generator_output(
                &public_output_directory.join(name),
                generator.max_output_bytes,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(GeneratedValues { secrets, public })
}

fn materialize_generator_secret_dependencies(
    generator: &nix_seal_core::Generator,
    secret_inputs: GeneratorSecretInputs<'_>,
    secret_directory: &Path,
) -> Result<()> {
    if generator.secret_dependencies.is_empty() {
        return Ok(());
    }
    let GeneratorSecretInputs::Plan {
        plan,
        repository_root,
        identity,
    } = secret_inputs
    else {
        bail!("external generator secret dependencies require a validated plan context");
    };
    for (index, secret_id) in generator.secret_dependencies.iter().enumerate() {
        let recipients = nix_seal_policy::secret_recipients(plan, secret_id)?;
        let authorized = recipients
            .recipients
            .values()
            .any(|recipient| nix_seal_crypto::identity_matches_recipient(identity, recipient));
        if !authorized {
            bail!(
                "generator identity is not authorized by canonical recipient policy for {secret_id}"
            );
        }
        let secret = plan
            .secrets
            .get(secret_id)
            .context("generator secret dependency is absent from plan")?;
        let ciphertext_path = existing_secret_path(repository_root, &secret.source)?;
        let ciphertext = open_public_ciphertext(&ciphertext_path)?;
        let output_path = secret_directory.join(index.to_string());
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .context("could not create private generator secret dependency")?;
        set_private_file(&output_path)?;
        nix_seal_crypto::decrypt(ciphertext, &mut output, identity).with_context(|| {
            format!("could not decrypt generator secret dependency {secret_id}")
        })?;
        output
            .sync_all()
            .context("could not durably stage generator secret dependency")?;
    }
    Ok(())
}

fn read_generator_output(path: &Path, maximum: u64) -> Result<SecretBox<Vec<u8>>> {
    let metadata =
        fs::symlink_metadata(path).context("could not inspect constrained generator output")?;
    if !metadata.file_type().is_file() || metadata.len() > maximum {
        bail!("constrained generator output is invalid or exceeds its declared limit");
    }
    set_private_file(path)
        .context("could not restrict constrained generator output permissions")?;
    let mut input = open_private_identity(path)
        .context("constrained generator output has unsafe ownership or permissions")?;
    let capacity =
        usize::try_from(metadata.len()).context("generator output length cannot fit memory")?;
    let mut output = Vec::with_capacity(capacity);
    std::io::Read::by_ref(&mut input)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut output)
        .context("could not read constrained generator output")?;
    let length = u64::try_from(output.len()).context("generator output length cannot fit u64")?;
    if length > maximum {
        bail!("constrained generator output exceeded its declared limit");
    }
    Ok(SecretBox::new(Box::new(output)))
}

fn parse_prompt_files(values: &[String]) -> Result<BTreeMap<nix_seal_core::Id, PathBuf>> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (id, path) = value
            .split_once('=')
            .context("prompt file must use ID=PATH")?;
        let id = nix_seal_core::Id::parse(id).context("prompt file has an invalid prompt ID")?;
        let path = PathBuf::from(path);
        if !path.is_absolute() || parsed.insert(id, path).is_some() {
            bail!("prompt files must have unique IDs and absolute paths");
        }
    }
    Ok(parsed)
}

fn read_generator_prompts(
    generator: &nix_seal_core::Generator,
    prompt_files: &BTreeMap<nix_seal_core::Id, Option<PathBuf>>,
) -> Result<Vec<SecretBox<Vec<u8>>>> {
    generator
        .prompts
        .iter()
        .map(|prompt| {
            let path = prompt_files
                .get(&prompt.id)
                .context("declared generator prompt has no response source")?;
            match path {
                Some(path) => {
                    let mut input = open_private_identity(path).context(
                        "generator prompt response file has unsafe ownership or permissions",
                    )?;
                    let mut value = Vec::new();
                    std::io::Read::by_ref(&mut input)
                        .take(1024 * 1024 + 1)
                        .read_to_end(&mut value)
                        .context("could not read generator prompt response")?;
                    if value.len() > 1024 * 1024 {
                        bail!("generator prompt response exceeds the 1 MiB safety limit");
                    }
                    Ok(SecretBox::new(Box::new(value)))
                }
                None => read_tty_prompt(prompt),
            }
        })
        .collect()
}

const MAX_INTERACTIVE_PROMPT_BYTES: usize = 1024 * 1024;

/// Read one declared prompt from a controlling terminal. This frontend is
/// intentionally separate from stdin/stdout so generator pipes cannot consume
/// prompt input or receive prompt bytes. Multiline prompts terminate on an
/// explicit Ctrl-D, while single-line prompts consume one terminal line.
#[cfg(unix)]
fn read_tty_prompt(prompt: &nix_seal_core::GeneratorPrompt) -> Result<SecretBox<Vec<u8>>> {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let mut tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("interactive prompting requires a controlling terminal")?;
    if !rustix::termios::isatty(&tty) {
        bail!("interactive prompting requires a controlling terminal");
    }

    let message = prompt
        .message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    tty.write_all(message.as_bytes())
        .and_then(|()| {
            if prompt.multiline {
                tty.write_all(b" (finish with Ctrl-D): ")
            } else {
                tty.write_all(b": ")
            }
        })
        .and_then(|()| tty.flush())
        .context("could not write interactive prompt")?;

    let original = tcgetattr(&tty).context("could not inspect terminal settings")?;
    let restore_tty = tty
        .try_clone()
        .context("could not duplicate terminal handle")?;
    let restore = TerminalModeGuard {
        tty: restore_tty,
        original: Some(original.clone()),
    };
    if matches!(prompt.mode, nix_seal_core::GeneratorPromptMode::Hidden) {
        let mut masked = original;
        masked
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL);
        tcsetattr(&tty, OptionalActions::Flush, &masked)
            .context("could not disable terminal echo for hidden prompt")?;
    }

    let mut value = Vec::new();
    if prompt.multiline {
        (&mut tty)
            .take((MAX_INTERACTIVE_PROMPT_BYTES + 1) as u64)
            .read_to_end(&mut value)
            .context("could not read interactive prompt response")?;
    } else {
        loop {
            let mut buffer = [0_u8; 4096];
            let read = tty
                .read(&mut buffer)
                .context("could not read interactive prompt response")?;
            if read == 0 {
                break;
            }
            let end = buffer[..read]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(read, |position| position + 1);
            value.extend_from_slice(&buffer[..end]);
            let finished = value.len() > MAX_INTERACTIVE_PROMPT_BYTES || end != read;
            buffer.zeroize();
            if finished {
                break;
            }
        }
    }
    if value.len() > MAX_INTERACTIVE_PROMPT_BYTES {
        bail!("interactive prompt response exceeds the 1 MiB safety limit");
    }
    if !prompt.multiline && value.ends_with(b"\n") {
        value.pop();
        if value.ends_with(b"\r") {
            value.pop();
        }
    }
    drop(restore);
    tty.write_all(b"\n")
        .and_then(|()| tty.flush())
        .context("could not finish interactive prompt")?;
    Ok(SecretBox::new(Box::new(value)))
}

#[cfg(unix)]
struct TerminalModeGuard {
    tty: fs::File,
    original: Option<rustix::termios::Termios>,
}

#[cfg(unix)]
impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = rustix::termios::tcsetattr(
                &self.tty,
                rustix::termios::OptionalActions::Drain,
                &original,
            );
        }
    }
}

#[cfg(not(unix))]
fn read_tty_prompt(_prompt: &nix_seal_core::GeneratorPrompt) -> Result<SecretBox<Vec<u8>>> {
    bail!("interactive prompting is unavailable on this platform")
}

fn collect_generator_order(
    plan: &nix_seal_core::PlanV1,
    generator_id: &nix_seal_core::Id,
    visited: &mut BTreeSet<nix_seal_core::Id>,
    order: &mut Vec<nix_seal_core::Id>,
) -> Result<()> {
    if !visited.insert(generator_id.clone()) {
        return Ok(());
    }
    let generator = plan
        .generators
        .get(generator_id)
        .with_context(|| format!("unknown generator {generator_id}"))?;
    for dependency in &generator.dependencies {
        collect_generator_order(plan, dependency, visited, order)?;
    }
    order.push(generator_id.clone());
    Ok(())
}

fn generate_builtin_value(generator: &nix_seal_core::Generator) -> Result<SecretBox<Vec<u8>>> {
    match generator.executable.as_str() {
        "builtin:random" => Ok(nix_seal_crypto::random_bytes(generator_byte_length(
            generator,
        )?)?),
        "builtin:hex" => {
            let input = nix_seal_crypto::random_bytes(generator_byte_length(generator)?)?;
            let mut output = vec![0_u8; input.expose_secret().len().saturating_mul(2)];
            hex_encode(input.expose_secret(), &mut output)?;
            Ok(SecretBox::new(Box::new(output)))
        }
        "builtin:base64" => {
            let input = nix_seal_crypto::random_bytes(generator_byte_length(generator)?)?;
            Ok(SecretBox::new(Box::new(
                BASE64_STANDARD.encode(input.expose_secret()).into_bytes(),
            )))
        }
        "builtin:token" => {
            let input = nix_seal_crypto::random_bytes(generator_byte_length(generator)?)?;
            Ok(SecretBox::new(Box::new(
                URL_SAFE_NO_PAD.encode(input.expose_secret()).into_bytes(),
            )))
        }
        "builtin:passphrase" => generate_passphrase(generator),
        "builtin:argon2id-password-hash" => {
            bail!("builtin:argon2id-password-hash requires its declared hidden password prompt")
        }
        "builtin:ssh-ed25519" => generate_ssh_ed25519_private_key(generator),
        "builtin:wireguard-private-key" => {
            if !generator.parameters.is_empty() {
                bail!("builtin:wireguard-private-key does not accept parameters");
            }
            let mut input = nix_seal_crypto::random_bytes(32)?;
            let bytes = input.expose_secret_mut();
            // WireGuard uses Curve25519 private scalars. Clamp according to RFC 7748
            // before standard base64 serialization, the format consumed by wg(8).
            bytes[0] &= 0b1111_1000;
            bytes[31] &= 0b0111_1111;
            bytes[31] |= 0b0100_0000;
            Ok(SecretBox::new(Box::new(
                BASE64_STANDARD.encode(bytes).into_bytes(),
            )))
        }
        "builtin:uuid" => {
            if !generator.parameters.is_empty() {
                bail!("builtin:uuid does not accept parameters");
            }
            let mut input = nix_seal_crypto::random_bytes(16)?;
            let bytes = input.expose_secret_mut();
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            let mut output = Vec::with_capacity(36);
            for (index, byte) in bytes.iter().enumerate() {
                if matches!(index, 4 | 6 | 8 | 10) {
                    output.push(b'-');
                }
                output.push(hex_digit(byte >> 4));
                output.push(hex_digit(byte & 0x0f));
            }
            Ok(SecretBox::new(Box::new(output)))
        }
        _ => bail!(
            "generator executable is unsupported; v1 accepts builtin:random, builtin:hex, builtin:base64, builtin:token, builtin:passphrase, builtin:argon2id-password-hash, builtin:ssh-ed25519, builtin:wireguard-private-key, or builtin:uuid"
        ),
    }
}

/// Produces one self-describing Argon2id PHC password hash. The input is read
/// only from the explicitly declared private prompt file; the hash remains a
/// secret output and follows the normal age authoring transaction.
fn generate_argon2id_password_hash(
    generator: &nix_seal_core::Generator,
    prompts: &[SecretBox<Vec<u8>>],
) -> Result<SecretBox<Vec<u8>>> {
    if generator.outputs.len() != 1
        || generator.prompts.len() != 1
        || prompts.len() != 1
        || !matches!(
            generator.prompts[0].mode,
            nix_seal_core::GeneratorPromptMode::Hidden
        )
        || generator.prompts[0].multiline
        || generator.prompts[0].persistent
    {
        bail!(
            "builtin:argon2id-password-hash requires one single-line hidden prompt and one secret output"
        );
    }
    if prompts[0].expose_secret().is_empty() || prompts[0].expose_secret().len() > 1024 {
        bail!("builtin:argon2id-password-hash password input must be 1 to 1024 bytes");
    }
    if generator
        .parameters
        .keys()
        .any(|key| !matches!(key.as_str(), "memory-kib" | "iterations" | "output-length"))
    {
        bail!(
            "builtin:argon2id-password-hash accepts only memory-kib, iterations, and output-length parameters"
        );
    }
    let memory_kib = generator_u32_parameter(generator, "memory-kib", 65_536)?;
    let iterations = generator_u32_parameter(generator, "iterations", 3)?;
    let output_length = generator_u32_parameter(generator, "output-length", 32)?;
    if !(19_456..=524_288).contains(&memory_kib)
        || !(2..=10).contains(&iterations)
        || !(16..=64).contains(&output_length)
    {
        bail!(
            "builtin:argon2id-password-hash parameters require memory-kib 19456..524288, iterations 2..10, and output-length 16..64"
        );
    }
    let output_length = usize::try_from(output_length).context("invalid Argon2id output length")?;
    let params = Params::new(memory_kib, iterations, 1, Some(output_length))
        .map_err(|_| anyhow::anyhow!("invalid bounded Argon2id parameters"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt_bytes = nix_seal_crypto::random_bytes(16)?;
    let salt_encoded = BASE64_STANDARD_NO_PAD.encode(salt_bytes.expose_secret());
    let salt = SaltString::from_b64(&salt_encoded)
        .map_err(|_| anyhow::anyhow!("could not encode Argon2id salt"))?;
    let encoded = Zeroizing::new(
        argon2
            .hash_password(prompts[0].expose_secret(), &salt)
            .map_err(|_| anyhow::anyhow!("Argon2id password hashing failed"))?
            .to_string(),
    );
    Ok(SecretBox::new(Box::new(encoded.as_bytes().to_vec())))
}

fn generator_u32_parameter(
    generator: &nix_seal_core::Generator,
    name: &str,
    default: u32,
) -> Result<u32> {
    generator.parameters.get(name).map_or(Ok(default), |value| {
        value
            .parse::<u32>()
            .with_context(|| format!("builtin:argon2id-password-hash {name} must be an integer"))
    })
}

fn generate_passphrase(generator: &nix_seal_core::Generator) -> Result<SecretBox<Vec<u8>>> {
    if generator.parameters.keys().any(|key| key != "words") {
        bail!("builtin:passphrase accepts only the words parameter");
    }
    let words = generator
        .parameters
        .get("words")
        .map_or(Ok(16_usize), |value| {
            value
                .parse::<usize>()
                .context("builtin:passphrase words must be an integer")
        })?;
    if !(12..=64).contains(&words) {
        bail!("builtin:passphrase words must be between 12 and 64");
    }
    let random = nix_seal_crypto::random_bytes(words)?;
    let mut value = Vec::with_capacity(words.saturating_mul(8));
    for (index, byte) in random.expose_secret().iter().enumerate() {
        if index != 0 {
            value.push(b'-');
        }
        value.extend_from_slice(PASSPHRASE_WORDS[usize::from(byte & 0x3f)].as_bytes());
    }
    Ok(SecretBox::new(Box::new(value)))
}

/// Generates one standard unencrypted OpenSSH Ed25519 private key. The private
/// serialization is itself treated as a secret and immediately passed to the
/// normal age authoring transaction; the public key is derivable from it.
fn generate_ssh_ed25519_private_key(
    generator: &nix_seal_core::Generator,
) -> Result<SecretBox<Vec<u8>>> {
    if !generator.parameters.is_empty() || generator.outputs.len() != 1 {
        bail!("builtin:ssh-ed25519 accepts no parameters and requires exactly one secret output");
    }
    let seed = nix_seal_crypto::random_bytes(32)?;
    let mut secret_seed = Zeroizing::new([0_u8; 32]);
    secret_seed.copy_from_slice(seed.expose_secret());
    let signing_key = SigningKey::from_bytes(&secret_seed);
    let public = signing_key.verifying_key().to_bytes();

    let mut public_blob = Vec::with_capacity(64);
    ssh_write_string(&mut public_blob, b"ssh-ed25519")?;
    ssh_write_string(&mut public_blob, &public)?;

    let check_bytes = nix_seal_crypto::random_bytes(4)?;
    let check = u32::from_be_bytes(
        check_bytes
            .expose_secret()
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid SSH key check value"))?,
    );
    let mut private_blob = Zeroizing::new(Vec::with_capacity(160));
    ssh_write_u32(&mut private_blob, check);
    ssh_write_u32(&mut private_blob, check);
    ssh_write_string(&mut private_blob, b"ssh-ed25519")?;
    ssh_write_string(&mut private_blob, &public)?;
    let mut private_material = Zeroizing::new([0_u8; 64]);
    private_material[..32].copy_from_slice(secret_seed.as_ref());
    private_material[32..].copy_from_slice(&public);
    ssh_write_string(&mut private_blob, private_material.as_ref())?;
    ssh_write_string(&mut private_blob, b"nix-seal")?;
    let padding = 8_usize
        .checked_sub(private_blob.len() % 8)
        .context("SSH private-key padding underflow")?;
    for value in 1..=padding {
        private_blob.push(u8::try_from(value).context("SSH private-key padding overflow")?);
    }

    let mut container = Zeroizing::new(Vec::with_capacity(
        15_usize
            .saturating_add(public_blob.len())
            .saturating_add(private_blob.len()),
    ));
    container.extend_from_slice(b"openssh-key-v1\0");
    ssh_write_string(&mut container, b"none")?;
    ssh_write_string(&mut container, b"none")?;
    ssh_write_string(&mut container, b"")?;
    ssh_write_u32(&mut container, 1);
    ssh_write_string(&mut container, &public_blob)?;
    ssh_write_string(&mut container, &private_blob)?;

    let encoded_length = container
        .len()
        .checked_add(2)
        .context("SSH private-key encoding length overflow")?
        .checked_div(3)
        .context("SSH private-key encoding division failed")?
        .checked_mul(4)
        .context("SSH private-key encoding length overflow")?;
    let mut encoded = Zeroizing::new(vec![0_u8; encoded_length]);
    let written = BASE64_STANDARD
        .encode_slice(&container, &mut encoded)
        .context("could not encode generated SSH private key")?;
    let mut output = Vec::with_capacity(written.saturating_add(96));
    output.extend_from_slice(b"-----BEGIN OPENSSH ");
    output.extend_from_slice(b"PRIVATE KEY-----\n");
    for line in encoded[..written].chunks(70) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END OPENSSH ");
    output.extend_from_slice(b"PRIVATE KEY-----\n");
    Ok(SecretBox::new(Box::new(output)))
}

fn ssh_write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn ssh_write_string(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).context("SSH private-key field exceeds 4 GiB")?;
    ssh_write_u32(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn generator_byte_length(generator: &nix_seal_core::Generator) -> Result<usize> {
    if generator
        .parameters
        .keys()
        .any(|parameter| parameter != "bytes")
    {
        bail!("built-in random generators accept only the bytes parameter");
    }
    let length = generator
        .parameters
        .get("bytes")
        .map_or(Ok(32_usize), |value| value.parse::<usize>())
        .context("generator bytes parameter must be an unsigned integer")?;
    if !(1..=1024 * 1024).contains(&length) {
        bail!("generator bytes parameter must be between 1 and 1048576");
    }
    Ok(length)
}

fn hex_encode(input: &[u8], output: &mut [u8]) -> Result<()> {
    if output.len() != input.len().saturating_mul(2) {
        bail!("generator hex output length overflow");
    }
    for (index, byte) in input.iter().enumerate() {
        let position = index
            .checked_mul(2)
            .context("generator hex index overflow")?;
        output[position] = hex_digit(byte >> 4);
        output[position + 1] = hex_digit(byte & 0x0f);
    }
    Ok(())
}

fn hex_digit(value: u8) -> u8 {
    b"0123456789abcdef"[usize::from(value)]
}

fn run_activate(arguments: &ActivateArgs, json: bool) -> Result<()> {
    let mut spec: nix_seal_runtime::ActivationSpecV2 = read_json_bounded(&arguments.spec)?;
    if let Some(runtime_root) = &arguments.runtime_root {
        spec.runtime_root.clone_from(runtime_root);
    }
    spec.validate()?;
    let plan = read_plan_bounded(&spec.plan)?;
    let policy = nix_seal_policy::target_policy(&plan, &spec.target_id)?;
    verify_activation_projection(&spec, &policy)?;
    let identity = read_identity(&arguments.identity)?;
    ensure_identity_matches_recipient(&identity, &policy.recipient)?;
    let target_policy_hash = nix_seal_policy::target_policy_hash(&policy)?;
    let recipient_fingerprint = nix_seal_crypto::recipient_fingerprint(&policy.recipient)?;
    let artifacts = spec
        .artifacts
        .iter()
        .map(|artifact| {
            let secret_policy = policy.secrets.get(&artifact.secret_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "artifact secret {} is absent from target policy",
                    artifact.secret_id
                )
            })?;
            Ok(nix_seal_runtime::ActivationArtifact {
                ciphertext: &artifact.ciphertext,
                envelope: &artifact.envelope,
                secret_id: &artifact.secret_id,
                source_ciphertext_hash: &artifact.source_ciphertext_hash,
                artifact_generation: artifact.artifact_generation,
                approval_signers: &secret_policy.approval.signers,
                approval_threshold: usize::from(secret_policy.approval.threshold),
                mode: artifact.parsed_mode()?,
                owner: &artifact.owner,
                group: &artifact.group,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let templates = spec
        .templates
        .iter()
        .map(|template| {
            Ok(nix_seal_runtime::ActivationTemplate {
                source: &template.source,
                template_id: &template.template_id,
                placeholders: &template.placeholders,
                mode: template.parsed_mode()?,
                owner: &template.owner,
                group: &template.group,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let request = nix_seal_runtime::ActivationRequest {
        runtime_root: &spec.runtime_root,
        runtime_generation: spec.runtime_generation,
        plan_hash: &policy.plan_hash,
        target_policy_hash: &target_policy_hash,
        target_id: &spec.target_id,
        recipient_fingerprint: &recipient_fingerprint,
        tool_version: env!("CARGO_PKG_VERSION"),
        now,
        allowed_clock_skew: spec.allowed_clock_skew,
        target_identity: &identity,
        artifacts: &artifacts,
        templates: &templates,
        post_switch: spec.post_switch.as_ref(),
    };
    let result = nix_seal_runtime::activate(&request)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "activated":true,
                "changed":result.changed,
                "target":spec.target_id,
                "generationPath":result.generation_path,
                "secretCount":result.secret_count,
                "templateCount":result.template_count
            })
        );
    } else {
        println!("{}", result.generation_path.display());
        eprintln!(
            "activated {} secret(s) and {} template(s) for {} ({})",
            result.secret_count,
            result.template_count,
            spec.target_id,
            if result.changed {
                "changed"
            } else {
                "unchanged"
            }
        );
    }
    Ok(())
}

fn run_plugin_worker() -> Result<()> {
    if std::env::var_os("NIX_SEAL_PLUGIN_WORKER").as_deref() != Some(std::ffi::OsStr::new("1")) {
        bail!("internal age-plugin worker may only be launched by nix-seal");
    }
    nix_seal_crypto::run_plugin_worker_protocol(std::io::stdin().lock(), std::io::stdout().lock())
        .map_err(anyhow::Error::from)
}

fn ensure_identity_matches_recipient(
    identity: &secrecy::SecretString,
    recipient: &str,
) -> Result<()> {
    nix_seal_crypto::normalize_recipient(recipient)?;
    if !nix_seal_crypto::identity_matches_recipient(identity, recipient) {
        bail!("target identity does not match the recipient selected by plan policy");
    }
    Ok(())
}

fn artifact_written(path: &Path, signatures: usize, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","path":path,"signatures":signatures})
        );
    } else {
        println!("wrote {} with {signatures} signature(s)", path.display());
    }
}

fn read_signing_key(path: &Path) -> Result<nix_seal_manifest::ApprovalSigningKey> {
    let encoded = read_identity(path)?;
    Ok(nix_seal_manifest::ApprovalSigningKey::parse(
        encoded.expose_secret(),
    )?)
}

fn read_trusted_keys(paths: &[PathBuf]) -> Result<nix_seal_manifest::TrustedKeys> {
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    for path in paths {
        let encoded = std::fs::read_to_string(path)
            .with_context(|| format!("unable to read trusted key {}", path.display()))?;
        trusted.insert_encoded(&encoded)?;
    }
    Ok(trusted)
}

fn read_json_bounded<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    const LIMIT: u64 = 2 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("public metadata file exceeds the 2 MiB safety limit");
    }
    serde_json::from_slice(&bytes).context("invalid strict artifact JSON")
}

fn read_plan_bounded(path: &Path) -> Result<nix_seal_core::PlanV1> {
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("compiled plan exceeds the 16 MiB safety limit");
    }
    let plan: nix_seal_core::PlanV1 =
        serde_json::from_slice(&bytes).context("invalid strict plan.v1 JSON")?;
    nix_seal_policy::validate(&plan)?;
    validate_plan_identity_material(&plan)?;
    Ok(plan)
}

fn deep_check_plan(plan: &nix_seal_core::PlanV1, repository_root: &Path) -> Result<()> {
    validate_plan_identity_material(plan)?;
    for (secret_id, secret) in &plan.secrets {
        let recipients = nix_seal_policy::secret_recipients(plan, secret_id)?;
        for recipient in recipients.recipients.values() {
            nix_seal_crypto::recipient_fingerprint(recipient)?;
        }
        let path = existing_secret_path(repository_root, &secret.source)?;
        let file = open_public_ciphertext(&path)?;
        let length = file.metadata()?.len();
        if length == 0 || length > 70 * 1024 * 1024 {
            bail!("canonical ciphertext for {secret_id} has an invalid size");
        }
        nix_seal_crypto::validate_ciphertext_header(file)
            .with_context(|| format!("canonical ciphertext for {secret_id} is malformed"))?;
    }
    for target_id in plan.targets.keys() {
        let policy = nix_seal_policy::target_policy(plan, target_id)?;
        nix_seal_crypto::recipient_fingerprint(&policy.recipient)
            .with_context(|| format!("target {target_id} recipient is malformed"))?;
    }
    Ok(())
}

fn validate_plan_identity_material(plan: &nix_seal_core::PlanV1) -> Result<()> {
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    for (id, identity) in &plan.identities {
        match identity.kind {
            nix_seal_core::IdentityKind::Signer => {
                trusted
                    .insert_encoded(&identity.public)
                    .with_context(|| format!("signer identity {id} is malformed or duplicated"))?;
            }
            nix_seal_core::IdentityKind::Plugin => {
                nix_seal_crypto::recipient_fingerprint(&identity.public)
                    .with_context(|| format!("plugin identity {id} has a malformed recipient"))?;
            }
            nix_seal_core::IdentityKind::Administrator
            | nix_seal_core::IdentityKind::Target
            | nix_seal_core::IdentityKind::Recovery => {
                nix_seal_crypto::recipient_fingerprint(&identity.public)
                    .with_context(|| format!("recipient identity {id} is malformed"))?;
            }
        }
    }
    Ok(())
}

fn write_new_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let parent = path.parent().context("artifact path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn emit_canonical_public_json(output: Option<&Path>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = output {
        let parent = path.parent().context("public JSON output has no parent")?;
        std::fs::create_dir_all(parent)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("refusing to overwrite {}", path.display()))?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    } else {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}

fn run_secret(command: SecretCommand, json: bool) -> Result<()> {
    match command {
        SecretCommand::Create(arguments) => run_secret_write(
            &arguments,
            nix_seal_authoring::WriteMode::Create,
            json,
            "created",
        )?,
        SecretCommand::Import(arguments) => run_secret_write(
            &arguments,
            nix_seal_authoring::WriteMode::Create,
            json,
            "imported",
        )?,
        SecretCommand::Edit(arguments) => run_secret_edit(arguments, json)?,
        SecretCommand::Delete(arguments) => run_secret_delete(&arguments, json)?,
        SecretCommand::Reveal(arguments) => {
            if json {
                bail!("secret reveal refuses --json because plaintext JSON output is forbidden");
            }
            let plan = read_plan_bounded(&arguments.policy.plan)?;
            let recipients = nix_seal_policy::secret_recipients(&plan, &arguments.policy.secret)?;
            let identity = read_identity(&arguments.identity)?;
            if !recipients
                .recipients
                .values()
                .any(|value| nix_seal_crypto::identity_matches_recipient(&identity, value))
            {
                bail!("reveal identity is not authorized by canonical recipient policy");
            }
            let secret = plan
                .secrets
                .get(&arguments.policy.secret)
                .context("secret is absent from plan")?;
            let input = existing_secret_path(&arguments.repository_root, &secret.source)?;
            let ciphertext = open_public_ciphertext(&input)?;
            nix_seal_crypto::decrypt(ciphertext, std::io::stdout().lock(), &identity)?;
        }
        SecretCommand::List { plan, due } => {
            let plan = read_plan_bounded(&plan)?;
            let lifecycle = nix_seal_policy::lifecycle_report(&plan, SystemTime::now())?;
            let lifecycle: Vec<_> = lifecycle
                .into_iter()
                .filter(|report| {
                    !due || matches!(
                        report.state,
                        nix_seal_policy::LifecycleStateV1::Expired
                            | nix_seal_policy::LifecycleStateV1::RotationDue
                    )
                })
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema":"nix-seal.output.v1",
                        "secrets":lifecycle
                    })
                );
            } else {
                for report in lifecycle {
                    println!("{}\t{:?}", report.secret_id, report.state);
                }
            }
        }
        SecretCommand::Show(arguments) => {
            let plan = read_plan_bounded(&arguments.plan)?;
            let secret = plan
                .secrets
                .get(&arguments.secret)
                .context("secret is absent from plan")?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema":"nix-seal.output.v1",
                        "secretId":arguments.secret,
                        "secret":secret
                    })
                );
            } else {
                println!("{}", arguments.secret);
                println!("source: {}", secret.source);
                println!("delivery: {:?}", secret.delivery);
                println!("phase: {:?}", secret.phase);
            }
        }
    }
    Ok(())
}

fn run_secret_delete(arguments: &SecretDeleteArgs, json: bool) -> Result<()> {
    if !arguments.yes {
        bail!("secret deletion requires the explicit --yes acknowledgement");
    }
    let plan = read_plan_bounded(&arguments.policy.plan)?;
    let secret = plan
        .secrets
        .get(&arguments.policy.secret)
        .context("secret is absent from plan")?;
    let root = arguments
        .repository_root
        .canonicalize()
        .context("repository root must exist")?;
    let deleted_at = jiff::Timestamp::try_from(SystemTime::now())
        .map(|timestamp| timestamp.to_string())
        .context("system time is outside supported lifecycle range")?;
    let result = nix_seal_authoring::delete_secret(&nix_seal_authoring::DeleteRequest {
        repository_root: &root,
        relative_source: Path::new(&secret.source),
        quarantine_root: &arguments.quarantine_root,
        secret_id: arguments.policy.secret.as_str(),
        deleted_at: &deleted_at,
    })?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "operation":"deleted",
                "secretId":arguments.policy.secret,
                "originalPath":result.original_path,
                "tombstonePath":result.tombstone_path,
                "ciphertextHash":result.ciphertext_hash,
                "deletedAt":deleted_at
            })
        );
    } else {
        println!("{}", result.tombstone_path.display());
        eprintln!(
            "quarantined canonical ciphertext for {}; update the authoritative plan separately",
            arguments.policy.secret
        );
    }
    Ok(())
}

fn run_secret_write(
    arguments: &SecretWriteArgs,
    mode: nix_seal_authoring::WriteMode,
    json: bool,
    operation: &str,
) -> Result<()> {
    let plan = read_plan_bounded(&arguments.policy.plan)?;
    let secret = plan
        .secrets
        .get(&arguments.policy.secret)
        .context("secret is absent from plan")?;
    let recipient_policy = nix_seal_policy::secret_recipients(&plan, &arguments.policy.secret)?;
    let recipients: Vec<_> = recipient_policy
        .recipients
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if matches!(secret.delivery, nix_seal_core::DeliveryMode::Direct) {
        eprintln!(
            "warning: direct mode allows matching target keys to decrypt current and historical Git ciphertext"
        );
    }
    let root = arguments
        .repository_root
        .canonicalize()
        .context("repository root must exist")?;
    let identity = read_identity(&arguments.identity)?;
    let input = read_structured_secret_input(arguments.format)?;
    let result = nix_seal_authoring::write_secret(
        &root,
        Path::new(&secret.source),
        std::io::Cursor::new(input.expose_secret().as_slice()),
        &recipients,
        &identity,
        mode,
    )?;
    let rotated_at = (operation == "rotated")
        .then(|| {
            jiff::Timestamp::try_from(SystemTime::now())
                .map(|timestamp| timestamp.to_string())
                .context("system time is outside supported lifecycle range")
        })
        .transpose()?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "operation":operation,
                "secretId":arguments.policy.secret,
                "ciphertextPath":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "recipientCount":recipients.len(),
                "rotatedAt":rotated_at
            })
        );
    } else {
        println!("{}", result.path.display());
        eprintln!(
            "{operation} canonical ciphertext for {}",
            arguments.policy.secret
        );
        if let Some(rotated_at) = rotated_at {
            eprintln!("record lifecycle.rotatedAt = {rotated_at} in the authoritative plan source");
        }
    }
    Ok(())
}

fn read_structured_secret_input(format: Option<SecretFormat>) -> Result<SecretBox<Vec<u8>>> {
    let mut input = SecretBox::new(Box::new(Vec::new()));
    BoundedReader::new(
        std::io::stdin().lock(),
        EXTERNAL_MIGRATION_MAX_PLAINTEXT_BYTES,
    )
    .read_to_end(input.expose_secret_mut())
    .context("secret input exceeds the 64 MiB safety limit")?;
    validate_structured_secret_bytes(input.expose_secret(), format)?;
    Ok(input)
}

fn validate_structured_secret_bytes(input: &[u8], format: Option<SecretFormat>) -> Result<()> {
    let Some(format) = format else {
        return Ok(());
    };
    let text = std::str::from_utf8(input).context("structured secret input must be valid UTF-8")?;
    match format {
        SecretFormat::Json => {
            let _: serde_json::Value =
                serde_json::from_str(text).context("structured JSON secret input is malformed")?;
        }
        SecretFormat::Toml => {
            let _: toml::Value =
                toml::from_str(text).context("structured TOML secret input is malformed")?;
        }
        SecretFormat::Yaml => {
            let _: yaml_serde::Value =
                yaml_serde::from_str(text).context("structured YAML secret input is malformed")?;
        }
        SecretFormat::Dotenv => validate_dotenv(text)?,
    }
    Ok(())
}

fn validate_dotenv(input: &str) -> Result<()> {
    let mut keys = BTreeSet::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, _value) = line
            .strip_prefix("export ")
            .unwrap_or(line)
            .split_once('=')
            .context("dotenv entries must use KEY=VALUE syntax")?;
        if key.is_empty()
            || !key.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_lowercase()
                    || byte == b'_'
                    || index > 0 && byte.is_ascii_digit()
            })
            || !keys.insert(key)
        {
            bail!("dotenv entries require unique shell-compatible keys");
        }
    }
    Ok(())
}

fn run_secret_edit(arguments: SecretEditArgs, json: bool) -> Result<()> {
    let plan = read_plan_bounded(&arguments.secret.policy.plan)?;
    let secret = plan
        .secrets
        .get(&arguments.secret.policy.secret)
        .context("secret is absent from plan")?;
    let recipient_policy =
        nix_seal_policy::secret_recipients(&plan, &arguments.secret.policy.secret)?;
    let recipients: Vec<_> = recipient_policy
        .recipients
        .values()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let root = arguments
        .secret
        .repository_root
        .canonicalize()
        .context("repository root must exist")?;
    let identity = read_identity(&arguments.secret.identity)?;
    let workspace_root = match arguments.workspace_root {
        Some(path) => path,
        None => match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(path) if Path::new(&path).is_absolute() => PathBuf::from(path),
            _ => {
                eprintln!(
                    "warning: editor workspace uses the OS temporary directory, which may not be memory-backed"
                );
                std::env::temp_dir()
            }
        },
    }
    .canonicalize()
    .context("editor workspace root must exist")?;
    if matches!(secret.delivery, nix_seal_core::DeliveryMode::Direct) {
        eprintln!(
            "warning: direct mode allows matching target keys to decrypt current and historical Git ciphertext"
        );
    }
    let format = arguments.secret.format;
    let result = nix_seal_authoring::edit_secret_checked(
        &nix_seal_authoring::EditRequest {
            repository_root: &root,
            relative_destination: Path::new(&secret.source),
            identity: &identity,
            recipients: &recipients,
            editor: &arguments.editor,
            editor_arguments: &arguments.editor_arguments,
            workspace_root: &workspace_root,
        },
        |plaintext| {
            let mut input = SecretBox::new(Box::new(Vec::new()));
            BoundedReader::new(plaintext, EXTERNAL_MIGRATION_MAX_PLAINTEXT_BYTES)
                .read_to_end(input.expose_secret_mut())
                .map_err(|_| nix_seal_authoring::AuthoringError::InvalidEditedContent)?;
            validate_structured_secret_bytes(input.expose_secret(), format)
                .map_err(|_| nix_seal_authoring::AuthoringError::InvalidEditedContent)
        },
    )?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "operation":"edited",
                "secretId":arguments.secret.policy.secret,
                "ciphertextPath":result.path,
                "ciphertextHash":result.ciphertext_hash,
                "recipientCount":recipients.len()
            })
        );
    } else {
        println!("{}", result.path.display());
        eprintln!(
            "edited canonical ciphertext for {}",
            arguments.secret.policy.secret
        );
    }
    Ok(())
}

fn run_recipients(arguments: &SecretPlanArgs, json: bool) -> Result<()> {
    let plan = read_plan_bounded(&arguments.plan)?;
    let recipients = nix_seal_policy::secret_recipients(&plan, &arguments.secret)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "recipientPolicy":recipients
            })
        );
    } else {
        for (id, recipient) in &recipients.recipients {
            println!("{id}\t{recipient}");
        }
    }
    Ok(())
}

fn existing_secret_path(repository_root: &Path, relative: &str) -> Result<PathBuf> {
    let root = repository_root
        .canonicalize()
        .context("repository root must exist")?;
    let relative = Path::new(relative);
    if relative.is_absolute() {
        bail!("canonical ciphertext path must be repository-relative");
    }
    let mut path = root.clone();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(segment) = component else {
            bail!("canonical ciphertext path is not normalized");
        };
        path.push(segment);
        let metadata = std::fs::symlink_metadata(&path)?;
        if index + 1 == components.len() {
            if !metadata.file_type().is_file() {
                bail!("canonical ciphertext is not a regular file");
            }
        } else if !metadata.file_type().is_dir() {
            bail!("canonical ciphertext ancestry is not a directory");
        }
    }
    Ok(path)
}

fn existing_public_output_path(repository_root: &Path, relative: &str) -> Result<PathBuf> {
    existing_secret_path(repository_root, relative)
        .context("public output path is missing or unsafe")
}

/// Resolves an explicit plaintext render destination without permitting the
/// Nix store, links, shared writable parents, or implicit overwrite behavior.
fn prepare_private_template_destination(
    output: &Path,
    replace: bool,
) -> Result<(PathBuf, PathBuf)> {
    if !output.is_absolute() {
        bail!("template render output must be an absolute path outside the Nix store");
    }
    let parent = output
        .parent()
        .context("template render output has no parent directory")?
        .canonicalize()
        .context("template render output parent must already exist")?;
    if parent.starts_with("/nix/store") {
        bail!("template render output must not be placed in the Nix store");
    }
    let parent_metadata = fs::metadata(&parent)?;
    if !parent_metadata.is_dir() {
        bail!("template render output parent is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if parent_metadata.uid() != rustix::process::geteuid().as_raw()
            || parent_metadata.mode() & 0o022 != 0
        {
            bail!("template render output parent has unsafe ownership or write permissions");
        }
    }
    let name = output
        .file_name()
        .filter(|name| !name.is_empty())
        .context("template render output is not a normal file path")?;
    let destination = parent.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if !replace {
                bail!("template render output already exists; pass --replace to update it");
            }
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!("template render output is not a safe regular file");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 || metadata.uid() != rustix::process::geteuid().as_raw() {
                    bail!("template render output has unsafe ownership or link metadata");
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if replace {
                bail!("template render --replace requires an existing regular output file");
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok((destination, parent))
}

fn set_private_template_output(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_public_ciphertext(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let metadata = fstat(&descriptor).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        bail!("canonical ciphertext is not a no-follow single-link regular file");
    }
    Ok(std::fs::File::from(descriptor))
}

#[cfg(not(unix))]
fn open_public_ciphertext(path: &Path) -> Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("canonical ciphertext is not a regular file");
    }
    Ok(std::fs::File::open(path)?)
}

fn read_identity(path: &Path) -> Result<SecretString> {
    let mut bytes = Vec::new();
    open_private_identity(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        bail!("identity exceeds the 1 MiB safety limit");
    }
    Ok(SecretString::from(
        String::from_utf8(bytes).context("identity is not UTF-8")?,
    ))
}

#[cfg(unix)]
fn open_private_identity(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let metadata = fstat(&descriptor).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        bail!("private identity file has unsafe ownership, mode, or link metadata");
    }
    Ok(std::fs::File::from(descriptor))
}

#[cfg(not(unix))]
fn open_private_identity(path: &Path) -> Result<std::fs::File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("private identity file has unsafe link metadata");
    }
    Ok(std::fs::File::open(path)?)
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("identity path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    set_private_file(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("could not create private generator prompt file")?;
    set_private_file(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .context("could not write private generator prompt file")?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn cache_status(root: Option<PathBuf>, json: bool) -> Result<()> {
    let root = root.unwrap_or_else(default_cache_root);
    let cache = nix_seal_cache::Cache::open(&root)?;
    let inventory = cache.inventory()?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "root":cache.root(),
                "objects":inventory.object_count,
                "objectBytes":inventory.object_bytes,
                "artifacts":inventory.artifact_count,
                "artifactCiphertextBytes":inventory.artifact_ciphertext_bytes,
                "artifactEnvelopeBytes":inventory.artifact_envelope_bytes
            })
        );
    } else {
        println!(
            "{}: {} objects ({} bytes), {} target artifacts ({} ciphertext bytes, {} envelope bytes)",
            cache.root().display(),
            inventory.object_count,
            inventory.object_bytes,
            inventory.artifact_count,
            inventory.artifact_ciphertext_bytes,
            inventory.artifact_envelope_bytes
        );
    }
    Ok(())
}

struct GcRetention {
    plan_hash: String,
    artifact_keys: BTreeSet<String>,
    unavailable_sources: u64,
}

fn cache_gc(
    plan_path: &Path,
    repository_root: &Path,
    root: Option<PathBuf>,
    execute: bool,
    json: bool,
) -> Result<()> {
    let plan = read_plan_bounded(plan_path)?;
    let cache = nix_seal_cache::Cache::open(root.unwrap_or_else(default_cache_root))?;
    let retention = authenticated_gc_retention(&cache, &plan, repository_root)?;
    let report = cache.garbage_collect(&nix_seal_cache::GcRequest {
        retained_artifacts: retention.artifact_keys,
        // Generic objects are not referenced by the v1 plan/artifact format and
        // must therefore never be retained by inference.
        retained_objects: BTreeSet::new(),
        execute,
    })?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.cache-gc.v1",
                "root":cache.root(),
                "dryRun":!report.executed,
                "planHash":retention.plan_hash,
                "retainedArtifacts":report.retained_artifacts,
                "retainedObjects":report.retained_objects,
                "candidateArtifacts":report.candidate_artifacts,
                "candidateObjects":report.candidate_objects,
                "candidateBytes":report.candidate_bytes,
                "unavailableSources":retention.unavailable_sources
            })
        );
    } else {
        let action = if report.executed {
            "removed"
        } else {
            "would remove"
        };
        println!(
            "{}: retained {} target artifacts; {action} {} target artifacts and {} generic objects ({} bytes)",
            cache.root().display(),
            report.retained_artifacts,
            report.candidate_artifacts,
            report.candidate_objects,
            report.candidate_bytes,
        );
        if !report.executed {
            eprintln!("dry run; rerun with --execute to remove candidates");
        }
        if retention.unavailable_sources > 0 {
            eprintln!(
                "{} canonical ciphertext source(s) could not be authenticated; related artifacts are candidates",
                retention.unavailable_sources
            );
        }
    }
    Ok(())
}

fn cache_export(destination: &Path, root: Option<PathBuf>, json: bool) -> Result<()> {
    let cache = nix_seal_cache::Cache::open(root.unwrap_or_else(default_cache_root))?;
    let report = cache.export_to(destination)?;
    emit_cache_transfer("exported", cache.root(), destination, &report, json);
    Ok(())
}

fn cache_import(source: &Path, root: Option<PathBuf>, json: bool) -> Result<()> {
    let cache = nix_seal_cache::Cache::open(root.unwrap_or_else(default_cache_root))?;
    let report = cache.import_from(source)?;
    emit_cache_transfer("imported", source, cache.root(), &report, json);
    Ok(())
}

fn emit_cache_transfer(
    operation: &str,
    source: &Path,
    destination: &Path,
    report: &nix_seal_cache::CacheTransferReport,
    json: bool,
) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.cache-transfer.v1",
                "operation":operation,
                "source":source,
                "destination":destination,
                "objects":report.object_count,
                "artifacts":report.artifact_count,
                "bytes":report.bytes
            })
        );
    } else {
        println!(
            "{operation} {} objects and {} target artifacts ({} bytes) from {} to {}",
            report.object_count,
            report.artifact_count,
            report.bytes,
            source.display(),
            destination.display(),
        );
    }
}

fn authenticated_gc_retention(
    cache: &nix_seal_cache::Cache,
    plan: &nix_seal_core::PlanV1,
    repository_root: &Path,
) -> Result<GcRetention> {
    let plan_hash = nix_seal_policy::plan_hash(plan)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let mut target_policies = BTreeMap::new();
    let mut source_hashes = BTreeMap::new();
    let mut unavailable_sources = BTreeSet::new();
    let mut artifact_keys = BTreeSet::new();
    for record in cache.artifact_records()? {
        let Ok(envelope) =
            serde_json::from_slice::<nix_seal_manifest::SignedEnvelopeV1>(&record.envelope)
        else {
            continue;
        };
        let Ok(manifest) = nix_seal_manifest::inspect_unverified(&envelope) else {
            continue;
        };
        if artifact_is_active(
            &record,
            &envelope,
            &manifest,
            plan,
            &plan_hash,
            repository_root,
            now,
            &mut target_policies,
            &mut source_hashes,
            &mut unavailable_sources,
        ) {
            artifact_keys.insert(record.key);
        }
    }
    Ok(GcRetention {
        plan_hash,
        artifact_keys,
        unavailable_sources: u64::try_from(unavailable_sources.len())
            .context("source availability count exceeds supported range")?,
    })
}

#[allow(clippy::too_many_arguments)]
fn artifact_is_active(
    record: &nix_seal_cache::ArtifactRecord,
    envelope: &nix_seal_manifest::SignedEnvelopeV1,
    manifest: &nix_seal_manifest::TargetManifestV2,
    plan: &nix_seal_core::PlanV1,
    plan_hash: &str,
    repository_root: &Path,
    now: u64,
    target_policies: &mut BTreeMap<nix_seal_core::Id, nix_seal_policy::TargetPolicyV1>,
    source_hashes: &mut BTreeMap<nix_seal_core::Id, Option<String>>,
    unavailable_sources: &mut BTreeSet<nix_seal_core::Id>,
) -> bool {
    if manifest.plan_hash != plan_hash
        || !plan.targets.contains_key(&manifest.target_id)
        || !plan.secrets.contains_key(&manifest.secret_id)
    {
        return false;
    }
    let policy = match target_policies.entry(manifest.target_id.clone()) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => {
            let Ok(policy) = nix_seal_policy::target_policy(plan, &manifest.target_id) else {
                return false;
            };
            entry.insert(policy)
        }
    };
    let Ok(policy_hash) = nix_seal_policy::target_policy_hash(policy) else {
        return false;
    };
    let Some(secret_policy) = policy.secrets.get(&manifest.secret_id) else {
        return false;
    };
    if manifest.target_policy_hash != policy_hash {
        return false;
    }
    let source_hash = match source_hashes.entry(manifest.secret_id.clone()) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => {
            let hash = canonical_ciphertext_hash(repository_root, &secret_policy.source).ok();
            if hash.is_none() {
                unavailable_sources.insert(manifest.secret_id.clone());
            }
            entry.insert(hash)
        }
    };
    let Some(source_hash) = source_hash.as_deref() else {
        return false;
    };
    let Ok(recipient_fingerprint) = nix_seal_crypto::recipient_fingerprint(&policy.recipient)
    else {
        return false;
    };
    if manifest.source_ciphertext_hash != source_hash
        || manifest.recipient_fingerprint != recipient_fingerprint
    {
        return false;
    }
    let Ok(address) = nix_seal_cache::ArtifactAddress::new(
        plan_hash,
        &policy_hash,
        source_hash,
        &recipient_fingerprint,
        manifest.target_id.as_str(),
        manifest.secret_id.as_str(),
        manifest.artifact_generation,
    ) else {
        return false;
    };
    if address.key().ok().as_deref() != Some(&record.key) {
        return false;
    }
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    if secret_policy
        .approval
        .signers
        .values()
        .any(|encoded| trusted.insert_encoded(encoded).is_err())
    {
        return false;
    }
    let expected = nix_seal_manifest::ExpectedBinding {
        // The current policy has no producer-version allow-list yet. The signed
        // value remains bound by `verify`; a future version policy can constrain it.
        tool_version: &manifest.tool_version,
        plan_hash,
        target_policy_hash: &policy_hash,
        source_ciphertext_hash: source_hash,
        artifact_ciphertext_hash: &record.artifact_ciphertext_hash,
        target_id: &manifest.target_id,
        secret_id: &manifest.secret_id,
        recipient_fingerprint: &recipient_fingerprint,
        artifact_generation: manifest.artifact_generation,
        now,
        allowed_clock_skew: 300,
    };
    nix_seal_manifest::verify(
        envelope,
        &trusted,
        usize::from(secret_policy.approval.threshold),
        &expected,
    )
    .is_ok()
}

fn canonical_ciphertext_hash(repository_root: &Path, relative: &str) -> Result<String> {
    const LIMIT: u64 = 70 * 1024 * 1024;
    let path = existing_secret_path(repository_root, relative)?;
    let mut file = open_public_ciphertext(&path)?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).context("ciphertext read length exceeds u64")?)
            .context("ciphertext exceeds supported length")?;
        if total > LIMIT {
            bail!("canonical ciphertext exceeds the 70 MiB safety limit");
        }
        hasher.update(&buffer[..read]);
    }
    if total == 0 {
        bail!("canonical ciphertext is empty");
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn default_cache_root() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map_or_else(
            || {
                std::env::var_os("HOME")
                    .map_or_else(|| PathBuf::from("."), PathBuf::from)
                    .join(".cache")
            },
            PathBuf::from,
        )
        .join("nix-seal/v1")
}

fn completions(shell: CompletionShell) {
    let mut command = Cli::command();
    let name = command.get_name().to_owned();
    match shell {
        CompletionShell::Bash => clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut command,
            name,
            &mut std::io::stdout(),
        ),
        CompletionShell::Zsh => clap_complete::generate(
            clap_complete::Shell::Zsh,
            &mut command,
            name,
            &mut std::io::stdout(),
        ),
        CompletionShell::Fish => clap_complete::generate(
            clap_complete::Shell::Fish,
            &mut command,
            name,
            &mut std::io::stdout(),
        ),
        CompletionShell::Nushell => clap_complete::generate(
            clap_complete_nushell::Nushell,
            &mut command,
            name,
            &mut std::io::stdout(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{PasswordVerifier, password_hash::PasswordHash};
    use nix_seal_manifest::{ARTIFACT_SCHEMA, TargetManifestV2};
    use std::collections::BTreeMap;

    #[test]
    fn bounded_reader_rejects_bytes_past_the_configured_limit() {
        let mut reader = BoundedReader::new(&b"abc"[..], 2);
        let mut output = Vec::new();
        assert!(reader.read_to_end(&mut output).is_err());
        assert_eq!(output, b"ab");
    }

    #[test]
    fn exit_categories_follow_the_documented_typed_error_contract() {
        assert_eq!(
            exit_category(&anyhow::Error::new(nix_seal_crypto::CryptoError::Encrypt)),
            4
        );
        assert_eq!(
            exit_category(&anyhow::Error::new(
                nix_seal_runtime::RuntimeError::InvalidSpec
            )),
            6
        );
        assert_eq!(exit_category(&anyhow::anyhow!("operational failure")), 1);
    }

    #[cfg(unix)]
    #[test]
    fn process_hardening_disables_only_the_soft_core_limit() {
        let hardened = disabled_core_limit(rustix::process::Rlimit {
            current: Some(4_096),
            maximum: Some(8_192),
        });
        assert_eq!(hardened.current, Some(0));
        assert_eq!(hardened.maximum, Some(8_192));
    }

    #[test]
    fn identity_inventory_contains_only_declared_public_plan_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, recipient) = nix_seal_crypto::generate_x25519();
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient.clone(),
            },
        );

        let identities = public_identity_records(&plan);
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].id, "administrator");
        assert_eq!(identities[0].kind, "administrator");
        assert_eq!(identities[0].public, recipient);
        assert_eq!(
            serde_json::to_value(&identities)?[0]["kind"],
            serde_json::Value::String("administrator".to_owned())
        );
        Ok(())
    }

    #[test]
    fn routine_validation_rejects_malformed_identity_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: "not-an-age-recipient".to_owned(),
            },
        );
        assert!(nix_seal_policy::validate(&plan).is_err());
        Ok(())
    }

    #[test]
    fn ssh_signing_key_authorization_ignores_public_key_comments()
    -> Result<(), Box<dyn std::error::Error>> {
        let private = "-----BEGIN_OPENSSH_PRIVATE_KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END_OPENSSH_PRIVATE_KEY-----\n";
        let signing_key = nix_seal_manifest::ApprovalSigningKey::parse(&private.replace('_', " "))?;
        let secret = nix_seal_core::Id::parse("application/token")?;
        let policy = nix_seal_policy::TargetSecretPolicyV1 {
            source: "secrets/token.age".to_owned(),
            delivery: nix_seal_core::DeliveryMode::Rekeyed,
            phase: nix_seal_core::ActivationPhase::Activation,
            runtime: nix_seal_core::RuntimeSettings::default(),
            approval: nix_seal_policy::TargetApprovalPolicyV1 {
                threshold: 1,
                signers: BTreeMap::from([(
                    nix_seal_core::Id::parse("release")?,
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti release@example.com".to_owned(),
                )]),
            },
        };
        ensure_signing_key_authorized(&policy, &signing_key, &secret)?;
        Ok(())
    }

    #[test]
    fn dotenv_validation_rejects_duplicate_and_unsafe_keys() {
        assert!(validate_dotenv("TOKEN=value\nexport PORT=443\n").is_ok());
        assert!(validate_dotenv("TOKEN=one\nTOKEN=two\n").is_err());
        assert!(validate_dotenv("1TOKEN=value\n").is_err());
        assert!(validate_dotenv("TOKEN\n").is_err());
    }

    #[test]
    fn structured_validation_preserves_raw_mode_and_rejects_malformed_documents() {
        assert!(validate_structured_secret_bytes(b"arbitrary\0bytes", None).is_ok());
        assert!(
            validate_structured_secret_bytes(br#"{"token":"value"}"#, Some(SecretFormat::Json))
                .is_ok()
        );
        assert!(validate_structured_secret_bytes(b"{", Some(SecretFormat::Json)).is_err());
        assert!(
            validate_structured_secret_bytes(b"token = 'value'", Some(SecretFormat::Toml)).is_ok()
        );
        assert!(validate_structured_secret_bytes(b"token =", Some(SecretFormat::Toml)).is_err());
        assert!(
            validate_structured_secret_bytes(b"token: value\n", Some(SecretFormat::Yaml)).is_ok()
        );
        assert!(validate_structured_secret_bytes(b"token: [", Some(SecretFormat::Yaml)).is_err());
    }

    #[test]
    fn routine_template_preflight_rejects_malformed_public_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let plan_path = temporary.path().join("plan.v1.json");
        let source = temporary.path().join("application.conf.template");
        std::fs::write(&source, b"literal public template\n")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.templates.insert(
            nix_seal_core::Id::parse("application/config")?,
            nix_seal_core::Template {
                source: "application.conf.template".to_owned(),
                placeholders: BTreeMap::new(),
                runtime: nix_seal_core::RuntimeSettings::default(),
            },
        );
        validate_plan_templates(&plan, &plan_path)?;

        std::fs::write(&source, b"value={{nix-seal:missing}}\n")?;
        assert!(validate_plan_templates(&plan, &plan_path).is_err());
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn template_render_streams_to_a_private_atomic_output() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        let secrets = repository.join("secrets");
        std::fs::create_dir_all(&secrets)?;
        let identity_path = temporary.path().join("administrator.identity");
        let plan_path = temporary.path().join("plan.v1.json");
        let source = temporary.path().join("application.conf.template");
        let output = temporary.path().join("application.conf");
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        write_new_private(&identity_path, identity.expose_secret().as_bytes())?;
        let secret_id = nix_seal_core::Id::parse("application/password")?;
        let template_id = nix_seal_core::Id::parse("application/config")?;
        let ciphertext_path = secrets.join("password.age");
        let mut ciphertext = fs::File::create(&ciphertext_path)?;
        nix_seal_crypto::encrypt(
            b"template-render-canary".as_slice(),
            &mut ciphertext,
            std::slice::from_ref(&recipient),
        )?;
        ciphertext.sync_all()?;
        fs::write(&source, b"password={{nix-seal:password}}\n")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient,
            },
        );
        plan.identities.insert(
            nix_seal_core::Id::parse("signer.release")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: nix_seal_manifest::ApprovalSigningKey::generate()?.encode_public()?,
            },
        );
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/password.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        plan.templates.insert(
            template_id.clone(),
            nix_seal_core::Template {
                source: source.to_string_lossy().into_owned(),
                placeholders: BTreeMap::from([(
                    "password".to_owned(),
                    nix_seal_core::TemplatePlaceholder {
                        secret: secret_id,
                        encoding: nix_seal_core::TemplateEncoding::Utf8,
                    },
                )]),
                runtime: nix_seal_core::RuntimeSettings::default(),
            },
        );
        nix_seal_policy::validate(&plan)?;
        fs::write(&plan_path, nix_seal_policy::canonical_json(&plan)?)?;

        run_template_render(
            &plan_path,
            &template_id,
            &repository,
            &identity_path,
            &output,
            false,
            false,
        )?;
        assert_eq!(fs::read(&output)?, b"password=template-render-canary\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
        }
        assert!(
            run_template_render(
                &plan_path,
                &template_id,
                &repository,
                &identity_path,
                &output,
                false,
                false,
            )
            .is_err()
        );
        run_template_render(
            &plan_path,
            &template_id,
            &repository,
            &identity_path,
            &output,
            true,
            false,
        )?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn direct_delivery_rekey_and_provision_stage_without_an_administrator_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        let secrets = repository.join("secrets");
        std::fs::create_dir_all(&secrets)?;
        let plan_path = temporary.path().join("plan.v1.json");
        let signing_path = temporary.path().join("release.signing-key");
        let cache_root = temporary.path().join("cache");
        let (target_identity, target_recipient) = nix_seal_crypto::generate_x25519();
        let target_id = nix_seal_core::Id::parse("host.direct")?;
        let secret_id = nix_seal_core::Id::parse("application/token")?;
        let signer_id = nix_seal_core::Id::parse("signer.release")?;
        let signing_key = nix_seal_manifest::ApprovalSigningKey::generate()?;
        write_new_private(&signing_path, signing_key.encode_private()?.as_bytes())?;
        let mut ciphertext = fs::File::create(secrets.join("token.age"))?;
        nix_seal_crypto::encrypt(
            b"direct-cli-canary".as_slice(),
            &mut ciphertext,
            std::slice::from_ref(&target_recipient),
        )?;
        ciphertext.sync_all()?;

        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("target.direct")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Target,
                public: target_recipient,
            },
        );
        plan.identities.insert(
            signer_id.clone(),
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: signing_key.encode_public()?,
            },
        );
        plan.targets.insert(
            target_id.clone(),
            nix_seal_core::Target {
                kind: nix_seal_core::TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: nix_seal_core::Id::parse("target.direct")?,
                username: None,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/token.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Direct,
                administrators: Vec::new(),
                consumers: vec![target_id.clone()],
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        nix_seal_policy::validate(&plan)?;
        fs::write(&plan_path, nix_seal_policy::canonical_json(&plan)?)?;

        run_provision(
            ProvisionArgs {
                plan: plan_path.clone(),
                repository_root: repository.clone(),
                identity: None,
                target: target_id.clone(),
                generation: 1,
                signing_key: signing_path.clone(),
                expires_at: None,
                cache_root: Some(cache_root.clone()),
                execute: false,
            },
            false,
        )?;
        assert!(!cache_root.exists());
        run_rekey(
            RekeyArgs {
                plan: plan_path.clone(),
                repository_root: repository.clone(),
                identity: None,
                target: target_id.clone(),
                secret: secret_id.clone(),
                generation: 1,
                signing_key: signing_path.clone(),
                expires_at: None,
                cache_root: Some(cache_root.clone()),
            },
            false,
        )?;
        run_provision(
            ProvisionArgs {
                plan: plan_path,
                repository_root: repository.clone(),
                identity: None,
                target: target_id,
                generation: 1,
                signing_key: signing_path,
                expires_at: None,
                cache_root: Some(cache_root.clone()),
                execute: true,
            },
            false,
        )?;
        let records = nix_seal_cache::Cache::open(cache_root.clone())?.artifact_records()?;
        assert_eq!(records.len(), 1);
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(
            fs::File::open(&records[0].ciphertext_path)?,
            &mut plaintext,
            &target_identity,
        )?;
        assert_eq!(plaintext, b"direct-cli-canary");
        let retention = authenticated_gc_retention(
            &nix_seal_cache::Cache::open(cache_root)?,
            &plan,
            &repository,
        )?;
        assert_eq!(retention.artifact_keys.len(), 1);
        Ok(())
    }

    #[test]
    fn toml_identity_lifecycle_is_atomic_and_refuses_referenced_removal()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let toml_path = temporary.path().join("nix-seal.toml");
        fs::write(
            &toml_path,
            toml::to_string_pretty(&nix_seal_core::PlanV1::default())?,
        )?;
        let id = nix_seal_core::Id::parse("administrator")?;
        let (_, first_recipient) = nix_seal_crypto::generate_x25519();
        let (_, second_recipient) = nix_seal_crypto::generate_x25519();

        run_identity(
            IdentityCommand::Add {
                plan: IdentityPlanArgs {
                    toml: toml_path.clone(),
                    nix_plan: None,
                },
                id: id.clone(),
                kind: IdentityRole::Administrator,
                public: first_recipient,
            },
            true,
        )?;
        run_identity(
            IdentityCommand::Rotate {
                plan: IdentityPlanArgs {
                    toml: toml_path.clone(),
                    nix_plan: None,
                },
                id: id.clone(),
                public: second_recipient.clone(),
                yes: true,
            },
            true,
        )?;
        let plan = nix_seal_policy::load_toml(&toml_path)?;
        assert_eq!(plan.identities[&id].public, second_recipient);

        let mut referenced = plan.clone();
        referenced.groups.insert(
            nix_seal_core::Id::parse("administrators")?,
            nix_seal_core::Group {
                members: vec![id.clone()],
            },
        );
        assert_eq!(
            identity_references(&referenced, &id),
            vec!["group administrators"]
        );

        fs::write(&toml_path, toml::to_string_pretty(&referenced)?)?;
        assert!(
            run_identity(
                IdentityCommand::Remove {
                    plan: IdentityPlanArgs {
                        toml: toml_path.clone(),
                        nix_plan: None,
                    },
                    id: id.clone(),
                    yes: true,
                },
                true,
            )
            .is_err()
        );
        assert!(
            nix_seal_policy::load_toml(&toml_path)?
                .identities
                .contains_key(&id)
        );

        fs::write(&toml_path, toml::to_string_pretty(&plan)?)?;

        run_identity(
            IdentityCommand::Remove {
                plan: IdentityPlanArgs {
                    toml: toml_path.clone(),
                    nix_plan: None,
                },
                id: id.clone(),
                yes: true,
            },
            true,
        )?;
        assert!(
            !nix_seal_policy::load_toml(&toml_path)?
                .identities
                .contains_key(&id)
        );
        Ok(())
    }

    #[test]
    fn identity_add_rejects_a_nix_plan_collision_before_rewriting_toml()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let toml_path = temporary.path().join("nix-seal.toml");
        fs::write(
            &toml_path,
            toml::to_string_pretty(&nix_seal_core::PlanV1::default())?,
        )?;
        let nix_plan_path = temporary.path().join("nix-plan.json");
        let id = nix_seal_core::Id::parse("administrator")?;
        let (_, recipient) = nix_seal_crypto::generate_x25519();
        let mut nix_plan = nix_seal_core::PlanV1::default();
        nix_plan.identities.insert(
            id.clone(),
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient.clone(),
            },
        );
        fs::write(&nix_plan_path, serde_json::to_vec(&nix_plan)?)?;

        assert!(
            run_identity(
                IdentityCommand::Add {
                    plan: IdentityPlanArgs {
                        toml: toml_path.clone(),
                        nix_plan: Some(nix_plan_path),
                    },
                    id,
                    kind: IdentityRole::Administrator,
                    public: recipient,
                },
                true,
            )
            .is_err()
        );
        assert!(
            nix_seal_policy::load_toml(&toml_path)?
                .identities
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn group_removal_refuses_nested_or_secret_references() -> Result<(), Box<dyn std::error::Error>>
    {
        let group = nix_seal_core::Id::parse("operators")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.groups.insert(
            group.clone(),
            nix_seal_core::Group {
                members: Vec::new(),
            },
        );
        plan.groups.insert(
            nix_seal_core::Id::parse("nested")?,
            nix_seal_core::Group {
                members: vec![group.clone()],
            },
        );
        assert_eq!(group_references(&plan, &group), vec!["group nested"]);
        plan.groups.remove(&nix_seal_core::Id::parse("nested")?);
        plan.secrets.insert(
            nix_seal_core::Id::parse("service/token")?,
            nix_seal_core::Secret {
                source: "secrets/token.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: vec![group.clone()],
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        assert_eq!(
            group_references(&plan, &group),
            vec!["secret service/token"]
        );
        Ok(())
    }

    #[test]
    fn sops_migration_source_must_remain_below_its_repository_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("repository");
        fs::create_dir(&root)?;
        fs::write(root.join("legacy.yaml"), b"public test input")?;
        assert_eq!(
            resolve_migration_regular_file(&root, Path::new("legacy.yaml"))?,
            root.canonicalize()?.join("legacy.yaml")
        );
        assert!(resolve_migration_regular_file(&root, Path::new("../outside")).is_err());
        assert!(resolve_migration_regular_file(&root, Path::new("/absolute")).is_err());
        Ok(())
    }

    #[test]
    fn agenix_rekey_export_accepts_master_to_target_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let (_, target) = nix_seal_crypto::generate_x25519();
        let (_, master) = nix_seal_crypto::generate_x25519();
        let metadata = temporary.path().join("agenix-rekey.json");
        fs::write(
            &metadata,
            serde_json::json!({
                "schema":"nix-seal.agenix-rekey-export.v1",
                "target":{
                    "id":"desktop",
                    "kind":"nixos",
                    "system":"x86_64-linux",
                    "recipient":target,
                    "storageMode":"derivation"
                },
                "masterRecipients":[master],
                "secrets":{
                    "service-token":{"rekeyFile":"secrets/service-token.age"},
                    "derived":{"rekeyFile":"secrets/derived.age","intermediary":true}
                }
            })
            .to_string(),
        )?;
        migrate_agenix_rekey_export(&metadata, true)?;
        assert!(validate_agenix_rekey_source("../unsafe.age").is_err());
        Ok(())
    }

    #[test]
    fn clan_facts_inventory_accepts_documented_public_leaves()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let machines = temporary.path().join("machines");
        fs::create_dir(&machines)?;
        fs::create_dir(machines.join("desktop"))?;
        fs::create_dir(machines.join("desktop/facts"))?;
        fs::write(machines.join("desktop/facts/public-key"), b"public value")?;
        migrate_clan_facts_tree(&machines, false)?;
        Ok(())
    }

    #[test]
    fn sops_migration_commits_only_after_external_success() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        fs::create_dir(root.join("legacy"))?;
        fs::create_dir(root.join("secrets"))?;
        fs::write(root.join("legacy/source.yaml"), b"ignored by test producer")?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let identity_path = root.join("identity.age");
        write_private_bytes(&identity_path, identity.expose_secret().as_bytes())?;
        // Nix sandbox builders do not provide /usr/bin/true, and the PATH
        // entry is commonly a multicall coreutils symlink. Use an ephemeral,
        // regular executable so this continues to exercise the production
        // absolute, non-symlink check on every supported test platform.
        let shell = std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH is absent")?)
            .map(|directory| directory.join("sh"))
            .find(|candidate| candidate.is_file())
            .ok_or("sh is absent from PATH")?
            .canonicalize()?;
        let producer = root.join("successful-sops-producer");
        fs::write(&producer, format!("#!{}\nexit 0\n", shell.display()))?;
        fs::set_permissions(&producer, fs::Permissions::from_mode(0o700))?;
        migrate_sops_document(
            &root,
            Path::new("legacy/source.yaml"),
            Path::new("secrets/result.age"),
            &producer,
            None,
            &identity_path,
            &[recipient],
            false,
            true,
            false,
        )?;
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(
            fs::File::open(root.join("secrets/result.age"))?,
            &mut plaintext,
            &identity,
        )?;
        assert!(plaintext.is_empty());
        Ok(())
    }

    #[test]
    fn pgp_migration_is_dry_run_first_and_requires_a_private_home_for_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let home = root.join("gnupg");
        fs::create_dir(&home)?;
        #[cfg(unix)]
        set_private_directory(&home)?;
        migrate_pgp_document(
            &root,
            Path::new("legacy/source.pgp"),
            Path::new("secrets/result.age"),
            Path::new("/not/started/in-a-dry-run"),
            &home,
            Path::new("/not/read/in-a-dry-run"),
            &["age1dryrunrecipient".to_owned()],
            false,
            false,
            false,
        )?;
        assert!(!root.join("secrets/result.age").exists());
        assert_eq!(resolve_private_gnupg_home(&home)?, home);
        assert!(resolve_private_gnupg_home(&root.join("missing")).is_err());
        Ok(())
    }

    #[test]
    fn pgp_migration_command_ignores_configuration_and_network_key_lookup() {
        let command = pgp_decrypt_command(
            Path::new("/private/bin/gpg"),
            Path::new("/private/gnupg"),
            Path::new("/repository/legacy/source.pgp"),
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            arguments,
            vec![
                "--no-options",
                "--batch",
                "--quiet",
                "--no-tty",
                "--no-auto-key-locate",
                "--no-auto-key-import",
                "--no-auto-key-retrieve",
                "--decrypt",
                "/repository/legacy/source.pgp",
            ]
        );
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            environment,
            BTreeMap::from([
                ("GNUPGHOME".to_owned(), Some("/private/gnupg".to_owned())),
                ("LC_ALL".to_owned(), Some("C".to_owned())),
            ])
        );
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn built_in_generators_are_bounded_and_format_safe() -> Result<(), Box<dyn std::error::Error>> {
        let output = nix_seal_core::Id::parse("application/token")?;
        let random = nix_seal_core::Generator {
            executable: "builtin:random".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output.clone()],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("bytes".to_owned(), "48".to_owned())]),
            validation: None,
        };
        assert_eq!(generate_builtin_value(&random)?.expose_secret().len(), 48);
        let hex = nix_seal_core::Generator {
            executable: "builtin:hex".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output.clone()],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("bytes".to_owned(), "24".to_owned())]),
            validation: None,
        };
        let hex_value = generate_builtin_value(&hex)?;
        assert_eq!(hex_value.expose_secret().len(), 48);
        assert!(hex_value.expose_secret().iter().all(u8::is_ascii_hexdigit));
        let base64 = nix_seal_core::Generator {
            executable: "builtin:base64".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output.clone()],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("bytes".to_owned(), "24".to_owned())]),
            validation: None,
        };
        assert_eq!(generate_builtin_value(&base64)?.expose_secret().len(), 32);
        let token = nix_seal_core::Generator {
            executable: "builtin:token".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output.clone()],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("bytes".to_owned(), "24".to_owned())]),
            validation: None,
        };
        let token = generate_builtin_value(&token)?;
        assert_eq!(token.expose_secret().len(), 32);
        assert!(
            token
                .expose_secret()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
        let wireguard = nix_seal_core::Generator {
            executable: "builtin:wireguard-private-key".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output.clone()],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::new(),
            validation: None,
        };
        let wireguard = generate_builtin_value(&wireguard)?;
        let wireguard_bytes = BASE64_STANDARD.decode(wireguard.expose_secret())?;
        assert_eq!(wireguard_bytes.len(), 32);
        assert_eq!(wireguard_bytes[0] & 7, 0);
        assert_eq!(wireguard_bytes[31] & 128, 0);
        assert_eq!(wireguard_bytes[31] & 64, 64);
        let uuid = nix_seal_core::Generator {
            executable: "builtin:uuid".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![output],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::new(),
            validation: None,
        };
        let uuid = generate_builtin_value(&uuid)?;
        assert_eq!(uuid.expose_secret().len(), 36);
        assert_eq!(uuid.expose_secret()[14], b'4');
        assert!(matches!(
            uuid.expose_secret()[19],
            b'8' | b'9' | b'a' | b'b'
        ));
        Ok(())
    }

    #[test]
    fn passphrase_generator_enforces_its_entropy_floor() -> Result<(), Box<dyn std::error::Error>> {
        let generator = nix_seal_core::Generator {
            executable: "builtin:passphrase".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![nix_seal_core::Id::parse("application/passphrase")?],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("words".to_owned(), "12".to_owned())]),
            validation: None,
        };
        let value = generate_builtin_value(&generator)?;
        assert_eq!(
            value.expose_secret().split(|byte| *byte == b'-').count(),
            12
        );
        assert!(
            generate_passphrase(&nix_seal_core::Generator {
                parameters: BTreeMap::from([("words".to_owned(), "11".to_owned())]),
                ..generator
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn argon2id_password_hash_generator_uses_a_hidden_prompt_and_bounded_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        let generator = nix_seal_core::Generator {
            executable: "builtin:argon2id-password-hash".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![nix_seal_core::Id::parse("application/password-hash")?],
            public_outputs: Vec::new(),
            prompts: vec![nix_seal_core::GeneratorPrompt {
                id: nix_seal_core::Id::parse("password")?,
                mode: nix_seal_core::GeneratorPromptMode::Hidden,
                message: "Password".to_owned(),
                multiline: false,
                persistent: false,
            }],
            parameters: BTreeMap::from([
                ("memory-kib".to_owned(), "19456".to_owned()),
                ("iterations".to_owned(), "2".to_owned()),
                ("output-length".to_owned(), "16".to_owned()),
            ]),
            validation: None,
        };
        let password = SecretBox::new(Box::new(b"argon2id-test-password".to_vec()));
        let generated =
            generate_generator_values(&generator, &[password], GeneratorSecretInputs::None)?;
        let encoded = std::str::from_utf8(generated.secrets[0].expose_secret())?;
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        let parsed = PasswordHash::new(encoded)
            .map_err(|_| "generated Argon2id output is not a valid PHC hash")?;
        Argon2::default()
            .verify_password(b"argon2id-test-password", &parsed)
            .map_err(|_| "generated Argon2id output did not verify")?;
        let visible = nix_seal_core::Generator {
            prompts: vec![nix_seal_core::GeneratorPrompt {
                mode: nix_seal_core::GeneratorPromptMode::Visible,
                ..generator.prompts[0].clone()
            }],
            ..generator
        };
        assert!(
            generate_generator_values(
                &visible,
                &[SecretBox::new(Box::new(b"argon2id-test-password".to_vec()))],
                GeneratorSecretInputs::None,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn generator_validation_state_triggers_only_explicit_fingerprint_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        fs::create_dir_all(repository.join("secrets"))?;
        let generator_id = nix_seal_core::Id::parse("application-token")?;
        let secret_id = nix_seal_core::Id::parse("application/token")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/token.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        let generator = nix_seal_core::Generator {
            executable: "builtin:uuid".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![secret_id],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::new(),
            validation: Some("v1".to_owned()),
        };
        assert_eq!(
            generator_action(&plan, &generator_id, &generator, &repository, false)?,
            GeneratorAction::Create
        );
        fs::write(repository.join("secrets/token.age"), b"ciphertext")?;
        write_generator_state(
            &repository,
            &generator_id,
            "v1",
            &generator.outputs,
            &generator
                .public_outputs
                .iter()
                .map(|output| output.id.clone())
                .collect::<Vec<_>>(),
        )?;
        assert_eq!(
            generator_action(&plan, &generator_id, &generator, &repository, false)?,
            GeneratorAction::Unchanged
        );
        let changed = nix_seal_core::Generator {
            validation: Some("v2".to_owned()),
            ..generator
        };
        assert_eq!(
            generator_action(&plan, &generator_id, &changed, &repository, false)?,
            GeneratorAction::Replace
        );
        remove_generator_state(&repository, &generator_id)?;
        assert!(generator_action(&plan, &generator_id, &changed, &repository, false).is_err());
        Ok(())
    }

    #[test]
    fn interactive_prompt_resolution_is_explicit_and_keeps_noninteractive_runs_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        fs::create_dir_all(&repository)?;
        let generator_id = nix_seal_core::Id::parse("application/bootstrap")?;
        let prompt_id = nix_seal_core::Id::parse("database/password")?;
        let generator = nix_seal_core::Generator {
            executable: "/nix/store/example/bin/generator".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![nix_seal_core::Id::parse("application/token")?],
            public_outputs: Vec::new(),
            prompts: vec![nix_seal_core::GeneratorPrompt {
                id: prompt_id.clone(),
                mode: nix_seal_core::GeneratorPromptMode::Hidden,
                message: "Database password".to_owned(),
                multiline: false,
                persistent: false,
            }],
            parameters: BTreeMap::new(),
            validation: None,
        };
        let mut plan = nix_seal_core::PlanV1::default();
        plan.generators.insert(generator_id.clone(), generator);
        let order = vec![generator_id];
        assert!(validate_generator_prompt_files(&plan, &order, &[], &repository, false).is_err());
        let resolved = validate_generator_prompt_files(&plan, &order, &[], &repository, true)?;
        assert_eq!(resolved.get(&prompt_id), Some(&None));
        Ok(())
    }

    #[test]
    fn persistent_prompt_state_is_private_and_reused() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        fs::create_dir_all(&repository)?;
        let generator_id = nix_seal_core::Id::parse("application/bootstrap")?;
        let prompt_id = nix_seal_core::Id::parse("database/password")?;
        let generator = nix_seal_core::Generator {
            executable: "/nix/store/example/bin/generator".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![nix_seal_core::Id::parse("application/token")?],
            public_outputs: Vec::new(),
            prompts: vec![nix_seal_core::GeneratorPrompt {
                id: prompt_id.clone(),
                mode: nix_seal_core::GeneratorPromptMode::Hidden,
                message: "Database password".to_owned(),
                multiline: false,
                persistent: true,
            }],
            parameters: BTreeMap::new(),
            validation: None,
        };
        let mut plan = nix_seal_core::PlanV1::default();
        plan.generators
            .insert(generator_id.clone(), generator.clone());
        let value = SecretBox::new(Box::new(b"persistent-prompt".to_vec()));
        persist_generator_prompts(&repository, &generator_id, &generator, &[value])?;
        let path = generator_prompt_state_path(&repository, &generator_id, &prompt_id)?;
        let metadata = fs::metadata(&path)?;
        assert!(metadata.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(metadata.permissions().mode() & 0o077, 0);
        }
        let files = validate_generator_prompt_files(
            &plan,
            std::slice::from_ref(&generator_id),
            &[],
            &repository,
            false,
        )?;
        let restored = read_generator_prompts(&generator, &files)?;
        assert_eq!(restored[0].expose_secret(), b"persistent-prompt");
        Ok(())
    }

    #[test]
    fn ssh_ed25519_generator_emits_a_standard_age_compatible_private_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let generator = nix_seal_core::Generator {
            executable: "builtin:ssh-ed25519".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![nix_seal_core::Id::parse("application/ssh-private-key")?],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::new(),
            validation: None,
        };
        let value = generate_builtin_value(&generator)?;
        let text = String::from_utf8(value.expose_secret().clone())?;
        assert!(text.starts_with(concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----\n")));
        assert!(text.ends_with(concat!("-----END OPENSSH ", "PRIVATE KEY-----\n")));
        let recipient = nix_seal_crypto::recipient_from_identity(&SecretString::from(text))?;
        assert!(recipient.starts_with("ssh-ed25519 "));
        assert!(
            generate_ssh_ed25519_private_key(&nix_seal_core::Generator {
                outputs: vec![
                    nix_seal_core::Id::parse("application/first")?,
                    nix_seal_core::Id::parse("application/second")?,
                ],
                ..generator
            })
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn init_creates_a_valid_empty_public_plan_without_overwriting()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let config = temporary.path().join("nix-seal.toml");
        run_init(&config, true)?;
        let plan = nix_seal_policy::load_toml(&config)?;
        nix_seal_policy::validate(&plan)?;
        assert!(plan.identities.is_empty());
        assert!(plan.secrets.is_empty());
        assert!(run_init(&config, false).is_err());
        assert!(run_init(&temporary.path().join("nix-seal.json"), false).is_err());
        Ok(())
    }

    #[test]
    fn constrained_external_generator_uses_private_declared_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let shell = std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH is absent")?)
            .map(|directory| directory.join("sh"))
            .find(|candidate| candidate.is_file())
            .ok_or("sh is absent from PATH")?
            .canonicalize()?;
        let generator = nix_seal_core::Generator {
            executable: shell.to_string_lossy().into_owned(),
            arguments: vec![
                "-c".to_owned(),
                "IFS= read -r value < \"$NIX_SEAL_PROMPT_DIR/0\"; printf %s \"$value\" > \"$NIX_SEAL_OUTPUT_DIR/0\"; printf second > \"$NIX_SEAL_OUTPUT_DIR/1\"; printf public > \"$NIX_SEAL_PUBLIC_OUTPUT_DIR/0\"".to_owned(),
            ],
            runtime_inputs: Vec::new(),
            timeout_seconds: 5,
            max_output_bytes: 1024,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: vec![
                nix_seal_core::Id::parse("generator/one")?,
                nix_seal_core::Id::parse("generator/two")?,
            ],
            public_outputs: vec![nix_seal_core::GeneratorPublicOutput {
                id: nix_seal_core::Id::parse("generator/public")?,
                destination: "public/generator-output".to_owned(),
            }],
            prompts: vec![nix_seal_core::GeneratorPrompt {
                id: nix_seal_core::Id::parse("generator/value")?,
                mode: nix_seal_core::GeneratorPromptMode::Hidden,
                message: "test prompt".to_owned(),
                multiline: false,
                persistent: false,
            }],
            parameters: BTreeMap::new(),
            validation: None,
        };
        let values = generate_external_values(
            &generator,
            &[SecretBox::new(Box::new(b"first".to_vec()))],
            GeneratorSecretInputs::None,
        )?;
        assert_eq!(values.secrets.len(), 2);
        assert_eq!(values.secrets[0].expose_secret(), b"first");
        assert_eq!(values.secrets[1].expose_secret(), b"second");
        assert_eq!(values.public.len(), 1);
        assert_eq!(values.public[0].expose_secret(), b"public");
        Ok(())
    }

    #[test]
    fn constrained_external_generator_receives_only_declared_secret_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let shell = std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH is absent")?)
            .map(|directory| directory.join("sh"))
            .find(|candidate| candidate.is_file())
            .ok_or("sh is absent from PATH")?
            .canonicalize()?;
        let temporary = tempfile::tempdir()?;
        let repository = temporary.path().join("repository");
        fs::create_dir_all(repository.join("secrets"))?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let dependency_id = nix_seal_core::Id::parse("application/input")?;
        let output_id = nix_seal_core::Id::parse("application/output")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient.clone(),
            },
        );
        plan.identities.insert(
            nix_seal_core::Id::parse("signer")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: nix_seal_manifest::ApprovalSigningKey::generate()?.encode_public()?,
            },
        );
        plan.secrets.insert(
            dependency_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/input.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        nix_seal_crypto::encrypt(
            std::io::Cursor::new(b"dependency-canary"),
            fs::File::create(repository.join("secrets/input.age"))?,
            &[recipient],
        )?;
        let generator = nix_seal_core::Generator {
            executable: shell.to_string_lossy().into_owned(),
            arguments: vec![
                "-c".to_owned(),
                "test \"$NIX_SEAL_SECRET_COUNT\" = 1; test -f \"$NIX_SEAL_SECRET_DIR/0\"; test ! -e \"$NIX_SEAL_SECRET_DIR/1\"; IFS= read -r value < \"$NIX_SEAL_SECRET_DIR/0\"; printf %s \"$value\" > \"$NIX_SEAL_OUTPUT_DIR/0\"".to_owned(),
            ],
            runtime_inputs: Vec::new(),
            timeout_seconds: 5,
            max_output_bytes: 1024,
            dependencies: Vec::new(),
            secret_dependencies: vec![dependency_id],
            outputs: vec![output_id],
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::new(),
            validation: None,
        };
        let values = generate_external_values(
            &generator,
            &[],
            GeneratorSecretInputs::Plan {
                plan: &plan,
                repository_root: &repository,
                identity: &identity,
            },
        )?;
        assert_eq!(values.secrets.len(), 1);
        assert_eq!(values.secrets[0].expose_secret(), b"dependency-canary");
        let (unauthorized_identity, _) = nix_seal_crypto::generate_x25519();
        assert!(
            generate_external_values(
                &generator,
                &[],
                GeneratorSecretInputs::Plan {
                    plan: &plan,
                    repository_root: &repository,
                    identity: &unauthorized_identity,
                },
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn secretctl_migration_normalizes_only_representable_public_identifiers()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            migrated_id("IanHollow.home.ianmh.token")?.as_str(),
            "ianhollow.home.ianmh.token"
        );
        assert_eq!(
            migrated_id("host:nixos:desktop")?.as_str(),
            "host-nixos-desktop"
        );
        assert_eq!(
            migrated_id("home:ianmh@desktop")?.as_str(),
            "home-ianmh-desktop"
        );
        assert!(migrated_id("legacy value").is_err());
        assert_eq!(
            migrate_secretctl_source("secrets/IanHollow/token.age")?,
            "secrets/IanHollow/token.age"
        );
        assert!(migrate_secretctl_source("../secrets/token.age").is_err());
        assert!(migrate_secretctl_source("secrets/token.txt").is_err());
        Ok(())
    }

    #[test]
    fn secretctl_migration_cross_checks_groups_targets_and_recipients()
    -> Result<(), Box<dyn std::error::Error>> {
        let first =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEolRZAKwwqDLSkgezpqNK4WYLjMsE1qp8f3k7nYMVgq"
                .to_owned();
        let second =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFwSeiaY3PpNjPDaFA9bDPeFaLU5HYi0PrJKEEYIt3Vs"
                .to_owned();
        let group_recipients = vec![first.clone(), second.clone()];
        let mut index = SecretctlIndexV1 {
            version: 1,
            groups: BTreeMap::from([("operators".to_owned(), group_recipients.clone())]),
            targets: BTreeMap::from([
                (
                    "home:ianmh@desktop".to_owned(),
                    SecretctlTargetV1 {
                        target_type: "home".to_owned(),
                        groups: vec!["operators".to_owned()],
                        public_key: first.clone(),
                        recipients: group_recipients.clone(),
                    },
                ),
                (
                    "host:nixos:desktop".to_owned(),
                    SecretctlTargetV1 {
                        target_type: "host".to_owned(),
                        groups: vec!["operators".to_owned()],
                        public_key: second.clone(),
                        recipients: group_recipients.clone(),
                    },
                ),
            ]),
            secrets: BTreeMap::from([(
                "operators.home.ianmh.token".to_owned(),
                SecretctlSecretV1 {
                    id: "operators.home.ianmh.token".to_owned(),
                    group: "operators".to_owned(),
                    scope: "home".to_owned(),
                    selector: Some("ianmh".to_owned()),
                    agenix_name: "token".to_owned(),
                    file: "secrets/operators/home/ianmh/token.age".to_owned(),
                    recipients: vec![first.clone()],
                    consumers: vec!["home:ianmh@desktop".to_owned()],
                },
            )]),
        };
        let report = build_secretctl_migration_report(&index)?;
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.targets.len(), 2);
        assert_eq!(report.secrets.len(), 1);
        assert_eq!(report.ssh_recipient_count, 2);
        let signer = nix_seal_manifest::ApprovalSigningKey::generate()?;
        let plan = build_secretctl_candidate_plan(
            &index,
            &[
                "home:ianmh@desktop=x86_64-linux".to_owned(),
                "host:nixos:desktop=x86_64-linux".to_owned(),
            ],
            &[format!("release={}", signer.encode_public()?)],
        )?;
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(plan.groups.len(), 1);
        assert!(matches!(
            plan.secrets[&nix_seal_core::Id::parse("operators.home.ianmh.token")?].delivery,
            nix_seal_core::DeliveryMode::Direct
        ));
        assert_eq!(
            nix_seal_policy::secret_recipients(
                &plan,
                &nix_seal_core::Id::parse("operators.home.ianmh.token")?
            )?
            .recipients
            .len(),
            1
        );

        index
            .targets
            .get_mut("home:ianmh@desktop")
            .ok_or("target")?
            .recipients = vec![first];
        assert!(build_secretctl_migration_report(&index).is_err());
        Ok(())
    }

    #[test]
    fn agenix_migration_inventory_accepts_only_valid_age_ciphertexts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("secrets");
        std::fs::create_dir_all(directory.join("nested"))?;
        let (_, recipient) = nix_seal_crypto::generate_x25519();
        let ciphertext = directory.join("nested/token.age");
        let mut output = std::fs::File::create(&ciphertext)?;
        nix_seal_crypto::encrypt(
            b"migration-canary".as_slice(),
            &mut output,
            std::slice::from_ref(&recipient),
        )?;
        output.sync_all()?;
        let canonical = directory.canonicalize()?;
        let mut discovered = Vec::new();
        scan_agenix_ciphertexts(&canonical, &canonical, &mut discovered)?;
        assert_eq!(discovered, vec![ciphertext.canonicalize()?]);
        assert_eq!(
            migrated_id("agenix/nested/token")?.as_str(),
            "agenix/nested/token"
        );
        Ok(())
    }

    #[test]
    fn sops_json_migration_accepts_bounded_age_metadata() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("secrets");
        std::fs::create_dir_all(directory.join("nested"))?;
        let (_, recipient) = nix_seal_crypto::generate_x25519();
        let document = serde_json::json!({
            "token": "ENC[AES256_GCM,data:placeholder,type:str]",
            "sops": {
                "age": [{"recipient":recipient, "enc":"-----BEGIN AGE ENCRYPTED FILE-----"}],
                "mac": "ENC[AES256_GCM,data:placeholder,type:str]",
                "version": "3.9.0"
            }
        });
        let path = directory.join("nested/token.json");
        std::fs::write(&path, serde_json::to_vec(&document)?)?;
        let canonical = directory.canonicalize()?;
        let mut discovered = Vec::new();
        scan_sops_json_files(&canonical, &canonical, &mut discovered)?;
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].providers, BTreeSet::from(["age".to_owned()]));
        assert_eq!(discovered[0].age_recipient_count, 1);
        assert_eq!(
            migrated_id("sops/nested/token")?.as_str(),
            "sops/nested/token"
        );

        std::fs::write(directory.join("not-sops.json"), b"{}")?;
        assert!(scan_sops_json_files(&canonical, &canonical, &mut Vec::new()).is_err());
        Ok(())
    }

    #[test]
    fn clan_vars_migration_inventories_value_leaves_without_reading_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("vars/per-machine");
        let value = root.join("desktop/service-token/api-token/value");
        std::fs::create_dir_all(value.parent().ok_or("value parent")?)?;
        std::fs::write(&value, b"opaque-clan-var-fixture")?;
        std::fs::write(
            root.join("desktop/service-token/.validation.json"),
            b"public auxiliary metadata",
        )?;
        let canonical = root.canonicalize()?;
        let mut discovered = Vec::new();
        let mut auxiliary = 0;
        scan_clan_vars_files(&canonical, &canonical, &mut discovered, &mut auxiliary)?;
        assert_eq!(discovered.len(), 1);
        assert_eq!(auxiliary, 1);
        assert_eq!(discovered[0].machine, "desktop");
        assert_eq!(discovered[0].generator, "service-token");
        assert_eq!(discovered[0].output, "api-token");
        assert_eq!(discovered[0].bytes, 23);
        assert_eq!(
            migrated_id("clan-vars/desktop/service-token/api-token")?.as_str(),
            "clan-vars/desktop/service-token/api-token"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn agenix_migration_refuses_a_symlinked_root() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let linked = temporary.path().join("secrets");
        symlink(outside.path(), &linked)?;
        assert!(migrate_agenix_tree(&linked, "agenix", false).is_err());
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn plan_directed_builtin_generation_encrypts_and_requires_replace()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let identity_path = temporary.path().join("administrator.identity");
        let plan_path = temporary.path().join("plan.v1.json");
        let repository = temporary.path().join("repository");
        std::fs::create_dir_all(repository.join("secrets"))?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        write_new_private(&identity_path, identity.expose_secret().as_bytes())?;
        let secret_id = nix_seal_core::Id::parse("application/token")?;
        let second_secret_id = nix_seal_core::Id::parse("application/secondary-token")?;
        let generator_id = nix_seal_core::Id::parse("application-token")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient,
            },
        );
        plan.identities.insert(
            nix_seal_core::Id::parse("signer.release")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: nix_seal_manifest::ApprovalSigningKey::generate()?.encode_public()?,
            },
        );
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/application-token.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        plan.secrets.insert(
            second_secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/application-secondary-token.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        plan.generators.insert(
            generator_id.clone(),
            nix_seal_core::Generator {
                executable: "builtin:hex".to_owned(),
                arguments: Vec::new(),
                runtime_inputs: Vec::new(),
                timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
                max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
                dependencies: Vec::new(),
                secret_dependencies: Vec::new(),
                outputs: vec![secret_id, second_secret_id],
                public_outputs: Vec::new(),
                prompts: Vec::new(),
                parameters: BTreeMap::from([("bytes".to_owned(), "20".to_owned())]),
                validation: None,
            },
        );
        nix_seal_policy::validate(&plan)?;
        std::fs::write(&plan_path, nix_seal_policy::canonical_json(&plan)?)?;
        let request = GenerateArgs {
            plan: plan_path,
            generator: generator_id,
            repository_root: repository.clone(),
            identity: identity_path.clone(),
            replace: false,
            prompt_files: Vec::new(),
            interactive: false,
        };
        run_generate(&request, false)?;
        let ciphertext = repository.join("secrets/application-token.age");
        let second_ciphertext = repository.join("secrets/application-secondary-token.age");
        let mut first = Vec::new();
        nix_seal_crypto::decrypt(std::fs::File::open(&ciphertext)?, &mut first, &identity)?;
        assert_eq!(first.len(), 40);
        let mut second = Vec::new();
        nix_seal_crypto::decrypt(
            std::fs::File::open(&second_ciphertext)?,
            &mut second,
            &identity,
        )?;
        assert_eq!(second.len(), 40);
        assert_ne!(first, second);
        assert!(run_generate(&request, false).is_err());
        let mut unchanged = Vec::new();
        nix_seal_crypto::decrypt(std::fs::File::open(&ciphertext)?, &mut unchanged, &identity)?;
        assert_eq!(first, unchanged);
        let mut second_unchanged = Vec::new();
        nix_seal_crypto::decrypt(
            std::fs::File::open(&second_ciphertext)?,
            &mut second_unchanged,
            &identity,
        )?;
        assert_eq!(second, second_unchanged);
        run_generate(
            &GenerateArgs {
                replace: true,
                ..request
            },
            false,
        )?;
        let mut rotated = Vec::new();
        nix_seal_crypto::decrypt(std::fs::File::open(&ciphertext)?, &mut rotated, &identity)?;
        assert_eq!(rotated.len(), 40);
        assert_ne!(first, rotated);
        let mut second_rotated = Vec::new();
        nix_seal_crypto::decrypt(
            std::fs::File::open(&second_ciphertext)?,
            &mut second_rotated,
            &identity,
        )?;
        assert_eq!(second_rotated.len(), 40);
        assert_ne!(second, second_rotated);
        Ok(())
    }

    #[test]
    // Exercise the full signed activation document and renderer through the CLI bridge.
    #[allow(clippy::too_many_lines)]
    fn internal_activate_command_materializes_signed_spec() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let identity_path = temporary.path().join("target.identity");
        let ciphertext_path = temporary.path().join("artifact.age");
        let envelope_path = temporary.path().join("artifact.json");
        let template_path = temporary.path().join("application.conf.template");
        let plan_path = temporary.path().join("plan.v1.json");
        let spec_path = temporary.path().join("activation.json");
        let runtime_root = temporary.path().join("runtime");
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        write_new_private(&identity_path, identity.expose_secret().as_bytes())?;
        let mut ciphertext = std::fs::File::create(&ciphertext_path)?;
        nix_seal_crypto::encrypt(
            b"cli-activation-canary".as_slice(),
            &mut ciphertext,
            std::slice::from_ref(&recipient),
        )?;
        ciphertext.sync_all()?;
        let artifact_hash = blake3::hash(&std::fs::read(&ciphertext_path)?)
            .to_hex()
            .to_string();
        let source_hash = "1".repeat(64);
        let target_id = nix_seal_core::Id::parse("host.test")?;
        let secret_id = nix_seal_core::Id::parse("db/password")?;
        let signer = nix_seal_manifest::ApprovalSigningKey::generate()?;
        std::fs::write(&template_path, b"password={{nix-seal:password-base64}}\n")?;
        let owner = uzers::get_user_by_uid(uzers::get_current_uid())
            .and_then(|user| user.name().to_str().map(str::to_owned))
            .ok_or("current user is not resolvable")?;
        let group = uzers::get_group_by_gid(uzers::get_current_gid())
            .and_then(|group| group.name().to_str().map(str::to_owned))
            .ok_or("current group is not resolvable")?;
        let target_identity_id = nix_seal_core::Id::parse("target.host-test")?;
        let signer_id = nix_seal_core::Id::parse("signer.release")?;
        let template_id = nix_seal_core::Id::parse("application/config")?;
        let runtime = nix_seal_core::RuntimeSettings {
            owner: owner.clone(),
            group: group.clone(),
            mode: "0400".to_owned(),
            restart_units: Vec::new(),
            reload_units: Vec::new(),
        };
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            target_identity_id.clone(),
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Target,
                public: recipient.clone(),
            },
        );
        plan.identities.insert(
            signer_id,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: signer.encode_public()?,
            },
        );
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: recipient.clone(),
            },
        );
        plan.targets.insert(
            target_id.clone(),
            nix_seal_core::Target {
                kind: nix_seal_core::TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: target_identity_id,
                username: None,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/db.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: vec![target_id.clone()],
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: runtime.clone(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        plan.templates.insert(
            template_id.clone(),
            nix_seal_core::Template {
                source: template_path.to_string_lossy().into_owned(),
                placeholders: BTreeMap::from([(
                    "password-base64".to_owned(),
                    nix_seal_core::TemplatePlaceholder {
                        secret: secret_id.clone(),
                        encoding: nix_seal_core::TemplateEncoding::Base64,
                    },
                )]),
                runtime: runtime.clone(),
            },
        );
        nix_seal_policy::validate(&plan)?;
        std::fs::write(&plan_path, nix_seal_policy::canonical_json(&plan)?)?;
        let policy = nix_seal_policy::target_policy(&plan, &target_id)?;
        let target_policy_hash = nix_seal_policy::target_policy_hash(&policy)?;
        let fingerprint = nix_seal_crypto::recipient_fingerprint(&recipient)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let manifest = TargetManifestV2 {
            schema: ARTIFACT_SCHEMA.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            plan_hash: policy.plan_hash.clone(),
            target_policy_hash,
            source_ciphertext_hash: source_hash.clone(),
            artifact_ciphertext_hash: artifact_hash,
            target_id: target_id.clone(),
            secret_id: secret_id.clone(),
            recipient_fingerprint: fingerprint,
            artifact_generation: 1,
            issued_at: now.saturating_sub(1),
            expires_at: now.checked_add(60),
        };
        write_new_json(
            &envelope_path,
            &nix_seal_manifest::sign_manifest(&manifest, &signer)?,
        )?;
        let mut spec = nix_seal_runtime::ActivationSpecV2 {
            schema: nix_seal_runtime::ACTIVATION_SCHEMA.to_owned(),
            runtime_root: runtime_root.clone(),
            runtime_generation: None,
            plan: plan_path,
            target_id,
            phase: nix_seal_core::ActivationPhase::Activation,
            allowed_clock_skew: 0,
            artifacts: vec![nix_seal_runtime::ActivationArtifactSpecV2 {
                ciphertext: ciphertext_path,
                envelope: envelope_path,
                secret_id: secret_id.clone(),
                phase: nix_seal_core::ActivationPhase::Activation,
                source_ciphertext_hash: source_hash,
                artifact_generation: 1,
                mode: "0400".to_owned(),
                owner: owner.clone(),
                group: group.clone(),
            }],
            templates: vec![nix_seal_runtime::ActivationTemplateSpecV1 {
                source: template_path,
                template_id,
                phase: nix_seal_core::ActivationPhase::Activation,
                placeholders: BTreeMap::from([(
                    "password-base64".to_owned(),
                    nix_seal_runtime::TemplatePlaceholderSpecV1 {
                        secret_id,
                        encoding: nix_seal_runtime::TemplateEncodingV1::Base64,
                    },
                )]),
                mode: "0400".to_owned(),
                owner,
                group,
            }],
            post_switch: None,
        };
        write_new_json(&spec_path, &spec)?;
        run_activate(
            &ActivateArgs {
                spec: spec_path.clone(),
                identity: identity_path.clone(),
                runtime_root: None,
            },
            false,
        )?;
        assert_eq!(
            std::fs::read(runtime_root.join("current/db/password"))?,
            b"cli-activation-canary"
        );
        assert_eq!(
            std::fs::read(runtime_root.join("current/templates/application/config"))?,
            b"password=Y2xpLWFjdGl2YXRpb24tY2FuYXJ5\n"
        );
        spec.artifacts[0].mode = "0600".to_owned();
        std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
        let error = match run_activate(
            &ActivateArgs {
                spec: spec_path.clone(),
                identity: identity_path.clone(),
                runtime_root: None,
            },
            false,
        ) {
            Ok(()) => return Err("caller-supplied runtime policy drift was accepted".into()),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("differs from the canonical plan")
        );
        assert_eq!(
            std::fs::read(runtime_root.join("current/db/password"))?,
            b"cli-activation-canary"
        );
        spec.artifacts[0].mode = "0400".to_owned();
        spec.phase = nix_seal_core::ActivationPhase::Users;
        spec.artifacts[0].phase = nix_seal_core::ActivationPhase::Users;
        spec.templates[0].phase = nix_seal_core::ActivationPhase::Users;
        std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
        let error = match run_activate(
            &ActivateArgs {
                spec: spec_path,
                identity: identity_path,
                runtime_root: None,
            },
            false,
        ) {
            Ok(()) => return Err("caller-supplied activation phase drift was accepted".into()),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("activation artifact set does not exactly match target policy")
        );
        assert_eq!(
            std::fs::read(runtime_root.join("current/db/password"))?,
            b"cli-activation-canary"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn cache_gc_retains_only_current_authenticated_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let repository_root = temporary.path().join("repository");
        let source_path = repository_root.join("secrets/application.age");
        std::fs::create_dir_all(source_path.parent().ok_or("source has no parent")?)?;
        let (administrator_identity, administrator_recipient) = nix_seal_crypto::generate_x25519();
        let (_, target_recipient) = nix_seal_crypto::generate_x25519();
        let signer = nix_seal_manifest::ApprovalSigningKey::generate()?;
        let target_id = nix_seal_core::Id::parse("host.test")?;
        let secret_id = nix_seal_core::Id::parse("application/token")?;
        let target_identity_id = nix_seal_core::Id::parse("target.host-test")?;
        let signer_id = nix_seal_core::Id::parse("signer.release")?;
        let mut plan = nix_seal_core::PlanV1::default();
        plan.identities.insert(
            nix_seal_core::Id::parse("administrator")?,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Administrator,
                public: administrator_recipient,
            },
        );
        plan.identities.insert(
            target_identity_id.clone(),
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Target,
                public: target_recipient.clone(),
            },
        );
        plan.identities.insert(
            signer_id,
            nix_seal_core::Identity {
                kind: nix_seal_core::IdentityKind::Signer,
                public: signer.encode_public()?,
            },
        );
        plan.targets.insert(
            target_id.clone(),
            nix_seal_core::Target {
                kind: nix_seal_core::TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: target_identity_id,
                username: None,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        plan.secrets.insert(
            secret_id.clone(),
            nix_seal_core::Secret {
                source: "secrets/application.age".to_owned(),
                delivery: nix_seal_core::DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: vec![target_id.clone()],
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: nix_seal_core::RuntimeSettings::default(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        nix_seal_policy::validate(&plan)?;
        let mut source = std::fs::File::create(&source_path)?;
        nix_seal_crypto::encrypt(
            b"gc-canary".as_slice(),
            &mut source,
            &[plan
                .identities
                .get(&nix_seal_core::Id::parse("administrator")?)
                .ok_or("administrator missing")?
                .public
                .clone()],
        )?;
        source.sync_all()?;
        let policy = nix_seal_policy::target_policy(&plan, &target_id)?;
        let cache = nix_seal_cache::Cache::open(temporary.path().join("cache"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        nix_seal_rekey::rekey(
            &cache,
            &nix_seal_rekey::RekeyRequest {
                source: &source_path,
                administrator_identity: &administrator_identity,
                target_recipient: &target_recipient,
                plan_hash: &nix_seal_policy::plan_hash(&plan)?,
                target_policy_hash: &nix_seal_policy::target_policy_hash(&policy)?,
                target_id: &target_id,
                secret_id: &secret_id,
                artifact_generation: 1,
                issued_at: now,
                expires_at: now.checked_add(60),
                tool_version: env!("CARGO_PKG_VERSION"),
                signing_key: &signer,
            },
        )?;
        cache.put(b"unreferenced ciphertext")?;

        let retention = authenticated_gc_retention(&cache, &plan, &repository_root)?;
        assert_eq!(retention.artifact_keys.len(), 1);
        assert_eq!(retention.unavailable_sources, 0);
        let report = cache.garbage_collect(&nix_seal_cache::GcRequest {
            retained_artifacts: retention.artifact_keys,
            retained_objects: BTreeSet::new(),
            execute: false,
        })?;
        assert_eq!(report.retained_artifacts, 1);
        assert_eq!(report.candidate_objects, 1);

        plan.targets
            .get_mut(&target_id)
            .ok_or("target missing")?
            .tags
            .push("changed".to_owned());
        let stale = authenticated_gc_retention(&cache, &plan, &repository_root)?;
        assert!(stale.artifact_keys.is_empty());
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Command-line interface. Plaintext output is limited to `secret reveal`.

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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
    /// Identity operations.
    #[command(subcommand)]
    Key(KeyCommand),
    /// Signed target-artifact operations.
    #[command(subcommand)]
    Artifact(ArtifactCommand),
    /// Explicitly create or verify a target-encrypted cache artifact.
    Rekey(RekeyArgs),
    /// Internal authenticated runtime activation entrypoint.
    #[command(hide = true)]
    Activate(ActivateArgs),
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
    /// Generate shell completion definitions.
    Completions { shell: CompletionShell },
    /// Ciphertext cache operations.
    #[command(subcommand)]
    Cache(CacheCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
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
    /// Administrator X25519 identity file.
    #[arg(long)]
    identity: PathBuf,
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
    if let Err(error) = run() {
        eprintln!("nix-seal: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
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
        Command::Key(command) => run_key(command, cli.json)?,
        Command::Artifact(command) => run_artifact(command, cli.json)?,
        Command::Rekey(arguments) => run_rekey(arguments, cli.json)?,
        Command::Activate(arguments) => run_activate(&arguments, cli.json)?,
        Command::Secret(command) => run_secret(command, cli.json)?,
        Command::Rotate(arguments) => run_secret_write(
            &arguments,
            nix_seal_authoring::WriteMode::Replace,
            cli.json,
            "rotated",
        )?,
        Command::Recipients(arguments) => run_recipients(&arguments, cli.json)?,
        Command::Schema { kind } => run_schema(kind)?,
        Command::Completions { shell } => completions(shell),
        Command::Cache(CacheCommand::Status { root }) => cache_status(root, cli.json)?,
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
            let private = key.encode_private();
            write_new_private(&key_out, private.as_bytes())?;
            print_signing_key(&key, &key_out, json);
        }
        KeyCommand::InspectSigning { key } => {
            let signing_key = read_signing_key(&key)?;
            print_signing_key(&signing_key, &key, json);
        }
    }
    Ok(())
}

fn print_signing_key(key: &nix_seal_manifest::ApprovalSigningKey, path: &Path, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "publicKey":key.encode_public(),
                "keyId":key.key_id(),
                "keyPath":path
            })
        );
    } else {
        println!("{}", key.encode_public());
        eprintln!("key ID: {}", key.key_id());
    }
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
    if !matches!(secret_policy.delivery, nix_seal_core::DeliveryMode::Rekeyed) {
        bail!(
            "secret {} uses direct delivery and cannot be target-rekeyed",
            arguments.secret
        );
    }
    let source = arguments.repository_root.join(&secret_policy.source);
    let identity = read_identity(&arguments.identity)?;
    let signing_key = read_signing_key(&arguments.signing_key)?;
    let signing_public = signing_key.encode_public();
    if !secret_policy
        .approval
        .signers
        .values()
        .any(|public| public == &signing_public)
    {
        bail!(
            "signing key is not authorized by the approval policy for secret {}",
            arguments.secret
        );
    }
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    if arguments
        .expires_at
        .is_some_and(|expiry| expiry <= issued_at)
    {
        bail!("--expires-at must be later than the current time");
    }
    let root = arguments.cache_root.unwrap_or_else(default_cache_root);
    let cache = nix_seal_cache::Cache::open(root)?;
    let request = nix_seal_rekey::RekeyRequest {
        source: &source,
        administrator_identity: &identity,
        target_recipient: &policy.recipient,
        plan_hash: &policy.plan_hash,
        target_policy_hash: &target_policy_hash,
        target_id: &arguments.target,
        secret_id: &arguments.secret,
        artifact_generation: arguments.generation,
        issued_at,
        expires_at: arguments.expires_at,
        tool_version: env!("CARGO_PKG_VERSION"),
        signing_key: &signing_key,
    };
    let result = nix_seal_rekey::rekey(&cache, &request)?;
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
                "generation":arguments.generation
            })
        );
    } else {
        println!("{}", result.cache_key);
        eprintln!(
            "{} target artifact for {} on {}: {}",
            if result.reused { "reused" } else { "created" },
            arguments.secret,
            arguments.target,
            result.ciphertext_path.display()
        );
    }
    Ok(())
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
    let policy_secret_ids: BTreeSet<_> = policy.secrets.keys().collect();
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
        if artifact.owner != secret.runtime.owner
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
    let policy_template_ids: BTreeSet<_> = policy.templates.keys().collect();
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
        if template.source != expected_source
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
        .map(|secret| &secret.runtime)
        .chain(policy.templates.values().map(|template| &template.runtime))
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
    if nix_seal_crypto::recipient_from_identity(&identity)? != policy.recipient {
        bail!("target identity does not match the recipient selected by plan policy");
    }
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
    Ok(plan)
}

fn deep_check_plan(plan: &nix_seal_core::PlanV1, repository_root: &Path) -> Result<()> {
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    for (id, identity) in &plan.identities {
        match identity.kind {
            nix_seal_core::IdentityKind::Signer => {
                trusted
                    .insert_encoded(&identity.public)
                    .with_context(|| format!("signer identity {id} is malformed or duplicated"))?;
            }
            nix_seal_core::IdentityKind::Plugin => {
                bail!("identity {id} uses a plugin that this release cannot deeply validate");
            }
            nix_seal_core::IdentityKind::Administrator
            | nix_seal_core::IdentityKind::Target
            | nix_seal_core::IdentityKind::Recovery => {
                nix_seal_crypto::recipient_fingerprint(&identity.public)
                    .with_context(|| format!("recipient identity {id} is malformed"))?;
            }
        }
    }
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
            let public = nix_seal_crypto::recipient_from_identity(&identity)?;
            if !recipients.recipients.values().any(|value| value == &public) {
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
    let result = nix_seal_authoring::write_secret(
        &root,
        Path::new(&secret.source),
        std::io::stdin().lock(),
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
    let result = nix_seal_authoring::edit_secret(&nix_seal_authoring::EditRequest {
        repository_root: &root,
        relative_destination: Path::new(&secret.source),
        identity: &identity,
        recipients: &recipients,
        editor: &arguments.editor,
        editor_arguments: &arguments.editor_arguments,
        workspace_root: &workspace_root,
    })?;
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

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn cache_status(root: Option<PathBuf>, json: bool) -> Result<()> {
    let root = root.unwrap_or_else(default_cache_root);
    let cache = nix_seal_cache::Cache::open(&root)?;
    let objects = std::fs::read_dir(cache.root().join("objects"))
        .map_or(0, |entries| entries.filter_map(Result::ok).count());
    let artifacts = std::fs::read_dir(cache.root().join("artifacts"))
        .map_or(0, |entries| entries.filter_map(Result::ok).count());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.output.v1",
                "root":cache.root(),
                "objects":objects,
                "artifacts":artifacts
            })
        );
    } else {
        println!(
            "{}: {objects} objects, {artifacts} target artifacts",
            cache.root().display()
        );
    }
    Ok(())
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
    use nix_seal_manifest::{ARTIFACT_SCHEMA, TargetManifestV2};
    use std::collections::BTreeMap;

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
                public: signer.encode_public(),
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
                phase: nix_seal_core::ActivationPhase::Activation,
                runtime: runtime.clone(),
                lifecycle: nix_seal_core::Lifecycle::default(),
                approval_policy: None,
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
            allowed_clock_skew: 0,
            artifacts: vec![nix_seal_runtime::ActivationArtifactSpecV2 {
                ciphertext: ciphertext_path,
                envelope: envelope_path,
                secret_id: secret_id.clone(),
                source_ciphertext_hash: source_hash,
                artifact_generation: 1,
                mode: "0400".to_owned(),
                owner: owner.clone(),
                group: group.clone(),
            }],
            templates: vec![nix_seal_runtime::ActivationTemplateSpecV1 {
                source: template_path,
                template_id,
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
                spec: spec_path,
                identity: identity_path,
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
        Ok(())
    }
}

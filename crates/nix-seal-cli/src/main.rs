#![forbid(unsafe_code)]
//! Command-line interface. Plaintext output is limited to `secret reveal`.

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};
use std::{
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
    },
    /// Validate policy and public references.
    Check {
        #[arg(long, default_value = "nix-seal.toml")]
        toml: PathBuf,
        #[arg(long)]
        nix_plan: Option<PathBuf>,
        #[arg(long)]
        deep: bool,
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
    /// Print the plan.v1 `JSON` Schema.
    Schema,
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
    /// Canonical administrator-encrypted age file.
    #[arg(long)]
    source: PathBuf,
    /// Administrator X25519 identity file.
    #[arg(long)]
    identity: PathBuf,
    /// Exact target X25519 recipient.
    #[arg(long)]
    recipient: String,
    /// Canonical plan hash.
    #[arg(long)]
    plan_hash: String,
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
    /// Encrypt stdin to a new standard age file.
    Import {
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt to stdout. This is the only command that emits plaintext.
    Reveal {
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        input: PathBuf,
    },
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

fn main() {
    if let Err(error) = run() {
        eprintln!("nix-seal: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Plan { toml, nix_plan } => {
            let plan = load_plan(&toml, nix_plan.as_deref())?;
            nix_seal_policy::validate(&plan)?;
            let hash = nix_seal_policy::plan_hash(&plan)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"schema":"nix-seal.output.v1","planHash":hash,"plan":plan})
                );
            } else {
                eprintln!("plan hash: {hash}");
                println!(
                    "{}",
                    String::from_utf8(nix_seal_policy::canonical_json(&plan)?)?
                );
            }
        }
        Command::Check {
            toml,
            nix_plan,
            deep,
        } => {
            let plan = load_plan(&toml, nix_plan.as_deref())?;
            nix_seal_policy::validate(&plan)?;
            let hash = nix_seal_policy::plan_hash(&plan)?;
            if cli.json {
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
        }
        Command::Key(command) => run_key(command, cli.json)?,
        Command::Artifact(command) => run_artifact(command, cli.json)?,
        Command::Rekey(arguments) => run_rekey(arguments, cli.json)?,
        Command::Activate(arguments) => run_activate(&arguments, cli.json)?,
        Command::Secret(command) => run_secret(command)?,
        Command::Schema => println!("{}", nix_seal_policy::json_schema()?),
        Command::Completions { shell } => completions(shell),
        Command::Cache(CacheCommand::Status { root }) => cache_status(root, cli.json)?,
    }
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
            let manifest: nix_seal_manifest::TargetManifestV1 = read_json_bounded(&manifest)?;
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
    let identity = read_identity(&arguments.identity)?;
    let signing_key = read_signing_key(&arguments.signing_key)?;
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
        source: &arguments.source,
        administrator_identity: &identity,
        target_recipient: &arguments.recipient,
        plan_hash: &arguments.plan_hash,
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

fn run_activate(arguments: &ActivateArgs, json: bool) -> Result<()> {
    let mut spec: nix_seal_runtime::ActivationSpecV1 = read_json_bounded(&arguments.spec)?;
    if let Some(runtime_root) = &arguments.runtime_root {
        spec.runtime_root.clone_from(runtime_root);
    }
    spec.validate()?;
    let identity = read_identity(&arguments.identity)?;
    let mut trusted = nix_seal_manifest::TrustedKeys::new();
    for key in &spec.trusted_keys {
        trusted.insert_encoded(key)?;
    }
    let artifacts = spec
        .artifacts
        .iter()
        .map(|artifact| {
            Ok(nix_seal_runtime::ActivationArtifact {
                ciphertext: &artifact.ciphertext,
                envelope: &artifact.envelope,
                secret_id: &artifact.secret_id,
                source_ciphertext_hash: &artifact.source_ciphertext_hash,
                artifact_generation: artifact.artifact_generation,
                mode: artifact.parsed_mode()?,
                owner: &artifact.owner,
                group: &artifact.group,
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
        plan_hash: &spec.plan_hash,
        target_id: &spec.target_id,
        recipient_fingerprint: &spec.recipient_fingerprint,
        tool_version: env!("CARGO_PKG_VERSION"),
        now,
        allowed_clock_skew: spec.allowed_clock_skew,
        trusted_keys: &trusted,
        approval_threshold: spec.approval_threshold,
        target_identity: &identity,
        artifacts: &artifacts,
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
                "secretCount":result.secret_count
            })
        );
    } else {
        println!("{}", result.generation_path.display());
        eprintln!(
            "activated {} secret(s) for {} ({})",
            result.secret_count,
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

fn run_secret(command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Import { recipients, output } => {
            let parent = output.parent().context("output has no parent directory")?;
            std::fs::create_dir_all(parent)?;
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .with_context(|| format!("refusing to overwrite {}", output.display()))?;
            set_private_file(&output)?;
            if let Err(error) = nix_seal_crypto::encrypt(std::io::stdin().lock(), file, &recipients)
            {
                let _ = std::fs::remove_file(&output);
                return Err(error.into());
            }
            eprintln!("encrypted stdin to {}", output.display());
        }
        SecretCommand::Reveal { identity, input } => {
            let identity = read_identity(&identity)?;
            let ciphertext = std::fs::File::open(&input)?;
            nix_seal_crypto::decrypt(ciphertext, std::io::stdout().lock(), &identity)?;
        }
    }
    Ok(())
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
    use nix_seal_manifest::{ARTIFACT_SCHEMA, TargetManifestV1};

    #[test]
    fn internal_activate_command_materializes_signed_spec() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let identity_path = temporary.path().join("target.identity");
        let ciphertext_path = temporary.path().join("artifact.age");
        let envelope_path = temporary.path().join("artifact.json");
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
        let plan_hash = "0".repeat(64);
        let source_hash = "1".repeat(64);
        let target_id = nix_seal_core::Id::parse("host.test")?;
        let secret_id = nix_seal_core::Id::parse("db/password")?;
        let fingerprint = nix_seal_crypto::recipient_fingerprint(&recipient)?;
        let signer = nix_seal_manifest::ApprovalSigningKey::generate()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let manifest = TargetManifestV1 {
            schema: ARTIFACT_SCHEMA.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            plan_hash: plan_hash.clone(),
            source_ciphertext_hash: source_hash.clone(),
            artifact_ciphertext_hash: artifact_hash,
            target_id: target_id.clone(),
            secret_id: secret_id.clone(),
            recipient_fingerprint: fingerprint.clone(),
            artifact_generation: 1,
            issued_at: now.saturating_sub(1),
            expires_at: now.checked_add(60),
        };
        write_new_json(
            &envelope_path,
            &nix_seal_manifest::sign_manifest(&manifest, &signer)?,
        )?;
        let mut spec = nix_seal_runtime::ActivationSpecV1 {
            schema: nix_seal_runtime::ACTIVATION_SCHEMA.to_owned(),
            runtime_root: runtime_root.clone(),
            runtime_generation: None,
            plan_hash,
            target_id,
            recipient_fingerprint: fingerprint,
            allowed_clock_skew: 0,
            approval_threshold: 1,
            trusted_keys: vec![signer.encode_public()],
            artifacts: vec![nix_seal_runtime::ActivationArtifactSpecV1 {
                ciphertext: ciphertext_path,
                envelope: envelope_path,
                secret_id,
                source_ciphertext_hash: source_hash,
                artifact_generation: 1,
                mode: "0400".to_owned(),
                owner: uzers::get_user_by_uid(uzers::get_current_uid())
                    .and_then(|user| user.name().to_str().map(str::to_owned))
                    .ok_or("current user is not resolvable")?,
                group: uzers::get_group_by_gid(uzers::get_current_gid())
                    .and_then(|group| group.name().to_str().map(str::to_owned))
                    .ok_or("current group is not resolvable")?,
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
        let actions = nix_seal_runtime::PostSwitchSpecV1 {
            executable: temporary.path().join("missing-service-manager"),
            manager: nix_seal_runtime::ServiceManagerV1::SystemdSystem,
            reload_units: Vec::new(),
            restart_units: vec!["example.service".to_owned()],
            timeout_seconds: 1,
        };
        spec.post_switch = Some(actions);
        std::fs::write(&spec_path, serde_json::to_vec(&spec)?)?;
        run_activate(
            &ActivateArgs {
                spec: spec_path,
                identity: identity_path,
                runtime_root: None,
            },
            false,
        )?;
        assert_eq!(
            std::fs::read(runtime_root.join("current/db/password"))?,
            b"cli-activation-canary"
        );
        Ok(())
    }
}

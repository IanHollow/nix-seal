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
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        bail!("identity exceeds the 1 MiB safety limit");
    }
    Ok(SecretString::from(
        String::from_utf8(bytes).context("identity is not UTF-8")?,
    ))
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

#![forbid(unsafe_code)]
//! Command-line interface. Plaintext output is limited to `secret reveal`.

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
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
    }
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
    let count = std::fs::read_dir(cache.root().join("objects"))
        .map_or(0, |entries| entries.filter_map(Result::ok).count());
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.output.v1","root":cache.root(),"objects":count})
        );
    } else {
        println!("{}: {count} objects", cache.root().display());
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

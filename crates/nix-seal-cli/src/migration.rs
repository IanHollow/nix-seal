//! Dry-run-first migration CLI commands and adapters.
//
// The command module deliberately reaches only into crate-local helpers. The
// next extraction step moves those helpers to narrow shared crates; retaining a
// single transitional import avoids copying security-sensitive path and stream
// validation logic during this behavior-preserving split.
#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Args)]
pub(super) struct AgeTreeMigrationArgs {
    /// Existing directory containing canonical `*.age` ciphertext files.
    #[arg(long, default_value = "secrets")]
    pub(super) directory: PathBuf,
    /// Repository root containing both the legacy and destination trees.
    #[arg(long, default_value = ".")]
    pub(super) repository_root: PathBuf,
    /// Repository-relative destination tree for a side-by-side import.
    #[arg(long)]
    pub(super) destination: Option<PathBuf>,
    /// Private identity authorized to decrypt every legacy ciphertext.
    #[arg(long)]
    pub(super) identity: Option<PathBuf>,
    /// Optional private identity authorized to verify the replacement
    /// ciphertexts. Defaults to `--identity`; use this when migrating to a
    /// new administrator or recovery recipient.
    #[arg(long)]
    pub(super) verification_identity: Option<PathBuf>,
    /// Explicit replacement recipient; repeat for each recipient.
    #[arg(long = "recipient")]
    pub(super) recipients: Vec<String>,
    /// Replace existing destination ciphertexts; omission is create-only.
    #[arg(long)]
    pub(super) replace: bool,
    /// Commit the complete preflighted migration. Without this flag the
    /// command reports the mapping and never reads the private identity.
    #[arg(long)]
    pub(super) execute: bool,
}

#[derive(Args)]
pub(super) struct AgenixRekeyMigrationArgs {
    /// Public agenix-rekey export produced by `nixSeal.lib.agenixRekeyMigrationExport`.
    #[arg(long)]
    pub(super) metadata: PathBuf,
    /// Repository root containing the legacy rekey files and destination tree.
    #[arg(long, default_value = ".")]
    pub(super) repository_root: PathBuf,
    /// Repository-relative destination tree for a side-by-side import.
    #[arg(long)]
    pub(super) destination: Option<PathBuf>,
    /// Private administrator/recovery identity that can decrypt every source file.
    #[arg(long)]
    pub(super) identity: Option<PathBuf>,
    /// Optional private identity authorized to verify replacement ciphertexts.
    /// Defaults to `--identity`.
    #[arg(long)]
    pub(super) verification_identity: Option<PathBuf>,
    /// Explicit replacement recipient; repeat for each recipient.
    #[arg(long = "recipient")]
    pub(super) recipients: Vec<String>,
    /// Replace existing destination ciphertexts; omission is create-only.
    #[arg(long)]
    pub(super) replace: bool,
    /// Commit the complete preflighted migration. Without this flag the command
    /// reports the mapping and never reads the private identity.
    #[arg(long)]
    pub(super) execute: bool,
}

#[derive(Args)]
pub(super) struct ClanVarsMigrationArgs {
    /// Clan's existing `vars/per-machine` directory.
    #[arg(long, default_value = "vars/per-machine")]
    pub(super) directory: PathBuf,
    /// Repository root containing the legacy Vars tree and destination tree.
    #[arg(long, default_value = ".")]
    pub(super) repository_root: PathBuf,
    /// Repository-relative destination tree for a side-by-side import.
    #[arg(long)]
    pub(super) destination: Option<PathBuf>,
    /// Private identity authorized to verify every replacement ciphertext.
    #[arg(long)]
    pub(super) identity: Option<PathBuf>,
    /// Explicit replacement recipient; repeat for each recipient.
    #[arg(long = "recipient")]
    pub(super) recipients: Vec<String>,
    /// Replace existing destination ciphertexts; omission is create-only.
    #[arg(long)]
    pub(super) replace: bool,
    /// Commit the complete preflighted migration. Without this flag the
    /// command reports the mapping and never reads legacy values.
    #[arg(long)]
    pub(super) execute: bool,
}

#[derive(Args)]
pub(super) struct ClanFactsMigrationArgs {
    /// Clan's existing `machines/<machine>/facts` tree.
    #[arg(long, default_value = "machines")]
    pub(super) directory: PathBuf,
    /// Repository root containing the legacy Facts tree and destination tree.
    #[arg(long, default_value = ".")]
    pub(super) repository_root: PathBuf,
    /// Repository-relative destination tree for a side-by-side public import.
    #[arg(long)]
    pub(super) destination: Option<PathBuf>,
    /// Replace existing destination files; omission is create-only.
    #[arg(long)]
    pub(super) replace: bool,
    /// Commit the complete preflighted migration. Without this flag the
    /// command reports the mapping and never reads legacy values.
    #[arg(long)]
    pub(super) execute: bool,
}

#[derive(Subcommand)]
pub(super) enum MigrateCommand {
    /// Inspect or bulk-rekey an agenix ciphertext tree. The legacy tree is
    /// never modified; import writes a side-by-side destination tree.
    Agenix(AgeTreeMigrationArgs),
    /// Inspect or bulk-rekey a ragenix ciphertext tree; its ciphertext layout
    /// is agenix-compatible.
    Ragenix(AgeTreeMigrationArgs),
    /// Inspect or bulk-rekey a strict public agenix-rekey configuration export.
    AgenixRekey(AgenixRekeyMigrationArgs),
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
    /// Inspect or bulk-import Clan Vars per-machine output leaves.
    ClanVars(ClanVarsMigrationArgs),
    /// Inspect or bulk-import Clan Facts public leaves.
    ClanFacts(ClanFactsMigrationArgs),
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
        /// Private identity authorized to decrypt the legacy source.
        #[arg(long)]
        identity: PathBuf,
        /// Optional private identity authorized to verify the replacement
        /// ciphertext. Defaults to `--identity`.
        #[arg(long)]
        verification_identity: Option<PathBuf>,
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
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgenixRekeyExportV1 {
    schema: String,
    target: AgenixRekeyTargetV1,
    master_recipients: Vec<String>,
    secrets: BTreeMap<String, AgenixRekeySecretV1>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgenixRekeyTargetV1 {
    id: String,
    kind: String,
    system: String,
    recipient: String,
    storage_mode: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgenixRekeySecretV1 {
    rekey_file: String,
    #[serde(default)]
    intermediary: bool,
}

pub(super) fn run_migrate(command: MigrateCommand, json: bool) -> Result<()> {
    match command {
        MigrateCommand::Agenix(arguments) => migrate_agenix_tree(&arguments, "agenix", json),
        MigrateCommand::Ragenix(arguments) => migrate_agenix_tree(&arguments, "ragenix", json),
        MigrateCommand::AgenixRekey(arguments) => migrate_agenix_rekey_export(&arguments, json),
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
        MigrateCommand::ClanVars(arguments) => migrate_clan_vars_tree(&arguments, json),
        MigrateCommand::ClanFacts(arguments) => migrate_clan_facts_tree(&arguments, json),
        MigrateCommand::Ciphertext {
            repository_root,
            source,
            destination,
            identity,
            verification_identity,
            recipients,
            replace,
            execute,
        } => migrate_ciphertext(
            &repository_root,
            &source,
            &destination,
            &identity,
            verification_identity.as_deref(),
            &recipients,
            replace,
            execute,
            json,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn migrate_ciphertext(
    repository_root: &Path,
    source: &Path,
    destination: &Path,
    identity_path: &Path,
    verification_identity_path: Option<&Path>,
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
    let source_identity = read_identity(identity_path)?;
    let verification_identity = verification_identity_path.map(read_identity).transpose()?;
    let verification_identity = verification_identity.as_ref().unwrap_or(&source_identity);
    let mode = if replace {
        nix_seal_authoring::WriteMode::Replace
    } else {
        nix_seal_authoring::WriteMode::Create
    };
    let result = nix_seal_authoring::rekey_secret_with_identities(
        repository_root,
        source,
        destination,
        recipients,
        &source_identity,
        verification_identity,
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
pub(super) fn migrate_sops_document(
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
pub(super) fn migrate_pgp_document(
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

pub(super) fn pgp_decrypt_command(gpg: &Path, gnupg_home: &Path, source: &Path) -> ProcessCommand {
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

pub(super) fn resolve_private_gnupg_home(path: &Path) -> Result<PathBuf> {
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

pub(super) fn wait_for_external_migration(
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

pub(super) fn terminate_external_migration(child: &Arc<Mutex<Child>>) {
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
pub(super) fn isolate_child_process_group(command: &mut ProcessCommand) {
    use std::os::unix::process::CommandExt;

    // `process_group(0)` asks the child to become the leader of a new group
    // whose ID is its own PID. This is a safe std API and does not require a
    // pre-exec hook (which would require an unsafe block).
    command.process_group(0);
}

#[cfg(not(unix))]
pub(super) fn isolate_child_process_group(_command: &mut ProcessCommand) {}

pub(super) fn terminate_child_process_tree(child: &mut Child) {
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

pub(super) fn resolve_migration_repository_root(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "could not inspect migration repository root {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!("migration repository root must be a non-symlink directory");
    }
    path.canonicalize()
        .context("could not canonicalize migration repository root")
}

pub(super) fn validate_migration_relative_path(path: &Path, label: &str) -> Result<()> {
    if path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("migration {label} must be a non-empty repository-relative normal path");
    }
    Ok(())
}

pub(super) fn resolve_migration_directory(
    repository_root: &Path,
    relative: &Path,
) -> Result<PathBuf> {
    let root = resolve_migration_repository_root(repository_root)?;
    let directory = if relative.as_os_str().is_empty() || relative == Path::new(".") {
        root.clone()
    } else {
        validate_migration_relative_path(relative, "directory")?;
        let mut current = root.clone();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                bail!("migration directory must be a normal repository-relative path");
            };
            current.push(name);
            let metadata = fs::symlink_metadata(&current).with_context(|| {
                format!(
                    "could not inspect migration directory {}",
                    current.display()
                )
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                bail!("migration directory contains a symlink or non-directory entry");
            }
        }
        current
    };
    let canonical = directory
        .canonicalize()
        .context("could not canonicalize migration directory")?;
    if !canonical.starts_with(&root) {
        bail!("migration directory escaped the repository root");
    }
    Ok(canonical)
}

pub(super) fn normalize_migration_recipients(recipients: &[String]) -> Result<Vec<String>> {
    if recipients.is_empty() || recipients.len() > 256 {
        bail!("bulk migration requires between one and 256 replacement recipients");
    }
    let mut normalized = BTreeSet::new();
    for recipient in recipients {
        let recipient = nix_seal_crypto::normalize_recipient(recipient)
            .context("bulk migration recipient is invalid")?;
        if !normalized.insert(recipient) {
            bail!("bulk migration recipients must be distinct");
        }
    }
    Ok(normalized.into_iter().collect())
}

pub(super) fn resolve_migration_regular_file(
    repository_root: &Path,
    relative: &Path,
) -> Result<PathBuf> {
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

pub(super) fn resolve_external_executable(path: &Path) -> Result<PathBuf> {
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

#[allow(clippy::too_many_lines)]
pub(super) fn migrate_agenix_tree(
    arguments: &AgeTreeMigrationArgs,
    source: &str,
    json: bool,
) -> Result<()> {
    let directory = &arguments.directory;
    let import_requested = arguments.destination.is_some()
        || arguments.identity.is_some()
        || arguments.verification_identity.is_some()
        || !arguments.recipients.is_empty()
        || arguments.replace
        || arguments.execute;
    let repository_root_for_import = if import_requested {
        let repository_root = resolve_migration_repository_root(&arguments.repository_root)?;
        if directory.is_absolute() {
            bail!("bulk {source} migration requires --directory to be repository-relative");
        }
        Some(repository_root)
    } else {
        None
    };
    let root = if let Some(repository_root) = &repository_root_for_import {
        resolve_migration_directory(repository_root, directory)?
    } else {
        let supplied_metadata = fs::symlink_metadata(directory)
            .with_context(|| format!("could not inspect {source} ciphertext directory"))?;
        if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
            bail!("{source} ciphertext root must be a non-symlink directory");
        }
        directory
            .canonicalize()
            .with_context(|| format!("could not resolve {source} ciphertext directory"))?
    };
    let metadata = fs::symlink_metadata(&root)?;
    if !metadata.file_type().is_dir() {
        bail!("{source} ciphertext root is not a directory");
    }
    let mut ciphertexts = Vec::new();
    scan_agenix_ciphertexts(&root, &root, &mut ciphertexts)?;
    if ciphertexts.is_empty() {
        bail!("{source} ciphertext directory contains no .age files");
    }
    let (repository_root, source_relative_root, destination_root, replacement_recipients) =
        if import_requested {
            let repository_root = repository_root_for_import
                .clone()
                .context("bulk migration repository root was not initialized")?;
            let source_relative_root = root
                .strip_prefix(&repository_root)
                .context("legacy ciphertext directory escaped repository root")?
                .to_owned();
            let destination = arguments
                .destination
                .as_deref()
                .context("bulk migration requires --destination")?;
            validate_migration_relative_path(destination, "destination")?;
            let destination_root = destination.to_owned();
            let destination_lexical = repository_root.join(&destination_root);
            if destination_lexical.starts_with(&root) || root.starts_with(&destination_lexical) {
                bail!("bulk migration destination must be side-by-side with the legacy tree");
            }
            let identity = arguments
                .identity
                .as_deref()
                .context("bulk migration requires --identity")?;
            if !identity.is_absolute() {
                bail!("bulk migration identity must be an absolute private path");
            }
            if let Some(verification_identity) = arguments.verification_identity.as_deref()
                && !verification_identity.is_absolute()
            {
                bail!("bulk migration verification identity must be an absolute private path");
            }
            let replacement_recipients = normalize_migration_recipients(&arguments.recipients)?;
            (
                repository_root,
                source_relative_root,
                destination_root,
                replacement_recipients,
            )
        } else {
            (PathBuf::new(), PathBuf::new(), PathBuf::new(), Vec::new())
        };
    let mut entries = Vec::with_capacity(ciphertexts.len());
    let mappings = ciphertexts
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .context("agenix ciphertext escaped its canonical root")?
                .to_owned();
            let stem = relative.with_extension("");
            let legacy_id = stem
                .to_str()
                .context("agenix ciphertext path is not UTF-8")?;
            let nix_seal_id = migrated_id(&format!("{source}/{legacy_id}"))?;
            let mut mapping = serde_json::json!({
                "legacyId":legacy_id,
                "nixSealId":nix_seal_id,
                "source":relative,
            });
            if import_requested {
                let source_relative = source_relative_root.join(&relative);
                let destination = destination_root.join(&relative);
                mapping["destination"] = serde_json::json!(destination);
                entries.push((source_relative, destination));
            }
            Ok(mapping)
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = if import_requested {
        vec![
            if arguments.execute {
                "side-by-side migration committed only after every source was staged and round-trip verified"
            } else {
                "dry run only: no ciphertext, configuration, or source manager was changed"
            },
            "recipient policy is explicit for every migrated ciphertext; the legacy tree remains available for rollback and comparison",
            "only regular .age files were accepted; symlinks and non-regular entries are rejected",
        ]
    } else {
        vec![
            "dry run only: no ciphertext, configuration, or source manager was changed",
            "ciphertext headers were validated but recipient policy is not encoded in agenix ciphertext paths; provide an explicit nix-seal recipient and target mapping before import",
            "only regular .age files were accepted; symlinks and non-regular entries are rejected",
        ]
    };
    let mut mappings = mappings;
    if import_requested && arguments.execute {
        let identity_path = arguments
            .identity
            .as_deref()
            .context("bulk migration identity was not provided")?;
        let source_identity = read_identity(identity_path)?;
        let verification_identity = arguments
            .verification_identity
            .as_deref()
            .map(read_identity)
            .transpose()?;
        let verification_identity = verification_identity.as_ref().unwrap_or(&source_identity);
        let writes = entries
            .iter()
            .map(
                |(relative_source, destination)| nix_seal_authoring::BatchRekeyWrite {
                    relative_source,
                    relative_destination: destination,
                    recipients: &replacement_recipients,
                },
            )
            .collect::<Vec<_>>();
        let results = nix_seal_authoring::rekey_secret_batch_with_identities(
            &repository_root,
            &writes,
            &source_identity,
            verification_identity,
            if arguments.replace {
                nix_seal_authoring::WriteMode::Replace
            } else {
                nix_seal_authoring::WriteMode::Create
            },
        )?;
        for (mapping, result) in mappings.iter_mut().zip(results) {
            mapping["ciphertextHash"] = serde_json::json!(result.ciphertext_hash);
            mapping["plaintextBytes"] = serde_json::json!(result.plaintext_bytes);
        }
    }
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":source,
                "dryRun":!import_requested || !arguments.execute,
                "recipientPolicy":if import_requested { serde_json::json!({"recipients":&replacement_recipients}) } else { serde_json::Value::Null },
                "secrets":mappings,
                "warnings":warnings
            })
        );
    } else {
        println!(
            "{source} {}: {} ciphertexts mapped",
            if import_requested && arguments.execute {
                "migration"
            } else {
                "dry-run"
            },
            mappings.len()
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        if import_requested {
            eprintln!(
                "replacement recipient policy: {} recipient(s)",
                replacement_recipients.len()
            );
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

#[allow(clippy::too_many_lines)]
pub(super) fn migrate_agenix_rekey_export(
    arguments: &AgenixRekeyMigrationArgs,
    json: bool,
) -> Result<()> {
    let input = open_public_ciphertext(&arguments.metadata)
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
    let import_requested = arguments.destination.is_some()
        || arguments.identity.is_some()
        || arguments.verification_identity.is_some()
        || !arguments.recipients.is_empty()
        || arguments.replace
        || arguments.execute;
    let mut mappings = Vec::with_capacity(export.secrets.len());
    let mut entries = Vec::with_capacity(export.secrets.len());
    let mut replacement_recipients = Vec::new();
    if import_requested {
        let repository_root = resolve_migration_repository_root(&arguments.repository_root)?;
        let destination = arguments
            .destination
            .as_deref()
            .context("bulk agenix-rekey migration requires --destination")?;
        validate_migration_relative_path(destination, "destination")?;
        if destination == Path::new(".") {
            bail!("bulk agenix-rekey destination must be a separate repository tree");
        }
        replacement_recipients = normalize_migration_recipients(&arguments.recipients)?;
        let identity_path = arguments
            .identity
            .as_deref()
            .context("bulk agenix-rekey migration requires --identity")?;
        if !identity_path.is_absolute() {
            bail!("bulk agenix-rekey migration identity must be an absolute private path");
        }
        if let Some(verification_identity) = arguments.verification_identity.as_deref()
            && !verification_identity.is_absolute()
        {
            bail!(
                "bulk agenix-rekey migration verification identity must be an absolute private path"
            );
        }
        let destination_root = repository_root.join(destination);
        for (legacy_id, secret) in &export.secrets {
            let relative_source = PathBuf::from(validate_agenix_rekey_source(&secret.rekey_file)?);
            let source = resolve_migration_regular_file(&repository_root, &relative_source)?;
            if destination_root.starts_with(&source) || source.starts_with(&destination_root) {
                bail!("bulk agenix-rekey destination must not overlap a legacy source");
            }
            let relative_destination = destination.join(&relative_source);
            let nix_id = migrated_id(legacy_id)?;
            mappings.push(serde_json::json!({
                "legacyId":legacy_id,
                "nixSealId":nix_id,
                "source":relative_source,
                "destination":relative_destination,
                "consumers":if secret.intermediary { Vec::<String>::new() } else { vec![target_id.to_string()] },
                "repositoryOnly":secret.intermediary,
            }));
            entries.push((relative_source, relative_destination));
        }
        if arguments.execute {
            let source_identity = read_identity(identity_path)?;
            let verification_identity = arguments
                .verification_identity
                .as_deref()
                .map(read_identity)
                .transpose()?;
            let verification_identity = verification_identity.as_ref().unwrap_or(&source_identity);
            let writes = entries
                .iter()
                .map(|(relative_source, relative_destination)| {
                    nix_seal_authoring::BatchRekeyWrite {
                        relative_source,
                        relative_destination,
                        recipients: &replacement_recipients,
                    }
                })
                .collect::<Vec<_>>();
            let results = nix_seal_authoring::rekey_secret_batch_with_identities(
                &repository_root,
                &writes,
                &source_identity,
                verification_identity,
                if arguments.replace {
                    nix_seal_authoring::WriteMode::Replace
                } else {
                    nix_seal_authoring::WriteMode::Create
                },
            )?;
            for (mapping, result) in mappings.iter_mut().zip(results) {
                mapping["ciphertextHash"] = serde_json::json!(result.ciphertext_hash);
                mapping["plaintextBytes"] = serde_json::json!(result.plaintext_bytes);
            }
        }
    } else {
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
    }
    let warnings = if import_requested {
        vec![
            if arguments.execute {
                "side-by-side migration committed only after every source was staged and round-trip verified"
            } else {
                "dry run only: no ciphertext, configuration, or source manager was changed"
            },
            "the export establishes rekeyed administrator-to-target semantics; runtime ownership, lifecycle, templates, and approval policy still require reviewed nix-seal mappings",
            "intermediary secrets remain repository-only in the mapping and require an explicit policy decision before delivery",
        ]
    } else {
        vec![
            "dry run only: no ciphertext, configuration, cache, or source manager was changed",
            "the export establishes rekeyed administrator-to-target semantics, but runtime ownership, lifecycle, templates, and approval policy require reviewed nix-seal mappings",
            "intermediary secrets are repository-only and must not be given target consumers without an explicit policy decision",
        ]
    };
    let report = serde_json::json!({
        "schema":"nix-seal.migration-report.v1",
        "source":"agenix-rekey",
        "dryRun":!import_requested || !arguments.execute,
        "target":{
            "legacyId":export.target.id,
            "nixSealId":target_id,
            "kind":export.target.kind,
            "system":export.target.system,
            "recipient":target_recipient,
            "storageMode":export.target.storage_mode,
        },
        "masterRecipientCount":masters.len(),
        "recipientPolicy":if import_requested { serde_json::json!({"recipients":&replacement_recipients}) } else { serde_json::Value::Null },
        "secrets":mappings,
        "warnings":warnings,
    });
    if json {
        println!("{report}");
    } else {
        println!(
            "agenix-rekey {}: {} secrets mapped",
            if import_requested && arguments.execute {
                "migration"
            } else {
                "dry-run"
            },
            report["secrets"].as_array().map_or(0, Vec::len)
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        if import_requested {
            eprintln!(
                "replacement recipient policy: {} recipient(s)",
                replacement_recipients.len()
            );
        }
        for mapping in report["secrets"].as_array().into_iter().flatten() {
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

pub(super) fn validate_agenix_rekey_source(value: &str) -> Result<&str> {
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

pub(super) fn scan_agenix_ciphertexts(
    root: &Path,
    directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<()> {
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

pub(super) struct SopsJsonInventory {
    path: PathBuf,
    pub(super) providers: BTreeSet<String>,
    pub(super) age_recipient_count: usize,
}

/// Produces a public-only SOPS JSON inventory. This does not implement SOPS
/// decryption or authenticate encrypted values; it validates only the bounded,
/// cleartext SOPS metadata required to plan a later explicit migration.
pub(super) fn migrate_sops_json_tree(directory: &Path, json: bool) -> Result<()> {
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

pub(super) fn scan_sops_json_files(
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

pub(super) fn inspect_sops_json(path: &Path) -> Result<SopsJsonInventory> {
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

pub(super) struct ClanVarInventory {
    path: PathBuf,
    pub(super) machine: String,
    pub(super) generator: String,
    pub(super) output: String,
    pub(super) bytes: u64,
}

/// Inventories Clan Vars' documented `machine/generator/file/value` leaves
/// without opening a value for reading. An explicit import streams each value
/// directly into a side-by-side native age ciphertext tree; the source manager
/// remains untouched for rollback and comparison.
#[allow(clippy::too_many_lines)]
pub(super) fn migrate_clan_vars_tree(arguments: &ClanVarsMigrationArgs, json: bool) -> Result<()> {
    let import_requested = arguments.destination.is_some()
        || arguments.identity.is_some()
        || !arguments.recipients.is_empty()
        || arguments.replace
        || arguments.execute;
    let repository_root = if import_requested {
        Some(resolve_migration_repository_root(
            &arguments.repository_root,
        )?)
    } else {
        None
    };
    if import_requested && arguments.directory.is_absolute() {
        bail!("bulk Clan Vars migration requires --directory to be repository-relative");
    }
    let root = if let Some(repository_root) = &repository_root {
        resolve_migration_directory(repository_root, &arguments.directory)?
    } else {
        let supplied_metadata = fs::symlink_metadata(&arguments.directory)
            .context("could not inspect Clan Vars per-machine directory")?;
        if supplied_metadata.file_type().is_symlink() || !supplied_metadata.file_type().is_dir() {
            bail!("Clan Vars root must be a non-symlink directory");
        }
        arguments
            .directory
            .canonicalize()
            .context("could not resolve Clan Vars per-machine directory")?
    };
    let mut values = Vec::new();
    let mut auxiliary_files = 0_u64;
    scan_clan_vars_files(&root, &root, &mut values, &mut auxiliary_files)?;
    if values.is_empty() {
        bail!("Clan Vars per-machine directory contains no output value files");
    }
    let (destination, replacement_recipients, identity_path) = if import_requested {
        let repository_root = repository_root
            .as_ref()
            .context("bulk Clan Vars migration repository root was not initialized")?;
        let destination = arguments
            .destination
            .as_deref()
            .context("bulk Clan Vars migration requires --destination")?;
        validate_migration_relative_path(destination, "destination")?;
        let destination_root = repository_root.join(destination);
        if destination_root.starts_with(&root) || root.starts_with(&destination_root) {
            bail!("bulk Clan Vars destination must be side-by-side with the legacy tree");
        }
        let recipients = normalize_migration_recipients(&arguments.recipients)?;
        let identity = arguments
            .identity
            .as_deref()
            .context("bulk Clan Vars migration requires --identity")?;
        if !identity.is_absolute() {
            bail!("bulk Clan Vars migration identity must be an absolute private path");
        }
        (
            Some(destination.to_owned()),
            recipients,
            Some(identity.to_owned()),
        )
    } else {
        (None, Vec::new(), None)
    };
    let mut seen_ids = BTreeSet::new();
    let mut entries = Vec::with_capacity(values.len());
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
            let relative_destination = destination.as_ref().and_then(|destination| {
                relative
                    .parent()
                    .map(|parent| destination.join(parent).with_extension("age"))
            });
            if let Some(repository_root) = &repository_root {
                let relative_source = entry
                    .path
                    .strip_prefix(repository_root)
                    .context("Clan Vars value escaped the migration repository root")?
                    .to_owned();
                entries.push((
                    relative_source,
                    relative_destination
                        .clone()
                        .context("Clan Vars destination was not initialized")?,
                ));
            }
            Ok(serde_json::json!({
                "legacyId":format!("{}/{}/{}", entry.machine, entry.generator, entry.output),
                "nixSealId":id,
                "source":relative,
                "valueBytes":entry.bytes,
                "destination":relative_destination,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut mappings = mappings;
    if import_requested && arguments.execute {
        let repository_root = repository_root
            .as_ref()
            .context("bulk Clan Vars migration repository root was not initialized")?;
        let identity = read_identity(
            identity_path
                .as_deref()
                .context("bulk Clan Vars migration identity was not initialized")?,
        )?;
        let writes = entries
            .iter()
            .map(|(relative_source, relative_destination)| {
                nix_seal_authoring::BatchPlaintextFileWrite {
                    relative_source,
                    relative_destination,
                    recipients: &replacement_recipients,
                }
            })
            .collect::<Vec<_>>();
        let results = nix_seal_authoring::write_secret_file_batch(
            repository_root,
            &writes,
            &identity,
            if arguments.replace {
                nix_seal_authoring::WriteMode::Replace
            } else {
                nix_seal_authoring::WriteMode::Create
            },
        )?;
        for (mapping, result) in mappings.iter_mut().zip(results) {
            mapping["ciphertextHash"] = serde_json::json!(result.ciphertext_hash);
            mapping["plaintextBytes"] = serde_json::json!(result.plaintext_bytes);
        }
    }
    let warnings = if import_requested {
        vec![
            if arguments.execute {
                "side-by-side migration committed only after every value was streamed and round-trip verified"
            } else {
                "dry run only: no value, configuration, or source manager was changed"
            },
            "Clan Vars storage backend and secret/public classification are not recoverable from an output leaf; review target, runtime, lifecycle, and public-output mappings before activation",
            "legacy values remain untouched for side-by-side rollback and comparison",
            "auxiliary regular files were ignored after link/type validation; only machine/generator/output/value leaves are migration candidates",
        ]
    } else {
        vec![
            "dry run only: no value, configuration, or source manager was changed",
            "Clan Vars storage backend and secret/public classification are not recoverable from an output leaf; provide explicit target, recipient, runtime, and public-output mappings before import",
            "output values were never read, decrypted, emitted, or passed to an external process",
            "auxiliary regular files were ignored after link/type validation; only machine/generator/output/value leaves are migration candidates",
        ]
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "schema":"nix-seal.migration-report.v1",
                "source":"clan-vars",
                "dryRun":!import_requested || !arguments.execute,
                "recipientPolicy":if import_requested { serde_json::json!({"recipients":&replacement_recipients}) } else { serde_json::Value::Null },
                "values":mappings,
                "auxiliaryFileCount":auxiliary_files,
                "warnings":warnings
            })
        );
    } else {
        println!(
            "clan-vars {}: {} value leaves mapped",
            if import_requested && arguments.execute {
                "migration"
            } else {
                "dry-run"
            },
            mappings.len()
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        if import_requested {
            eprintln!(
                "replacement recipient policy: {} recipient(s)",
                replacement_recipients.len()
            );
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

pub(super) fn scan_clan_vars_files(
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

pub(super) fn inspect_clan_var_value(path: &Path, relative: &Path) -> Result<ClanVarInventory> {
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
/// An explicit destination enables a side-by-side public import; the legacy
/// tree remains untouched for rollback and comparison.
#[allow(clippy::too_many_lines)]
pub(super) fn migrate_clan_facts_tree(
    arguments: &ClanFactsMigrationArgs,
    json: bool,
) -> Result<()> {
    let import_requested =
        arguments.destination.is_some() || arguments.replace || arguments.execute;
    let repository_root = if import_requested {
        if arguments.directory.is_absolute() {
            bail!("bulk Clan Facts migration requires --directory to be repository-relative");
        }
        Some(resolve_migration_repository_root(
            &arguments.repository_root,
        )?)
    } else {
        None
    };
    let root = if let Some(repository_root) = &repository_root {
        resolve_migration_directory(repository_root, &arguments.directory)?
    } else {
        let metadata = fs::symlink_metadata(&arguments.directory)
            .context("could not inspect Clan Facts root")?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            bail!("Clan Facts root must be a non-symlink directory");
        }
        arguments
            .directory
            .canonicalize()
            .context("could not resolve Clan Facts root")?
    };
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
    let (destination, entries) = if import_requested {
        let repository_root = repository_root
            .as_ref()
            .context("bulk Clan Facts migration repository root was not initialized")?;
        let destination = arguments
            .destination
            .as_deref()
            .context("bulk Clan Facts migration requires --destination")?;
        validate_migration_relative_path(destination, "destination")?;
        let destination_root = repository_root.join(destination);
        if destination_root.starts_with(&root) || root.starts_with(&destination_root) {
            bail!("bulk Clan Facts destination must be side-by-side with the legacy tree");
        }
        let mut entries = Vec::with_capacity(facts.len());
        for (_, _, _, path) in &facts {
            let relative_source = path
                .strip_prefix(repository_root)
                .context("Clan Facts value escaped the migration repository root")?
                .to_owned();
            let relative = path
                .strip_prefix(&root)
                .context("Clan Facts value escaped its canonical root")?;
            entries.push((relative_source, destination.join(relative)));
        }
        (Some(destination.to_owned()), entries)
    } else {
        (None, Vec::new())
    };
    let mut seen = BTreeSet::new();
    let mut mappings = facts
        .iter()
        .enumerate()
        .map(|(index, (machine, name, bytes, path))| {
            let id = migrated_id(&format!("clan-facts/{machine}/{name}"))?;
            if !seen.insert(id.clone()) {
                bail!("Clan Facts paths collide after nix-seal ID normalization");
            }
            let relative = path
                .strip_prefix(&root)
                .context("Clan Facts value escaped its canonical root")?;
            Ok(serde_json::json!({
                "legacyId":format!("{machine}/{name}"),
                "nixSealId":id,
                "source":relative,
                "valueBytes":bytes,
                "destination":destination.as_ref().map(|_| entries[index].1.clone()),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    if import_requested && arguments.execute {
        let repository_root = repository_root
            .as_ref()
            .context("bulk Clan Facts migration repository root was not initialized")?;
        let writes = entries
            .iter()
            .map(|(relative_source, relative_destination)| {
                nix_seal_authoring::BatchPublicFileWrite {
                    relative_source,
                    relative_destination,
                }
            })
            .collect::<Vec<_>>();
        let results = nix_seal_authoring::write_public_file_batch(
            repository_root,
            &writes,
            if arguments.replace {
                nix_seal_authoring::WriteMode::Replace
            } else {
                nix_seal_authoring::WriteMode::Create
            },
        )?;
        for (mapping, result) in mappings.iter_mut().zip(results) {
            mapping["contentHash"] = serde_json::json!(result.content_hash);
            mapping["plaintextBytes"] = serde_json::json!(result.plaintext_bytes);
        }
    }
    let warnings = if import_requested {
        vec![
            if arguments.execute {
                "side-by-side public migration committed only after every fact was streamed and verified"
            } else {
                "dry run only: no value, configuration, or source manager was changed"
            },
            "Clan Facts leaves are public outputs; secret facts use configurable stores and require an explicit reviewed export",
            "legacy facts remain untouched for side-by-side rollback and comparison",
        ]
    } else {
        vec![
            "dry run only: no value, configuration, or source manager was changed",
            "only documented public facts were inventoried without reading them; secret facts use configurable stores and require an explicit reviewed export",
        ]
    };
    if json {
        println!(
            "{}",
            serde_json::json!({"schema":"nix-seal.migration-report.v1","source":"clan-facts","dryRun":!import_requested || !arguments.execute,"facts":mappings,"warnings":warnings})
        );
    } else {
        println!(
            "clan-facts {}: {} public facts mapped",
            if import_requested && arguments.execute {
                "migration"
            } else {
                "dry-run"
            },
            mappings.len()
        );
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

pub(super) fn migrated_id(value: &str) -> Result<nix_seal_core::Id> {
    let mut normalized = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' => normalized.push(char::from(byte.to_ascii_lowercase())),
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'/' | b'-' | b'_' => {
                normalized.push(char::from(byte));
            }
            b':' | b'@' => normalized.push('-'),
            _ => bail!("legacy ID cannot be represented safely in nix-seal"),
        }
    }
    nix_seal_core::Id::parse(normalized).context("legacy ID normalization is invalid")
}

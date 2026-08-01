#![forbid(unsafe_code)]
//! Transactional, plan-directed canonical ciphertext authoring.

use secrecy::SecretString;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;

/// Whether an authoring transaction creates or atomically replaces ciphertext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteMode {
    /// Refuse an existing destination.
    Create,
    /// Require and atomically replace an existing regular destination.
    Replace,
}

/// Public result metadata; it never contains plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoringResult {
    /// Final canonical ciphertext path.
    pub path: PathBuf,
    /// BLAKE3 hash of the committed ciphertext.
    pub ciphertext_hash: String,
    /// Number of encrypted plaintext bytes.
    pub plaintext_bytes: u64,
}

/// One secret output staged as part of an all-or-recover batch authoring operation.
pub struct BatchSecretWrite<'a> {
    /// Repository-relative canonical ciphertext destination.
    pub relative_destination: &'a Path,
    /// Plaintext bytes retained by the caller only for the duration of the transaction.
    pub plaintext: &'a [u8],
    /// Plan-derived canonical recipients.
    pub recipients: &'a [String],
}

struct PreparedBatchWrite {
    destination: PathBuf,
    parent: PathBuf,
    previous: Option<std::fs::Metadata>,
    staged: Option<NamedTempFile>,
    result: AuthoringResult,
}

/// Inputs for a recoverable canonical-ciphertext deletion.
pub struct DeleteRequest<'a> {
    /// Existing repository root.
    pub repository_root: &'a Path,
    /// Repository-relative canonical ciphertext source from the plan.
    pub relative_source: &'a Path,
    /// Repository-relative private quarantine directory.
    pub quarantine_root: &'a Path,
    /// Public plan secret ID recorded in the tombstone.
    pub secret_id: &'a str,
    /// RFC 3339 deletion time recorded in the tombstone.
    pub deleted_at: &'a str,
}

/// Public metadata for a recoverable deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionResult {
    /// Directory containing `ciphertext.age` and `tombstone.json`.
    pub tombstone_path: PathBuf,
    /// Original canonical ciphertext path.
    pub original_path: PathBuf,
    /// BLAKE3 hash of the quarantined ciphertext.
    pub ciphertext_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TombstoneV1<'a> {
    schema: &'static str,
    secret_id: &'a str,
    original_source: &'a str,
    ciphertext_hash: &'a str,
    deleted_at: &'a str,
}

/// Redacted canonical authoring failure.
#[derive(Debug, Error)]
pub enum AuthoringError {
    /// Repository root or relative source path is unsafe.
    #[error("canonical secret destination is outside the repository or has unsafe ancestry")]
    UnsafePath,
    /// Create found an existing destination or replace found no safe destination.
    #[error("canonical secret destination has incompatible existing state")]
    DestinationState,
    /// The verification identity is not among the selected recipients.
    #[error("verification identity is not authorized by the selected recipient policy")]
    VerificationIdentity,
    /// Encrypting or round-trip decrypting failed.
    #[error(transparent)]
    Crypto(#[from] nix_seal_crypto::CryptoError),
    /// Round-trip plaintext differed from the input stream.
    #[error("new ciphertext failed round-trip plaintext verification")]
    RoundTrip,
    /// An external plaintext producer failed its final status check.
    #[error("external plaintext producer did not complete successfully")]
    ExternalInput,
    /// Filesystem transaction failed.
    #[error("canonical ciphertext transaction failed")]
    Io(#[source] std::io::Error),
    /// Editor path, exit status, or edited plaintext file was unsafe.
    #[error("explicit editor transaction failed or produced unsafe output")]
    Editor,
    /// The caller rejected edited plaintext before any ciphertext replacement.
    #[error("edited plaintext failed the declared format validation")]
    InvalidEditedContent,
    /// The atomic change completed but directory durability could not be confirmed.
    #[error("ciphertext changed atomically but filesystem durability could not be confirmed")]
    DurabilityUnknown,
    /// A multi-output transaction could not commit, but every earlier change was restored.
    #[error("multi-output ciphertext transaction failed and was rolled back")]
    BatchRolledBack,
    /// A multi-output transaction failed and rollback could not be confirmed.
    #[error("multi-output ciphertext transaction failed and rollback could not be confirmed")]
    BatchRecoveryUnknown,
    /// Tombstone metadata could not be encoded.
    #[error("recoverable deletion tombstone could not be encoded")]
    Tombstone(#[source] serde_json::Error),
}

/// Explicit editor invocation. No shell or inherited environment is used.
pub struct EditRequest<'a> {
    /// Existing repository root.
    pub repository_root: &'a Path,
    /// Repository-relative canonical ciphertext source.
    pub relative_destination: &'a Path,
    /// Authorized identity used to decrypt and verify the replacement.
    pub identity: &'a SecretString,
    /// Plan-derived canonical recipients.
    pub recipients: &'a [String],
    /// Absolute editor executable path.
    pub editor: &'a Path,
    /// Explicit arguments placed before the private temporary file path.
    pub editor_arguments: &'a [String],
    /// Existing directory in which a private ephemeral workspace is created.
    pub workspace_root: &'a Path,
}

/// Encrypts a bounded input, verifies it by round-trip decryption, and commits atomically.
pub fn write_secret<R: Read>(
    repository_root: &Path,
    relative_destination: &Path,
    input: R,
    recipients: &[String],
    verification_identity: &SecretString,
    mode: WriteMode,
) -> Result<AuthoringResult, AuthoringError> {
    write_secret_checked(
        repository_root,
        relative_destination,
        input,
        recipients,
        verification_identity,
        mode,
        || Ok(()),
    )
}

/// Encrypts a bounded input and runs a caller-supplied final input check before
/// committing ciphertext. This lets migration callers stream an external
/// decryptor directly into age encryption while still failing closed when that
/// process reports an error after closing standard output.
pub fn write_secret_checked<R: Read, F: FnOnce() -> Result<(), AuthoringError>>(
    repository_root: &Path,
    relative_destination: &Path,
    input: R,
    recipients: &[String],
    verification_identity: &SecretString,
    mode: WriteMode,
    final_input_check: F,
) -> Result<AuthoringResult, AuthoringError> {
    let verification_recipient = nix_seal_crypto::recipient_from_identity(verification_identity)?;
    let normalized_recipients = recipients
        .iter()
        .map(|recipient| nix_seal_crypto::normalize_recipient(recipient))
        .collect::<Result<Vec<_>, _>>()?;
    if !normalized_recipients.contains(&verification_recipient) {
        return Err(AuthoringError::VerificationIdentity);
    }
    let destination = resolve_destination(repository_root, relative_destination)?;
    let previous = validate_destination(&destination, mode)?;
    let parent = destination.parent().ok_or(AuthoringError::UnsafePath)?;
    let mut staged = NamedTempFile::new_in(parent).map_err(AuthoringError::Io)?;
    set_private(staged.path()).map_err(AuthoringError::Io)?;

    let mut hashing_input = HashingReader::new(input);
    nix_seal_crypto::encrypt(&mut hashing_input, staged.as_file_mut(), recipients)?;
    staged.as_file().sync_all().map_err(AuthoringError::Io)?;
    let (plaintext_hash, plaintext_bytes) = hashing_input.finish();

    staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
    let mut verified = HashingWriter::default();
    nix_seal_crypto::decrypt(staged.as_file_mut(), &mut verified, verification_identity)?;
    if verified.hash() != plaintext_hash || verified.bytes != plaintext_bytes {
        return Err(AuthoringError::RoundTrip);
    }
    staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
    let ciphertext_hash = hash_file(staged.as_file_mut())?;

    // Do not make ciphertext visible until an input-producing subprocess (if
    // any) has reported a successful final status.
    final_input_check()?;

    match mode {
        WriteMode::Create => {
            staged
                .persist_noclobber(&destination)
                .map_err(|error| AuthoringError::Io(error.error))?;
        }
        WriteMode::Replace => {
            ensure_unchanged(&destination, previous.as_ref())?;
            staged
                .persist(&destination)
                .map_err(|error| AuthoringError::Io(error.error))?;
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthoringError::DurabilityUnknown)?;
    Ok(AuthoringResult {
        path: destination,
        ciphertext_hash,
        plaintext_bytes,
    })
}

/// Streams existing canonical age ciphertext into fresh recipients and commits the
/// verified replacement atomically. Plaintext is never materialized on disk.
pub fn rekey_secret(
    repository_root: &Path,
    relative_source: &Path,
    relative_destination: &Path,
    recipients: &[String],
    verification_identity: &SecretString,
    mode: WriteMode,
) -> Result<AuthoringResult, AuthoringError> {
    let verification_recipient = nix_seal_crypto::recipient_from_identity(verification_identity)?;
    let normalized_recipients = recipients
        .iter()
        .map(|recipient| nix_seal_crypto::normalize_recipient(recipient))
        .collect::<Result<Vec<_>, _>>()?;
    if !normalized_recipients.contains(&verification_recipient) {
        return Err(AuthoringError::VerificationIdentity);
    }
    let source = resolve_existing(repository_root, relative_source)?;
    let source_file = open_nofollow_regular(&source)?;
    let destination = resolve_destination(repository_root, relative_destination)?;
    let previous = validate_destination(&destination, mode)?;
    let parent = destination.parent().ok_or(AuthoringError::UnsafePath)?;
    let mut staged = NamedTempFile::new_in(parent).map_err(AuthoringError::Io)?;
    set_private(staged.path()).map_err(AuthoringError::Io)?;
    nix_seal_crypto::rekey(
        source_file,
        staged.as_file_mut(),
        verification_identity,
        recipients,
    )?;
    staged.as_file().sync_all().map_err(AuthoringError::Io)?;
    staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
    let mut verified = HashingWriter::default();
    nix_seal_crypto::decrypt(staged.as_file_mut(), &mut verified, verification_identity)?;
    staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
    let ciphertext_hash = hash_file(staged.as_file_mut())?;

    match mode {
        WriteMode::Create => {
            staged
                .persist_noclobber(&destination)
                .map_err(|error| AuthoringError::Io(error.error))?;
        }
        WriteMode::Replace => {
            ensure_unchanged(&destination, previous.as_ref())?;
            staged
                .persist(&destination)
                .map_err(|error| AuthoringError::Io(error.error))?;
        }
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthoringError::DurabilityUnknown)?;
    Ok(AuthoringResult {
        path: destination,
        ciphertext_hash,
        plaintext_bytes: verified.bytes,
    })
}

/// Stages, verifies, and durably commits a group of ciphertext outputs.
///
/// Every output is encrypted and round-trip verified before an existing
/// ciphertext is moved. Replacements are temporarily backed up in their own
/// directory and restored if any later commit fails. This is intentionally a
/// repository-ciphertext transaction: plaintext never reaches the backup or
/// journal paths.
pub fn write_secret_batch(
    repository_root: &Path,
    writes: &[BatchSecretWrite<'_>],
    verification_identity: &SecretString,
    mode: WriteMode,
) -> Result<Vec<AuthoringResult>, AuthoringError> {
    let mut prepared = prepare_batch_writes(repository_root, writes, verification_identity, mode)?;

    for item in &prepared {
        match mode {
            WriteMode::Create if item.destination.exists() => {
                return Err(AuthoringError::DestinationState);
            }
            WriteMode::Replace => ensure_unchanged(&item.destination, item.previous.as_ref())?,
            WriteMode::Create => {}
        }
    }
    let mut backups = Vec::with_capacity(prepared.len());
    for item in &prepared {
        if mode == WriteMode::Create {
            backups.push(None);
            continue;
        }
        let backup = NamedTempFile::new_in(&item.parent).map_err(AuthoringError::Io)?;
        set_private(backup.path()).map_err(AuthoringError::Io)?;
        let backup = backup.into_temp_path();
        if std::fs::rename(&item.destination, &backup).is_err() {
            if restore_batch(&prepared, &mut backups, &[]) {
                return Err(AuthoringError::BatchRolledBack);
            }
            return Err(AuthoringError::BatchRecoveryUnknown);
        }
        backups.push(Some(backup));
    }
    let results = commit_prepared_batch(&mut prepared, mode, &mut backups)?;
    drop(backups);
    for item in &prepared {
        File::open(&item.parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AuthoringError::DurabilityUnknown)?;
    }
    Ok(results)
}

fn prepare_batch_writes(
    repository_root: &Path,
    writes: &[BatchSecretWrite<'_>],
    verification_identity: &SecretString,
    mode: WriteMode,
) -> Result<Vec<PreparedBatchWrite>, AuthoringError> {
    if writes.is_empty() || writes.len() > 10_000 {
        return Err(AuthoringError::UnsafePath);
    }
    let verification_recipient = nix_seal_crypto::recipient_from_identity(verification_identity)?;
    let mut destinations = BTreeSet::new();
    let mut prepared = Vec::with_capacity(writes.len());
    for write in writes {
        let normalized_recipients = write
            .recipients
            .iter()
            .map(|recipient| nix_seal_crypto::normalize_recipient(recipient))
            .collect::<Result<Vec<_>, _>>()?;
        if !normalized_recipients.contains(&verification_recipient) {
            return Err(AuthoringError::VerificationIdentity);
        }
        let destination = resolve_destination(repository_root, write.relative_destination)?;
        if !destinations.insert(destination.clone()) {
            return Err(AuthoringError::DestinationState);
        }
        let previous = validate_destination(&destination, mode)?;
        let parent = destination
            .parent()
            .ok_or(AuthoringError::UnsafePath)?
            .to_owned();
        let mut staged = NamedTempFile::new_in(&parent).map_err(AuthoringError::Io)?;
        set_private(staged.path()).map_err(AuthoringError::Io)?;
        let mut input = HashingReader::new(std::io::Cursor::new(write.plaintext));
        nix_seal_crypto::encrypt(&mut input, staged.as_file_mut(), write.recipients)?;
        staged.as_file().sync_all().map_err(AuthoringError::Io)?;
        let (plaintext_hash, plaintext_bytes) = input.finish();
        staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
        let mut verified = HashingWriter::default();
        nix_seal_crypto::decrypt(staged.as_file_mut(), &mut verified, verification_identity)?;
        if verified.hash() != plaintext_hash || verified.bytes != plaintext_bytes {
            return Err(AuthoringError::RoundTrip);
        }
        staged.as_file_mut().rewind().map_err(AuthoringError::Io)?;
        let ciphertext_hash = hash_file(staged.as_file_mut())?;
        prepared.push(PreparedBatchWrite {
            destination: destination.clone(),
            parent,
            previous,
            staged: Some(staged),
            result: AuthoringResult {
                path: destination,
                ciphertext_hash,
                plaintext_bytes,
            },
        });
    }
    Ok(prepared)
}

fn commit_prepared_batch(
    prepared: &mut [PreparedBatchWrite],
    mode: WriteMode,
    backups: &mut [Option<TempPath>],
) -> Result<Vec<AuthoringResult>, AuthoringError> {
    let mut committed = Vec::with_capacity(prepared.len());
    for index in 0..prepared.len() {
        let staged = prepared[index]
            .staged
            .take()
            .ok_or(AuthoringError::BatchRecoveryUnknown)?;
        let persisted = match mode {
            WriteMode::Create => staged.persist_noclobber(&prepared[index].destination),
            WriteMode::Replace => staged.persist(&prepared[index].destination),
        };
        if persisted.is_err() {
            if restore_batch(prepared, &mut *backups, &committed) {
                return Err(AuthoringError::BatchRolledBack);
            }
            return Err(AuthoringError::BatchRecoveryUnknown);
        }
        committed.push(prepared[index].destination.clone());
    }
    Ok(prepared.iter().map(|item| item.result.clone()).collect())
}

fn restore_batch(
    prepared: &[PreparedBatchWrite],
    backups: &mut [Option<TempPath>],
    committed: &[PathBuf],
) -> bool {
    let committed: BTreeSet<_> = committed.iter().collect();
    let mut restored = true;
    for (item, backup) in prepared.iter().zip(backups.iter_mut()).rev() {
        if committed.contains(&item.destination) && std::fs::remove_file(&item.destination).is_err()
        {
            restored = false;
        }
        if let Some(backup) = backup.take()
            && std::fs::rename(&backup, &item.destination).is_err()
        {
            restored = false;
        }
    }
    restored
}

/// Decrypts into a private ephemeral workspace, invokes an explicit editor, and replaces atomically.
pub fn edit_secret(request: &EditRequest<'_>) -> Result<AuthoringResult, AuthoringError> {
    edit_secret_checked(request, |_| Ok(()))
}

/// Edits canonical ciphertext while validating the private edited file before it
/// is encrypted or committed. The validator must consume only bounded input and
/// return a redacted error. A validation failure leaves the old ciphertext in
/// place.
pub fn edit_secret_checked<F>(
    request: &EditRequest<'_>,
    validate_edited: F,
) -> Result<AuthoringResult, AuthoringError>
where
    F: FnOnce(&mut File) -> Result<(), AuthoringError>,
{
    let editor = resolve_editor_executable(request.editor)?;
    let destination = resolve_destination(request.repository_root, request.relative_destination)?;
    validate_destination(&destination, WriteMode::Replace)?;
    let workspace_root = resolve_editor_workspace_root(request.workspace_root)?;
    let workspace = tempfile::Builder::new()
        .prefix("nix-seal-edit-")
        .tempdir_in(workspace_root)
        .map_err(AuthoringError::Io)?;
    set_private_directory(workspace.path()).map_err(AuthoringError::Io)?;
    let plaintext_path = workspace.path().join("value");
    let mut plaintext = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&plaintext_path)
        .map_err(AuthoringError::Io)?;
    set_private(&plaintext_path).map_err(AuthoringError::Io)?;
    nix_seal_crypto::decrypt(
        open_nofollow_regular(&destination)?,
        &mut plaintext,
        request.identity,
    )?;
    plaintext.sync_all().map_err(AuthoringError::Io)?;
    drop(plaintext);

    let status = Command::new(editor)
        .args(request.editor_arguments)
        .arg(&plaintext_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(workspace.path())
        .status()
        .map_err(|_| AuthoringError::Editor)?;
    if !status.success() {
        return Err(AuthoringError::Editor);
    }
    let mut plaintext = open_private_edited(&plaintext_path)?;
    validate_edited(&mut plaintext)?;
    plaintext.rewind().map_err(AuthoringError::Io)?;
    write_secret(
        request.repository_root,
        request.relative_destination,
        plaintext,
        request.recipients,
        request.identity,
        WriteMode::Replace,
    )
}

/// Validates that an explicit editor resolves to a regular executable.
///
/// The editor is intentionally user-selected and therefore remains part of the
/// authoring workstation's trusted computing base. This type check does not
/// reduce that trust boundary; it rejects accidental non-executable targets.
fn resolve_editor_executable(path: &Path) -> Result<PathBuf, AuthoringError> {
    if !path.is_absolute() {
        return Err(AuthoringError::Editor);
    }
    let canonical = path.canonicalize().map_err(|_| AuthoringError::Editor)?;
    let canonical_metadata =
        std::fs::symlink_metadata(&canonical).map_err(|_| AuthoringError::Editor)?;
    if canonical_metadata.file_type().is_symlink()
        || !is_executable_regular_file(&canonical_metadata)
    {
        return Err(AuthoringError::Editor);
    }
    // Retain the supplied path for execution. Some Nix tools are applet
    // symlinks (for example `cp` -> `coreutils`), where invoking the resolved
    // multicall binary would change the selected program. The editor remains
    // an explicit user-trusted executable; this validation only prevents an
    // accidental non-executable target.
    Ok(path.to_owned())
}

#[cfg(unix)]
fn is_executable_regular_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_regular_file(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_file()
}

/// Resolves a private-workspace parent without following a user-supplied link.
fn resolve_editor_workspace_root(path: &Path) -> Result<PathBuf, AuthoringError> {
    if !path.is_absolute() {
        return Err(AuthoringError::Editor);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| AuthoringError::Editor)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(AuthoringError::Editor);
    }
    let canonical = path.canonicalize().map_err(|_| AuthoringError::Editor)?;
    let canonical_metadata =
        std::fs::symlink_metadata(&canonical).map_err(|_| AuthoringError::Editor)?;
    if canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.file_type().is_dir()
        || !same_file(&metadata, &canonical_metadata)
    {
        return Err(AuthoringError::Editor);
    }
    Ok(canonical)
}

/// Atomically moves canonical ciphertext into a private, collision-safe quarantine tombstone.
pub fn delete_secret(request: &DeleteRequest<'_>) -> Result<DeletionResult, AuthoringError> {
    if request.secret_id.is_empty() || request.deleted_at.is_empty() {
        return Err(AuthoringError::UnsafePath);
    }
    let source = resolve_existing(request.repository_root, request.relative_source)?;
    let previous = validate_destination(&source, WriteMode::Replace)?
        .ok_or(AuthoringError::DestinationState)?;
    let mut ciphertext = open_nofollow_regular(&source)?;
    let ciphertext_hash = hash_file(&mut ciphertext)?;
    let quarantine_root =
        resolve_private_directory(request.repository_root, request.quarantine_root)?;
    let tombstone = tempfile::Builder::new()
        .prefix("secret-")
        .tempdir_in(&quarantine_root)
        .map_err(AuthoringError::Io)?;
    set_private_directory(tombstone.path()).map_err(AuthoringError::Io)?;

    let metadata = TombstoneV1 {
        schema: "nix-seal.deleted-secret.v1",
        secret_id: request.secret_id,
        original_source: request
            .relative_source
            .to_str()
            .ok_or(AuthoringError::UnsafePath)?,
        ciphertext_hash: &ciphertext_hash,
        deleted_at: request.deleted_at,
    };
    let metadata_bytes = serde_json::to_vec(&metadata).map_err(AuthoringError::Tombstone)?;
    let metadata_path = tombstone.path().join("tombstone.json");
    let mut metadata_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&metadata_path)
        .map_err(AuthoringError::Io)?;
    set_private(&metadata_path).map_err(AuthoringError::Io)?;
    metadata_file
        .write_all(&metadata_bytes)
        .and_then(|()| metadata_file.write_all(b"\n"))
        .and_then(|()| metadata_file.sync_all())
        .map_err(AuthoringError::Io)?;

    ensure_unchanged(&source, Some(&previous))?;
    let quarantined = tombstone.path().join("ciphertext.age");
    std::fs::rename(&source, &quarantined).map_err(AuthoringError::Io)?;
    let tombstone_path = tombstone.keep();

    let moved = std::fs::symlink_metadata(&quarantined).map_err(AuthoringError::Io)?;
    if !safe_regular(&moved) || !same_file(&previous, &moved) {
        return Err(AuthoringError::DurabilityUnknown);
    }
    File::open(&tombstone_path)
        .and_then(|directory| directory.sync_all())
        .and_then(|()| File::open(&quarantine_root)?.sync_all())
        .and_then(|()| {
            File::open(source.parent().ok_or_else(|| {
                std::io::Error::other("canonical source has no parent directory")
            })?)?
            .sync_all()
        })
        .map_err(|_| AuthoringError::DurabilityUnknown)?;
    Ok(DeletionResult {
        tombstone_path,
        original_path: source,
        ciphertext_hash,
    })
}

fn resolve_destination(root: &Path, relative: &Path) -> Result<PathBuf, AuthoringError> {
    if !root.is_absolute()
        || relative.is_absolute()
        || relative.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().is_empty()
        })
    {
        return Err(AuthoringError::UnsafePath);
    }
    let canonical_root = root.canonicalize().map_err(AuthoringError::Io)?;
    let parent_relative = relative.parent().ok_or(AuthoringError::UnsafePath)?;
    let mut parent = canonical_root.clone();
    for component in parent_relative.components() {
        let Component::Normal(segment) = component else {
            return Err(AuthoringError::UnsafePath);
        };
        parent.push(segment);
        match std::fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(AuthoringError::UnsafePath),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&parent).map_err(AuthoringError::Io)?;
            }
            Err(error) => return Err(AuthoringError::Io(error)),
        }
    }
    let canonical_parent = parent.canonicalize().map_err(AuthoringError::Io)?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(AuthoringError::UnsafePath);
    }
    let file_name = relative.file_name().ok_or(AuthoringError::UnsafePath)?;
    Ok(canonical_parent.join(file_name))
}

fn resolve_existing(root: &Path, relative: &Path) -> Result<PathBuf, AuthoringError> {
    validate_relative(relative)?;
    let canonical_root = root.canonicalize().map_err(AuthoringError::Io)?;
    if !canonical_root.is_absolute() {
        return Err(AuthoringError::UnsafePath);
    }
    let mut path = canonical_root.clone();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(AuthoringError::UnsafePath);
        };
        path.push(segment);
        let metadata = std::fs::symlink_metadata(&path).map_err(AuthoringError::Io)?;
        if path != canonical_root.join(relative) && !metadata.file_type().is_dir() {
            return Err(AuthoringError::UnsafePath);
        }
    }
    Ok(path)
}

fn resolve_private_directory(root: &Path, relative: &Path) -> Result<PathBuf, AuthoringError> {
    validate_relative(relative)?;
    let canonical_root = root.canonicalize().map_err(AuthoringError::Io)?;
    let mut path = canonical_root.clone();
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            return Err(AuthoringError::UnsafePath);
        };
        path.push(segment);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(AuthoringError::UnsafePath),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&path).map_err(AuthoringError::Io)?;
            }
            Err(error) => return Err(AuthoringError::Io(error)),
        }
    }
    let canonical = path.canonicalize().map_err(AuthoringError::Io)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(AuthoringError::UnsafePath);
    }
    set_private_directory(&canonical).map_err(AuthoringError::Io)?;
    Ok(canonical)
}

fn validate_relative(relative: &Path) -> Result<(), AuthoringError> {
    if relative.is_absolute()
        || relative.as_os_str().is_empty()
        || relative.components().any(|component| {
            !matches!(component, Component::Normal(_)) || component.as_os_str().is_empty()
        })
    {
        return Err(AuthoringError::UnsafePath);
    }
    Ok(())
}

fn validate_destination(
    destination: &Path,
    mode: WriteMode,
) -> Result<Option<std::fs::Metadata>, AuthoringError> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) if mode == WriteMode::Create => Err(AuthoringError::DestinationState),
        Ok(metadata) if safe_regular(&metadata) => Ok(Some(metadata)),
        Ok(_) => Err(AuthoringError::DestinationState),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && mode == WriteMode::Create => {
            Ok(None)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(AuthoringError::DestinationState)
        }
        Err(error) => Err(AuthoringError::Io(error)),
    }
}

fn ensure_unchanged(
    destination: &Path,
    previous: Option<&std::fs::Metadata>,
) -> Result<(), AuthoringError> {
    let previous = previous.ok_or(AuthoringError::DestinationState)?;
    let current = std::fs::symlink_metadata(destination).map_err(AuthoringError::Io)?;
    if !safe_regular(&current) || !same_file(previous, &current) {
        return Err(AuthoringError::DestinationState);
    }
    Ok(())
}

#[cfg(unix)]
fn open_nofollow_regular(path: &Path) -> Result<File, AuthoringError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| AuthoringError::Io(error.into()))?;
    let metadata = fstat(&descriptor).map_err(|error| AuthoringError::Io(error.into()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        return Err(AuthoringError::DestinationState);
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_nofollow_regular(path: &Path) -> Result<File, AuthoringError> {
    let metadata = std::fs::symlink_metadata(path).map_err(AuthoringError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(AuthoringError::DestinationState);
    }
    File::open(path).map_err(AuthoringError::Io)
}

#[cfg(unix)]
fn open_private_edited(path: &Path) -> Result<File, AuthoringError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| AuthoringError::Editor)?;
    let metadata = fstat(&descriptor).map_err(|_| AuthoringError::Editor)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o077 != 0
    {
        return Err(AuthoringError::Editor);
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_private_edited(path: &Path) -> Result<File, AuthoringError> {
    open_nofollow_regular(path).map_err(|_| AuthoringError::Editor)
}

#[cfg(unix)]
fn safe_regular(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.file_type().is_file() && metadata.nlink() == 1
}

#[cfg(not(unix))]
fn safe_regular(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_file()
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn hash_file(file: &mut File) -> Result<String, AuthoringError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(AuthoringError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (blake3::Hash, u64) {
        (self.hasher.finalize(), self.bytes)
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("input size overflow"))?;
        Ok(read)
    }
}

#[derive(Default)]
struct HashingWriter {
    hasher: blake3::Hasher,
    bytes: u64,
}

impl HashingWriter {
    fn hash(&self) -> blake3::Hash {
        self.hasher.clone().finalize()
    }
}

impl Write for HashingWriter {
    fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        self.hasher.update(buffer);
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(buffer.len()).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("output size overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_replace_are_verified_and_atomic() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let destination = Path::new("secrets/db.age");
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let recipients = vec![recipient];
        let created = write_secret(
            &root,
            destination,
            b"first-value".as_slice(),
            &recipients,
            &identity,
            WriteMode::Create,
        )?;
        assert_eq!(created.plaintext_bytes, 11);
        let before = std::fs::read(&created.path)?;
        assert!(!before.windows(11).any(|window| window == b"first-value"));

        let (wrong_identity, _) = nix_seal_crypto::generate_x25519();
        assert!(matches!(
            write_secret(
                &root,
                destination,
                b"must-not-commit".as_slice(),
                &recipients,
                &wrong_identity,
                WriteMode::Replace,
            ),
            Err(AuthoringError::VerificationIdentity)
        ));
        assert_eq!(std::fs::read(&created.path)?, before);

        let replaced = write_secret(
            &root,
            destination,
            b"second-value".as_slice(),
            &recipients,
            &identity,
            WriteMode::Replace,
        )?;
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(File::open(&replaced.path)?, &mut plaintext, &identity)?;
        assert_eq!(plaintext, b"second-value");

        let editor_value = root.join("editor-value");
        std::fs::write(&editor_value, b"edited-value")?;
        set_private(&editor_value)?;
        let copy_editor = find_test_executable("cp")?;
        let edited = edit_secret(&EditRequest {
            repository_root: &root,
            relative_destination: destination,
            identity: &identity,
            recipients: &recipients,
            editor: &copy_editor,
            editor_arguments: &[editor_value.to_string_lossy().into_owned()],
            workspace_root: &root,
        })?;
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(File::open(&edited.path)?, &mut plaintext, &identity)?;
        assert_eq!(plaintext, b"edited-value");

        let before_failure = std::fs::read(&edited.path)?;
        assert!(matches!(
            edit_secret_checked(
                &EditRequest {
                    repository_root: &root,
                    relative_destination: destination,
                    identity: &identity,
                    recipients: &recipients,
                    editor: &copy_editor,
                    editor_arguments: &[editor_value.to_string_lossy().into_owned()],
                    workspace_root: &root,
                },
                |_| Err(AuthoringError::InvalidEditedContent),
            ),
            Err(AuthoringError::InvalidEditedContent)
        ));
        assert_eq!(std::fs::read(&edited.path)?, before_failure);

        let failing_editor = find_test_executable("false")?;
        assert!(matches!(
            edit_secret(&EditRequest {
                repository_root: &root,
                relative_destination: destination,
                identity: &identity,
                recipients: &recipients,
                editor: &failing_editor,
                editor_arguments: &[],
                workspace_root: &root,
            }),
            Err(AuthoringError::Editor)
        ));
        assert_eq!(std::fs::read(&edited.path)?, before_failure);
        Ok(())
    }

    #[test]
    fn batch_generation_validates_every_output_before_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let recipients = vec![recipient];
        let first = b"first-created";
        let second = b"second-created";
        let created = write_secret_batch(
            &root,
            &[
                BatchSecretWrite {
                    relative_destination: Path::new("secrets/one.age"),
                    plaintext: first,
                    recipients: &recipients,
                },
                BatchSecretWrite {
                    relative_destination: Path::new("secrets/two.age"),
                    plaintext: second,
                    recipients: &recipients,
                },
            ],
            &identity,
            WriteMode::Create,
        )?;
        assert_eq!(created.len(), 2);
        let before_one = std::fs::read(root.join("secrets/one.age"))?;
        let before_two = std::fs::read(root.join("secrets/two.age"))?;

        let (_, unauthorized_recipient) = nix_seal_crypto::generate_x25519();
        let unauthorized = vec![unauthorized_recipient];
        assert!(matches!(
            write_secret_batch(
                &root,
                &[
                    BatchSecretWrite {
                        relative_destination: Path::new("secrets/one.age"),
                        plaintext: b"must-not-commit-one",
                        recipients: &recipients,
                    },
                    BatchSecretWrite {
                        relative_destination: Path::new("secrets/two.age"),
                        plaintext: b"must-not-commit-two",
                        recipients: &unauthorized,
                    },
                ],
                &identity,
                WriteMode::Replace,
            ),
            Err(AuthoringError::VerificationIdentity)
        ));
        assert_eq!(std::fs::read(root.join("secrets/one.age"))?, before_one);
        assert_eq!(std::fs::read(root.join("secrets/two.age"))?, before_two);

        let replacement = write_secret_batch(
            &root,
            &[
                BatchSecretWrite {
                    relative_destination: Path::new("secrets/one.age"),
                    plaintext: b"first-replaced",
                    recipients: &recipients,
                },
                BatchSecretWrite {
                    relative_destination: Path::new("secrets/two.age"),
                    plaintext: b"second-replaced",
                    recipients: &recipients,
                },
            ],
            &identity,
            WriteMode::Replace,
        )?;
        let expected: [&[u8]; 2] = [b"first-replaced", b"second-replaced"];
        for (result, expected) in replacement.iter().zip(expected) {
            let mut plaintext = Vec::new();
            nix_seal_crypto::decrypt(File::open(&result.path)?, &mut plaintext, &identity)?;
            assert_eq!(plaintext, expected);
        }
        Ok(())
    }

    #[test]
    fn failed_final_input_check_preserves_existing_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let recipients = vec![recipient];
        let destination = Path::new("secrets/checked.age");
        let created = write_secret(
            &root,
            destination,
            b"before".as_slice(),
            &recipients,
            &identity,
            WriteMode::Create,
        )?;
        let before = std::fs::read(&created.path)?;
        assert!(matches!(
            write_secret_checked(
                &root,
                destination,
                b"after".as_slice(),
                &recipients,
                &identity,
                WriteMode::Replace,
                || Err(AuthoringError::ExternalInput),
            ),
            Err(AuthoringError::ExternalInput)
        ));
        assert_eq!(std::fs::read(created.path)?, before);
        Ok(())
    }

    #[test]
    fn rekey_streams_existing_ciphertext_without_plaintext_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let (administrator_identity, administrator_recipient) = nix_seal_crypto::generate_x25519();
        let (_, target_recipient) = nix_seal_crypto::generate_x25519();
        write_secret(
            &root,
            Path::new("secrets/source.age"),
            b"streamed-migration-value".as_slice(),
            std::slice::from_ref(&administrator_recipient),
            &administrator_identity,
            WriteMode::Create,
        )?;
        let rekeyed = rekey_secret(
            &root,
            Path::new("secrets/source.age"),
            Path::new("secrets/destination.age"),
            &[administrator_recipient, target_recipient],
            &administrator_identity,
            WriteMode::Create,
        )?;
        let ciphertext = std::fs::read(&rekeyed.path)?;
        assert!(
            !ciphertext
                .windows(b"streamed-migration-value".len())
                .any(|window| window == b"streamed-migration-value")
        );
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(
            File::open(&rekeyed.path)?,
            &mut plaintext,
            &administrator_identity,
        )?;
        assert_eq!(plaintext, b"streamed-migration-value");
        Ok(())
    }

    fn find_test_executable(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        std::env::split_paths(&std::env::var_os("PATH").ok_or("test PATH is absent")?)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| format!("test executable {name} is absent from PATH").into())
    }

    #[cfg(unix)]
    #[test]
    fn editor_inputs_refuse_nonexecutable_and_symlinked_workspace_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let non_executable = root.join("non-executable-editor");
        std::fs::write(&non_executable, b"not an executable")?;
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            resolve_editor_executable(&non_executable),
            Err(AuthoringError::Editor)
        ));

        let executable = find_test_executable("cp")?.canonicalize()?;
        let linked_editor = root.join("linked-editor");
        symlink(&executable, &linked_editor)?;
        assert_eq!(resolve_editor_executable(&linked_editor)?, linked_editor);

        let linked_workspace = root.join("linked-workspace");
        symlink(&root, &linked_workspace)?;
        assert!(matches!(
            resolve_editor_workspace_root(&linked_workspace),
            Err(AuthoringError::Editor)
        ));
        assert_eq!(resolve_editor_workspace_root(&root)?, root);
        Ok(())
    }

    #[test]
    fn deletion_is_recoverable_private_and_collision_safe() -> Result<(), Box<dyn std::error::Error>>
    {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let destination = Path::new("secrets/db.age");
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let recipients = vec![recipient];
        let created = write_secret(
            &root,
            destination,
            b"recoverable-value".as_slice(),
            &recipients,
            &identity,
            WriteMode::Create,
        )?;
        let ciphertext = std::fs::read(&created.path)?;
        let deleted = delete_secret(&DeleteRequest {
            repository_root: &root,
            relative_source: destination,
            quarantine_root: Path::new(".nix-seal/trash/v1"),
            secret_id: "db/password",
            deleted_at: "2026-07-31T22:00:00Z",
        })?;

        assert!(!created.path.exists());
        assert_eq!(
            std::fs::read(deleted.tombstone_path.join("ciphertext.age"))?,
            ciphertext
        );
        let tombstone: serde_json::Value = serde_json::from_slice(&std::fs::read(
            deleted.tombstone_path.join("tombstone.json"),
        )?)?;
        assert_eq!(tombstone["schema"], "nix-seal.deleted-secret.v1");
        assert_eq!(tombstone["secretId"], "db/password");
        assert_eq!(tombstone["originalSource"], "secrets/db.age");
        assert_eq!(tombstone["ciphertextHash"], deleted.ciphertext_hash);
        assert_eq!(tombstone["deletedAt"], "2026-07-31T22:00:00Z");

        write_secret(
            &root,
            destination,
            b"second-value".as_slice(),
            &recipients,
            &identity,
            WriteMode::Create,
        )?;
        let second = delete_secret(&DeleteRequest {
            repository_root: &root,
            relative_source: destination,
            quarantine_root: Path::new(".nix-seal/trash/v1"),
            secret_id: "db/password",
            deleted_at: "2026-07-31T22:00:01Z",
        })?;
        assert_ne!(deleted.tombstone_path, second.tombstone_path);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let quarantine = root.join(".nix-seal/trash/v1");
            assert_eq!(std::fs::metadata(quarantine)?.mode() & 0o777, 0o700);
            assert_eq!(
                std::fs::metadata(&second.tombstone_path)?.mode() & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(second.tombstone_path.join("ciphertext.age"))?.nlink(),
                1
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_destination_ancestry() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        symlink(outside.path(), temporary.path().join("secrets"))?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        assert!(matches!(
            write_secret(
                &temporary.path().canonicalize()?,
                Path::new("secrets/db.age"),
                b"canary".as_slice(),
                &[recipient],
                &identity,
                WriteMode::Create,
            ),
            Err(AuthoringError::UnsafePath)
        ));
        assert!(!outside.path().join("db.age").exists());

        let delete_root = tempfile::tempdir()?;
        let delete_root = delete_root.path().canonicalize()?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let created = write_secret(
            &delete_root,
            Path::new("secrets/db.age"),
            b"preserve-me".as_slice(),
            &[recipient],
            &identity,
            WriteMode::Create,
        )?;
        let before_delete = std::fs::read(&created.path)?;
        symlink(outside.path(), delete_root.join(".nix-seal"))?;
        assert!(matches!(
            delete_secret(&DeleteRequest {
                repository_root: &delete_root,
                relative_source: Path::new("secrets/db.age"),
                quarantine_root: Path::new(".nix-seal/trash/v1"),
                secret_id: "db/password",
                deleted_at: "2026-07-31T22:00:00Z",
            }),
            Err(AuthoringError::UnsafePath)
        ));
        assert!(created.path.exists());
        assert_eq!(std::fs::read(created.path)?, before_delete);
        Ok(())
    }
}

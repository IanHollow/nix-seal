#![forbid(unsafe_code)]
//! Transactional, plan-directed canonical ciphertext authoring.

use secrecy::SecretString;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};
use tempfile::NamedTempFile;
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
    /// Filesystem transaction failed.
    #[error("canonical ciphertext transaction failed")]
    Io(#[source] std::io::Error),
    /// Editor path, exit status, or edited plaintext file was unsafe.
    #[error("explicit editor transaction failed or produced unsafe output")]
    Editor,
    /// The atomic change completed but directory durability could not be confirmed.
    #[error("ciphertext changed atomically but filesystem durability could not be confirmed")]
    DurabilityUnknown,
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
    let verification_recipient = nix_seal_crypto::recipient_from_identity(verification_identity)?;
    if !recipients.contains(&verification_recipient) {
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

/// Decrypts into a private ephemeral workspace, invokes an explicit editor, and replaces atomically.
pub fn edit_secret(request: &EditRequest<'_>) -> Result<AuthoringResult, AuthoringError> {
    if !request.editor.is_absolute() || !request.workspace_root.is_absolute() {
        return Err(AuthoringError::Editor);
    }
    let destination = resolve_destination(request.repository_root, request.relative_destination)?;
    validate_destination(&destination, WriteMode::Replace)?;
    let workspace_root = request
        .workspace_root
        .canonicalize()
        .map_err(AuthoringError::Io)?;
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

    let status = Command::new(request.editor)
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
    let plaintext = open_private_edited(&plaintext_path)?;
    write_secret(
        request.repository_root,
        request.relative_destination,
        plaintext,
        request.recipients,
        request.identity,
        WriteMode::Replace,
    )
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
        let edited = edit_secret(&EditRequest {
            repository_root: &root,
            relative_destination: destination,
            identity: &identity,
            recipients: &recipients,
            editor: Path::new("/bin/cp"),
            editor_arguments: &[editor_value.to_string_lossy().into_owned()],
            workspace_root: &root,
        })?;
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(File::open(&edited.path)?, &mut plaintext, &identity)?;
        assert_eq!(plaintext, b"edited-value");

        let before_failure = std::fs::read(&edited.path)?;
        assert!(matches!(
            edit_secret(&EditRequest {
                repository_root: &root,
                relative_destination: destination,
                identity: &identity,
                recipients: &recipients,
                editor: Path::new("/usr/bin/false"),
                editor_arguments: &[],
                workspace_root: &root,
            }),
            Err(AuthoringError::Editor)
        ));
        assert_eq!(std::fs::read(&edited.path)?, before_failure);
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
        Ok(())
    }
}

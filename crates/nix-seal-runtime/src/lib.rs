#![forbid(unsafe_code)]
//! Authenticated, transactional runtime activation primitives.

use fs2::FileExt;
use nix_seal_core::Id;
use nix_seal_manifest::{ExpectedBinding, SignedEnvelopeV1, TrustedKeys};
use secrecy::SecretString;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use thiserror::Error;

const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 2 * 1024 * 1024;

/// One public artifact and its exact locally expected policy bindings.
pub struct ActivationArtifact<'a> {
    /// Target-encrypted standard age file.
    pub ciphertext: &'a Path,
    /// DSSE-style signed manifest associated with `ciphertext`.
    pub envelope: &'a Path,
    /// Destination and signed secret ID.
    pub secret_id: &'a Id,
    /// Expected canonical administrator ciphertext hash.
    pub source_ciphertext_hash: &'a str,
    /// Exact policy-selected artifact generation.
    pub artifact_generation: u64,
    /// Restrictive runtime mode. Group/other access is rejected in v1.
    pub mode: u32,
}

/// Complete policy and trust context for one atomic activation.
pub struct ActivationRequest<'a> {
    /// Restrictive runtime root such as `/run/nix-seal`.
    pub runtime_root: &'a Path,
    /// Monotonic plaintext generation name.
    pub runtime_generation: u64,
    /// Exact local plan hash.
    pub plan_hash: &'a str,
    /// Exact local target ID.
    pub target_id: &'a Id,
    /// Target recipient fingerprint derived from the local target recipient.
    pub recipient_fingerprint: &'a str,
    /// Exact producer version supported by this activation binary.
    pub tool_version: &'a str,
    /// Current wall-clock time in Unix seconds.
    pub now: u64,
    /// Maximum accepted clock lead for artifact issue times.
    pub allowed_clock_skew: u64,
    /// Explicit trusted artifact-approval keys.
    pub trusted_keys: &'a TrustedKeys,
    /// Required number of distinct trusted approvals.
    pub approval_threshold: usize,
    /// Target age identity. It is never persisted by activation.
    pub target_identity: &'a SecretString,
    /// Every artifact in the all-or-nothing generation.
    pub artifacts: &'a [ActivationArtifact<'a>],
}

/// Public result of a successful generation switch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationResult {
    /// Immutable plaintext generation directory.
    pub generation_path: PathBuf,
    /// Number of activated secret files.
    pub secret_count: usize,
}

/// Runtime materialization failure with no plaintext context.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Filesystem operation failed.
    #[error("runtime generation filesystem operation failed")]
    Io(#[source] std::io::Error),
    /// A source was a link, directory, device, or multiply-linked file.
    #[error("activation source has unsafe filesystem metadata")]
    UnsafeSource,
    /// Runtime root, destination, generation, or mode violated constraints.
    #[error("invalid runtime destination")]
    InvalidDestination,
    /// Artifact or envelope exceeded a v1 resource bound.
    #[error("activation input exceeds v1 safety limits")]
    Limit,
    /// Public envelope JSON was malformed.
    #[error("artifact envelope is malformed")]
    Envelope,
    /// Artifact authentication failed before decryption.
    #[error(transparent)]
    Manifest(#[from] nix_seal_manifest::ManifestError),
    /// Target age decryption failed.
    #[error(transparent)]
    Crypto(#[from] nix_seal_crypto::CryptoError),
}

impl From<std::io::Error> for RuntimeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct PreparedArtifact<'a> {
    ciphertext: File,
    secret_id: &'a Id,
    mode: u32,
}

/// Authenticates every artifact before decrypting any, then atomically switches
/// a complete runtime generation.
pub fn activate(request: &ActivationRequest<'_>) -> Result<ActivationResult, RuntimeError> {
    if request.runtime_generation == 0 || request.artifacts.is_empty() {
        return Err(RuntimeError::InvalidDestination);
    }
    let mut prepared = Vec::with_capacity(request.artifacts.len());
    for artifact in request.artifacts {
        validate_mode(artifact.mode)?;
        let mut ciphertext = open_regular_nofollow(artifact.ciphertext)?;
        let artifact_hash = hash_bounded(&mut ciphertext, MAX_CIPHERTEXT_BYTES)?;
        ciphertext.seek(SeekFrom::Start(0))?;

        let envelope_file = open_regular_nofollow(artifact.envelope)?;
        let envelope_bytes = read_bounded(envelope_file, MAX_ENVELOPE_BYTES)?;
        let envelope: SignedEnvelopeV1 =
            serde_json::from_slice(&envelope_bytes).map_err(|_| RuntimeError::Envelope)?;
        let expected = ExpectedBinding {
            tool_version: request.tool_version,
            plan_hash: request.plan_hash,
            source_ciphertext_hash: artifact.source_ciphertext_hash,
            artifact_ciphertext_hash: &artifact_hash,
            target_id: request.target_id,
            secret_id: artifact.secret_id,
            recipient_fingerprint: request.recipient_fingerprint,
            artifact_generation: artifact.artifact_generation,
            now: request.now,
            allowed_clock_skew: request.allowed_clock_skew,
        };
        nix_seal_manifest::verify(
            &envelope,
            request.trusted_keys,
            request.approval_threshold,
            &expected,
        )?;
        prepared.push(PreparedArtifact {
            ciphertext,
            secret_id: artifact.secret_id,
            mode: artifact.mode,
        });
    }

    let generation = Generation::begin(request.runtime_root)?;
    for mut artifact in prepared {
        let mut destination = generation.create_file(artifact.secret_id, artifact.mode)?;
        nix_seal_crypto::decrypt(
            &mut artifact.ciphertext,
            &mut destination,
            request.target_identity,
        )?;
        destination.sync_all()?;
    }
    let generation_path = generation.commit_and_switch(request.runtime_generation)?;
    Ok(ActivationResult {
        generation_path,
        secret_count: request.artifacts.len(),
    })
}

/// An uncommitted restrictive generation directory holding an activation lock.
pub struct Generation {
    root: PathBuf,
    transaction: TempDir,
    _lock: File,
}

impl Generation {
    /// Starts a private generation on the same filesystem as the runtime root.
    pub fn begin(root: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let root = root.into();
        if let Ok(metadata) = std::fs::symlink_metadata(&root)
            && !metadata.file_type().is_dir()
        {
            return Err(RuntimeError::InvalidDestination);
        }
        std::fs::create_dir_all(&root)?;
        validate_runtime_root_identity(&root)?;
        set_mode(&root, 0o700)?;
        validate_runtime_root(&root)?;

        let lock = open_activation_lock(&root.join(".activate.lock"))?;
        set_file_mode(&lock, 0o600)?;
        lock.lock_exclusive()?;

        let transaction = tempfile::Builder::new()
            .prefix(".generation-")
            .tempdir_in(&root)?;
        set_mode(transaction.path(), 0o700)?;
        Ok(Self {
            root,
            transaction,
            _lock: lock,
        })
    }

    /// Creates one exclusive regular destination inside the private generation.
    pub fn create_file(&self, id: &Id, mode: u32) -> Result<File, RuntimeError> {
        validate_mode(mode)?;
        let path = self.transaction.path().join(id.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            validate_private_ancestors(self.transaction.path(), parent)?;
        }
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        set_file_mode(&file, mode)?;
        Ok(file)
    }

    /// Writes a bounded stream into one exclusive secret file.
    pub fn write_from<R: Read>(
        &self,
        id: &Id,
        mut plaintext: R,
        mode: u32,
    ) -> Result<(), RuntimeError> {
        let mut file = self.create_file(id, mode)?;
        let copied = std::io::copy(
            &mut plaintext.by_ref().take(64 * 1024 * 1024 + 1),
            &mut file,
        )?;
        if copied > 64 * 1024 * 1024 {
            return Err(RuntimeError::Limit);
        }
        file.sync_all()?;
        Ok(())
    }

    /// Atomically publishes and switches the `current` symlink to this complete
    /// generation. Existing generations are never overwritten.
    pub fn commit_and_switch(self, generation: u64) -> Result<PathBuf, RuntimeError> {
        if generation == 0 {
            return Err(RuntimeError::InvalidDestination);
        }
        sync_tree(self.transaction.path())?;
        let destination = self.root.join(format!("generation-{generation}"));
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(RuntimeError::InvalidDestination);
        }
        let source = self.transaction.keep();
        std::fs::rename(source, &destination)?;
        File::open(&self.root)?.sync_all()?;

        if let Err(error) = switch_current(&self.root, generation) {
            let _ = std::fs::remove_dir_all(&destination);
            return Err(error);
        }
        Ok(destination)
    }
}

fn validate_mode(mode: u32) -> Result<(), RuntimeError> {
    if mode == 0 || mode > 0o700 || mode & 0o077 != 0 {
        return Err(RuntimeError::InvalidDestination);
    }
    Ok(())
}

fn validate_runtime_root(root: &Path) -> Result<(), RuntimeError> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() {
        return Err(RuntimeError::InvalidDestination);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RuntimeError::InvalidDestination);
        }
    }
    Ok(())
}

fn validate_runtime_root_identity(root: &Path) -> Result<(), RuntimeError> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() {
        return Err(RuntimeError::InvalidDestination);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(RuntimeError::InvalidDestination);
        }
    }
    Ok(())
}

fn validate_private_ancestors(root: &Path, leaf: &Path) -> Result<(), RuntimeError> {
    let relative = leaf
        .strip_prefix(root)
        .map_err(|_| RuntimeError::InvalidDestination)?;
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)?;
        if !metadata.file_type().is_dir() {
            return Err(RuntimeError::InvalidDestination);
        }
        set_mode(&current, 0o700)?;
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<(), RuntimeError> {
    let mut directories = vec![root.to_owned()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        index += 1;
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
                return Err(RuntimeError::InvalidDestination);
            }
            if file_type.is_dir() {
                directories.push(entry.path());
            }
        }
    }
    for directory in directories.iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn switch_current(root: &Path, generation: u64) -> Result<(), RuntimeError> {
    use std::os::unix::fs::symlink;
    let current = root.join("current");
    if let Ok(metadata) = std::fs::symlink_metadata(&current) {
        if !metadata.file_type().is_symlink() {
            return Err(RuntimeError::InvalidDestination);
        }
        let target = std::fs::read_link(&current)?;
        let valid = target
            .to_str()
            .and_then(|value| value.strip_prefix("generation-"))
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            });
        if !valid {
            return Err(RuntimeError::InvalidDestination);
        }
    }
    let next = root.join(".current-next");
    if let Ok(metadata) = std::fs::symlink_metadata(&next) {
        if !metadata.file_type().is_symlink() {
            return Err(RuntimeError::InvalidDestination);
        }
        std::fs::remove_file(&next)?;
    }
    symlink(format!("generation-{generation}"), &next)?;
    std::fs::rename(&next, &current)?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn switch_current(_root: &Path, _generation: u64) -> Result<(), RuntimeError> {
    Err(RuntimeError::InvalidDestination)
}

fn hash_bounded(file: &mut File, limit: u64) -> Result<String, RuntimeError> {
    let mut hasher = blake3::Hasher::new();
    let mut reader = file.take(limit + 1);
    let copied = std::io::copy(&mut reader, &mut hasher)?;
    if copied > limit {
        return Err(RuntimeError::Limit);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn read_bounded<R: Read>(input: R, limit: u64) -> Result<Vec<u8>, RuntimeError> {
    let capacity = usize::try_from(limit.min(64 * 1024)).map_err(|_| RuntimeError::Limit)?;
    let mut bytes = Vec::with_capacity(capacity);
    input.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| RuntimeError::Limit)? > limit {
        return Err(RuntimeError::Limit);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, RuntimeError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            RuntimeError::UnsafeSource
        } else {
            RuntimeError::Io(error.into())
        }
    })?;
    let metadata = fstat(&descriptor).map_err(|error| RuntimeError::Io(error.into()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        return Err(RuntimeError::UnsafeSource);
    }
    Ok(File::from(descriptor))
}

#[cfg(unix)]
fn open_activation_lock(path: &Path) -> Result<File, RuntimeError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            RuntimeError::UnsafeSource
        } else {
            RuntimeError::Io(error.into())
        }
    })?;
    let metadata = fstat(&descriptor).map_err(|error| RuntimeError::Io(error.into()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_nlink != 1
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(RuntimeError::UnsafeSource);
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_activation_lock(path: &Path) -> Result<File, RuntimeError> {
    let metadata = std::fs::symlink_metadata(path);
    if metadata.is_ok_and(|value| !value.file_type().is_file()) {
        return Err(RuntimeError::UnsafeSource);
    }
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, RuntimeError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(RuntimeError::UnsafeSource);
    }
    Ok(File::open(path)?)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<(), std::io::Error> {
    use rustix::fs::{Mode, fchmod};
    let mode =
        u16::try_from(mode).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    fchmod(file, Mode::from_raw_mode(mode)).map_err(Into::into)
}

#[cfg(not(unix))]
fn set_file_mode(_file: &File, _mode: u32) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_seal_manifest::{ARTIFACT_SCHEMA, ApprovalSigningKey, TargetManifestV1};

    const PLAN_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SOURCE_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    struct Fixture {
        temporary: tempfile::TempDir,
        runtime: PathBuf,
        ciphertext: PathBuf,
        envelope: PathBuf,
        target_identity: SecretString,
        target_id: Id,
        secret_id: Id,
        fingerprint: String,
        trusted: TrustedKeys,
    }

    fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let runtime = temporary.path().join("runtime");
        let ciphertext = temporary.path().join("artifact.age");
        let envelope = temporary.path().join("manifest.json");
        let (target_identity, target_recipient) = nix_seal_crypto::generate_x25519();
        let fingerprint = nix_seal_crypto::recipient_fingerprint(&target_recipient)?;
        let mut output = File::create(&ciphertext)?;
        nix_seal_crypto::encrypt(
            b"plaintext-canary".as_slice(),
            &mut output,
            &[target_recipient],
        )?;
        output.sync_all()?;
        let artifact_hash = hash_bounded(&mut File::open(&ciphertext)?, MAX_CIPHERTEXT_BYTES)?;
        let target_id = Id::parse("host.web")?;
        let secret_id = Id::parse("db/password")?;
        let signing_key = ApprovalSigningKey::generate()?;
        let manifest = TargetManifestV1 {
            schema: ARTIFACT_SCHEMA.to_owned(),
            tool_version: "0.1.0-alpha.1".to_owned(),
            plan_hash: PLAN_HASH.to_owned(),
            source_ciphertext_hash: SOURCE_HASH.to_owned(),
            artifact_ciphertext_hash: artifact_hash,
            target_id: target_id.clone(),
            secret_id: secret_id.clone(),
            recipient_fingerprint: fingerprint.clone(),
            artifact_generation: 1,
            issued_at: 100,
            expires_at: Some(200),
        };
        let signed = nix_seal_manifest::sign_manifest(&manifest, &signing_key)?;
        std::fs::write(&envelope, serde_json::to_vec(&signed)?)?;
        let mut trusted = TrustedKeys::new();
        trusted.insert_encoded(&signing_key.encode_public())?;
        Ok(Fixture {
            temporary,
            runtime,
            ciphertext,
            envelope,
            target_identity,
            target_id,
            secret_id,
            fingerprint,
            trusted,
        })
    }

    #[test]
    fn verifies_then_atomically_switches_generation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let artifact = ActivationArtifact {
            ciphertext: &fixture.ciphertext,
            envelope: &fixture.envelope,
            secret_id: &fixture.secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: 1,
            plan_hash: PLAN_HASH,
            target_id: &fixture.target_id,
            recipient_fingerprint: &fixture.fingerprint,
            tool_version: "0.1.0-alpha.1",
            now: 101,
            allowed_clock_skew: 0,
            trusted_keys: &fixture.trusted,
            approval_threshold: 1,
            target_identity: &fixture.target_identity,
            artifacts: std::slice::from_ref(&artifact),
        };
        let result = activate(&request)?;
        assert_eq!(result.secret_count, 1);
        assert_eq!(
            std::fs::read(result.generation_path.join("db/password"))?,
            b"plaintext-canary"
        );
        assert_eq!(
            std::fs::read_link(fixture.runtime.join("current"))?,
            Path::new("generation-1")
        );
        Ok(())
    }

    #[test]
    fn authentication_failure_preserves_previous_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let initial = Generation::begin(&fixture.runtime)?;
        initial.write_from(&fixture.secret_id, b"old-value".as_slice(), 0o400)?;
        initial.commit_and_switch(1)?;
        std::fs::write(&fixture.ciphertext, b"substituted")?;

        let artifact = ActivationArtifact {
            ciphertext: &fixture.ciphertext,
            envelope: &fixture.envelope,
            secret_id: &fixture.secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: 2,
            plan_hash: PLAN_HASH,
            target_id: &fixture.target_id,
            recipient_fingerprint: &fixture.fingerprint,
            tool_version: "0.1.0-alpha.1",
            now: 101,
            allowed_clock_skew: 0,
            trusted_keys: &fixture.trusted,
            approval_threshold: 1,
            target_identity: &fixture.target_identity,
            artifacts: std::slice::from_ref(&artifact),
        };
        assert!(matches!(
            activate(&request),
            Err(RuntimeError::Manifest(
                nix_seal_manifest::ManifestError::Binding
            ))
        ));
        assert_eq!(
            std::fs::read_link(fixture.runtime.join("current"))?,
            Path::new("generation-1")
        );
        assert_eq!(
            std::fs::read(fixture.runtime.join("current/db/password"))?,
            b"old-value"
        );
        assert!(!fixture.runtime.join("generation-2").exists());
        Ok(())
    }

    #[test]
    fn verifies_entire_batch_before_creating_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let other_id = Id::parse("db/other")?;
        let first = ActivationArtifact {
            ciphertext: &fixture.ciphertext,
            envelope: &fixture.envelope,
            secret_id: &fixture.secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let mismatched = ActivationArtifact {
            ciphertext: &fixture.ciphertext,
            envelope: &fixture.envelope,
            secret_id: &other_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let artifacts = [first, mismatched];
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: 1,
            plan_hash: PLAN_HASH,
            target_id: &fixture.target_id,
            recipient_fingerprint: &fixture.fingerprint,
            tool_version: "0.1.0-alpha.1",
            now: 101,
            allowed_clock_skew: 0,
            trusted_keys: &fixture.trusted,
            approval_threshold: 1,
            target_identity: &fixture.target_identity,
            artifacts: &artifacts,
        };
        assert!(matches!(
            activate(&request),
            Err(RuntimeError::Manifest(
                nix_seal_manifest::ManifestError::Binding
            ))
        ));
        assert!(!fixture.runtime.exists());
        Ok(())
    }

    #[test]
    fn decryption_failure_preserves_previous_generation() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture()?;
        let initial = Generation::begin(&fixture.runtime)?;
        initial.write_from(&fixture.secret_id, b"old-value".as_slice(), 0o400)?;
        initial.commit_and_switch(1)?;
        let (wrong_identity, _recipient) = nix_seal_crypto::generate_x25519();
        let artifact = ActivationArtifact {
            ciphertext: &fixture.ciphertext,
            envelope: &fixture.envelope,
            secret_id: &fixture.secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: 2,
            plan_hash: PLAN_HASH,
            target_id: &fixture.target_id,
            recipient_fingerprint: &fixture.fingerprint,
            tool_version: "0.1.0-alpha.1",
            now: 101,
            allowed_clock_skew: 0,
            trusted_keys: &fixture.trusted,
            approval_threshold: 1,
            target_identity: &wrong_identity,
            artifacts: std::slice::from_ref(&artifact),
        };
        assert!(matches!(activate(&request), Err(RuntimeError::Crypto(_))));
        assert_eq!(
            std::fs::read_link(fixture.runtime.join("current"))?,
            Path::new("generation-1")
        );
        assert_eq!(
            std::fs::read(fixture.runtime.join("current/db/password"))?,
            b"old-value"
        );
        assert!(!fixture.runtime.join("generation-2").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_artifact_before_decryption() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let fixture = fixture()?;
        let link = fixture.temporary.path().join("linked.age");
        symlink(&fixture.ciphertext, &link)?;
        let artifact = ActivationArtifact {
            ciphertext: &link,
            envelope: &fixture.envelope,
            secret_id: &fixture.secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
        };
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: 1,
            plan_hash: PLAN_HASH,
            target_id: &fixture.target_id,
            recipient_fingerprint: &fixture.fingerprint,
            tool_version: "0.1.0-alpha.1",
            now: 101,
            allowed_clock_skew: 0,
            trusted_keys: &fixture.trusted,
            approval_threshold: 1,
            target_identity: &fixture.target_identity,
            artifacts: std::slice::from_ref(&artifact),
        };
        assert!(matches!(
            activate(&request),
            Err(RuntimeError::UnsafeSource)
        ));
        assert!(!fixture.runtime.exists());
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Authenticated, transactional runtime activation primitives.

use fs2::FileExt;
use nix_seal_core::Id;
use nix_seal_manifest::{ExpectedBinding, SignedEnvelopeV1, TrustedKeys};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use thiserror::Error;

const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: u64 = 2 * 1024 * 1024;
/// Exact schema accepted for public activation metadata.
pub const ACTIVATION_SCHEMA: &str = "nix-seal.activation.v1";

/// Strict public activation document. It may enter the Nix store.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationSpecV1 {
    /// Must equal [`ACTIVATION_SCHEMA`].
    pub schema: String,
    /// Restrictive runtime root.
    pub runtime_root: PathBuf,
    /// Optional explicit runtime generation; omission safely allocates the next.
    #[serde(default)]
    pub runtime_generation: Option<u64>,
    /// Exact compiled plan hash.
    pub plan_hash: String,
    /// Exact target binding.
    pub target_id: Id,
    /// Fingerprint of the target recipient corresponding to the private identity.
    pub recipient_fingerprint: String,
    /// Maximum accepted issue-time lead.
    #[serde(default = "default_clock_skew")]
    pub allowed_clock_skew: u64,
    /// Required number of distinct trusted approvals.
    pub approval_threshold: usize,
    /// Encoded public approval keys.
    pub trusted_keys: Vec<String>,
    /// Complete all-or-nothing artifact batch.
    pub artifacts: Vec<ActivationArtifactSpecV1>,
}

/// One public artifact entry in [`ActivationSpecV1`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivationArtifactSpecV1 {
    /// Target-encrypted standard age file.
    pub ciphertext: PathBuf,
    /// Signed envelope file.
    pub envelope: PathBuf,
    /// Signed secret and runtime destination ID.
    pub secret_id: Id,
    /// Expected canonical source ciphertext hash.
    pub source_ciphertext_hash: String,
    /// Exact artifact generation.
    pub artifact_generation: u64,
    /// Restrictive octal mode such as `0400`.
    pub mode: String,
    /// Existing operating-system account that owns the runtime file.
    pub owner: String,
    /// Existing operating-system group that owns the runtime file.
    pub group: String,
}

impl ActivationArtifactSpecV1 {
    /// Returns the validated numeric runtime mode.
    pub fn parsed_mode(&self) -> Result<u32, RuntimeError> {
        parse_mode(&self.mode)
    }
}

const fn default_clock_skew() -> u64 {
    300
}

impl ActivationSpecV1 {
    /// Enforces structural and resource constraints before filesystem access.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != ACTIVATION_SCHEMA
            || !self.runtime_root.is_absolute()
            || self.runtime_generation == Some(0)
            || !is_digest(&self.plan_hash)
            || !is_digest(&self.recipient_fingerprint)
            || self.allowed_clock_skew > 86_400
            || self.approval_threshold == 0
            || self.approval_threshold > self.trusted_keys.len()
            || self.trusted_keys.len() > 64
            || self
                .trusted_keys
                .iter()
                .any(|key| key.is_empty() || key.len() > 16 * 1024)
            || self.artifacts.is_empty()
            || self.artifacts.len() > 10_000
        {
            return Err(RuntimeError::InvalidSpec);
        }
        let mut ids = BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifact.ciphertext.is_absolute()
                || !artifact.envelope.is_absolute()
                || !is_digest(&artifact.source_ciphertext_hash)
                || artifact.artifact_generation == 0
                || !ids.insert(&artifact.secret_id)
                || parse_mode(&artifact.mode).is_err()
                || !is_account_name(&artifact.owner)
                || !is_account_name(&artifact.group)
            {
                return Err(RuntimeError::InvalidSpec);
            }
        }
        Ok(())
    }
}

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
    /// Existing operating-system account that owns the runtime file.
    pub owner: &'a str,
    /// Existing operating-system group that owns the runtime file.
    pub group: &'a str,
}

/// Complete policy and trust context for one atomic activation.
pub struct ActivationRequest<'a> {
    /// Restrictive runtime root such as `/run/nix-seal`.
    pub runtime_root: &'a Path,
    /// Monotonic plaintext generation name.
    pub runtime_generation: Option<u64>,
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
    /// Public activation metadata violated its strict schema or resource limits.
    #[error("invalid activation specification")]
    InvalidSpec,
    /// A declared runtime owner or group does not exist.
    #[error("declared runtime owner or group does not exist")]
    UnknownAccount,
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
    uid: u32,
    gid: u32,
}

/// Authenticates every artifact before decrypting any, then atomically switches
/// a complete runtime generation.
pub fn activate(request: &ActivationRequest<'_>) -> Result<ActivationResult, RuntimeError> {
    if request.runtime_generation == Some(0) || request.artifacts.is_empty() {
        return Err(RuntimeError::InvalidDestination);
    }
    let mut prepared = Vec::with_capacity(request.artifacts.len());
    for artifact in request.artifacts {
        validate_mode(artifact.mode)?;
        let uid = resolve_user(artifact.owner)?;
        let gid = resolve_group(artifact.group)?;
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
            uid,
            gid,
        });
    }

    let generation = Generation::begin(request.runtime_root)?;
    for mut artifact in prepared {
        let mut destination = generation.create_file_owned(
            artifact.secret_id,
            artifact.mode,
            artifact.uid,
            artifact.gid,
        )?;
        nix_seal_crypto::decrypt(
            &mut artifact.ciphertext,
            &mut destination,
            request.target_identity,
        )?;
        destination.sync_all()?;
    }
    let generation_path = generation.commit_and_switch_optional(request.runtime_generation)?;
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
        self.create_file_owned(
            id,
            mode,
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    /// Creates one exclusive destination and applies ownership through its
    /// already-open descriptor before returning it.
    pub fn create_file_owned(
        &self,
        id: &Id,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<File, RuntimeError> {
        validate_mode(mode)?;
        let path = self.transaction.path().join(id.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            validate_private_ancestors(self.transaction.path(), parent)?;
        }
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        set_file_owner(&file, uid, gid)?;
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
        self.commit_and_switch_optional(Some(generation))
    }

    fn commit_and_switch_optional(self, generation: Option<u64>) -> Result<PathBuf, RuntimeError> {
        let generation = generation.map_or_else(|| next_generation(&self.root), Ok)?;
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

fn next_generation(root: &Path) -> Result<u64, RuntimeError> {
    let mut maximum = 0_u64;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(suffix) = name.strip_prefix("generation-") else {
            continue;
        };
        if !file_type.is_dir()
            || suffix.is_empty()
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(RuntimeError::InvalidDestination);
        }
        let value = suffix
            .parse::<u64>()
            .map_err(|_| RuntimeError::InvalidDestination)?;
        maximum = maximum.max(value);
    }
    maximum
        .checked_add(1)
        .ok_or(RuntimeError::InvalidDestination)
}

fn parse_mode(value: &str) -> Result<u32, RuntimeError> {
    if value.len() != 4 || !value.starts_with('0') {
        return Err(RuntimeError::InvalidSpec);
    }
    let mode = u32::from_str_radix(value, 8).map_err(|_| RuntimeError::InvalidSpec)?;
    validate_mode(mode)?;
    Ok(mode)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.bytes().any(|byte| {
            byte.is_ascii_control() || byte == b'/' || byte == b':' || byte.is_ascii_whitespace()
        })
}

#[cfg(unix)]
fn resolve_user(name: &str) -> Result<u32, RuntimeError> {
    uzers::get_user_by_name(name)
        .map(|user| user.uid())
        .ok_or(RuntimeError::UnknownAccount)
}

#[cfg(not(unix))]
fn resolve_user(_name: &str) -> Result<u32, RuntimeError> {
    Err(RuntimeError::UnknownAccount)
}

#[cfg(unix)]
fn resolve_group(name: &str) -> Result<u32, RuntimeError> {
    uzers::get_group_by_name(name)
        .map(|group| group.gid())
        .ok_or(RuntimeError::UnknownAccount)
}

#[cfg(not(unix))]
fn resolve_group(_name: &str) -> Result<u32, RuntimeError> {
    Err(RuntimeError::UnknownAccount)
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
    let mut permissions = Mode::empty();
    if mode & 0o400 != 0 {
        permissions |= Mode::RUSR;
    }
    if mode & 0o200 != 0 {
        permissions |= Mode::WUSR;
    }
    if mode & 0o100 != 0 {
        permissions |= Mode::XUSR;
    }
    fchmod(file, permissions).map_err(Into::into)
}

#[cfg(unix)]
fn set_file_owner(file: &File, uid: u32, gid: u32) -> Result<(), std::io::Error> {
    use rustix::{
        fs::fchown,
        process::{Gid, Uid},
    };
    fchown(file, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid))).map_err(Into::into)
}

#[cfg(not(unix))]
fn set_file_owner(_file: &File, _uid: u32, _gid: u32) -> Result<(), std::io::Error> {
    Ok(())
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
        owner: String,
        group: String,
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
        let owner = uzers::get_user_by_uid(uzers::get_current_uid())
            .ok_or("current user is not resolvable")?
            .name()
            .to_str()
            .ok_or("current user name is not UTF-8")?
            .to_owned();
        let group = uzers::get_group_by_gid(uzers::get_current_gid())
            .ok_or("current group is not resolvable")?
            .name()
            .to_str()
            .ok_or("current group name is not UTF-8")?
            .to_owned();
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
            owner,
            group,
        })
    }

    fn owned_artifact<'a>(
        fixture: &'a Fixture,
        ciphertext: &'a Path,
        secret_id: &'a Id,
    ) -> ActivationArtifact<'a> {
        ActivationArtifact {
            ciphertext,
            envelope: &fixture.envelope,
            secret_id,
            source_ciphertext_hash: SOURCE_HASH,
            artifact_generation: 1,
            mode: 0o400,
            owner: &fixture.owner,
            group: &fixture.group,
        }
    }

    #[test]
    fn verifies_then_atomically_switches_generation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let artifact = owned_artifact(&fixture, &fixture.ciphertext, &fixture.secret_id);
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: None,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(result.generation_path.join("db/password"))?;
            assert_eq!(metadata.uid(), uzers::get_current_uid());
            assert_eq!(metadata.gid(), uzers::get_current_gid());
            assert_eq!(metadata.mode() & 0o777, 0o400);
        }
        assert_eq!(
            std::fs::read_link(fixture.runtime.join("current"))?,
            Path::new("generation-1")
        );
        let second = activate(&request)?;
        assert_eq!(second.generation_path, fixture.runtime.join("generation-2"));
        assert_eq!(
            std::fs::read_link(fixture.runtime.join("current"))?,
            Path::new("generation-2")
        );
        Ok(())
    }

    #[test]
    fn unknown_account_fails_before_runtime_creation() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let artifact = ActivationArtifact {
            owner: "nix-seal-account-that-must-not-exist",
            ..owned_artifact(&fixture, &fixture.ciphertext, &fixture.secret_id)
        };
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: None,
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
            Err(RuntimeError::UnknownAccount)
        ));
        assert!(!fixture.runtime.exists());
        Ok(())
    }

    #[test]
    fn activation_spec_is_strict_and_rejects_duplicate_destinations()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture()?;
        let artifact = ActivationArtifactSpecV1 {
            ciphertext: fixture.ciphertext.clone(),
            envelope: fixture.envelope.clone(),
            secret_id: fixture.secret_id.clone(),
            source_ciphertext_hash: SOURCE_HASH.to_owned(),
            artifact_generation: 1,
            mode: "0400".to_owned(),
            owner: fixture.owner.clone(),
            group: fixture.group.clone(),
        };
        let spec = ActivationSpecV1 {
            schema: ACTIVATION_SCHEMA.to_owned(),
            runtime_root: fixture.runtime.clone(),
            runtime_generation: None,
            plan_hash: PLAN_HASH.to_owned(),
            target_id: fixture.target_id,
            recipient_fingerprint: fixture.fingerprint,
            allowed_clock_skew: 300,
            approval_threshold: 1,
            trusted_keys: vec!["public-key-placeholder".to_owned()],
            artifacts: vec![artifact.clone()],
        };
        spec.validate()?;
        let mut duplicate = spec.clone();
        duplicate.artifacts.push(artifact);
        assert!(matches!(
            duplicate.validate(),
            Err(RuntimeError::InvalidSpec)
        ));
        let mut encoded = serde_json::to_value(&spec)?;
        encoded
            .as_object_mut()
            .ok_or("spec was not an object")?
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ActivationSpecV1>(encoded).is_err());
        let mut excessive_skew = spec;
        excessive_skew.allowed_clock_skew = 86_401;
        assert!(matches!(
            excessive_skew.validate(),
            Err(RuntimeError::InvalidSpec)
        ));
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

        let artifact = owned_artifact(&fixture, &fixture.ciphertext, &fixture.secret_id);
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: Some(2),
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
        let first = owned_artifact(&fixture, &fixture.ciphertext, &fixture.secret_id);
        let mismatched = owned_artifact(&fixture, &fixture.ciphertext, &other_id);
        let artifacts = [first, mismatched];
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: Some(1),
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
        let artifact = owned_artifact(&fixture, &fixture.ciphertext, &fixture.secret_id);
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: Some(2),
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
        let artifact = owned_artifact(&fixture, &link, &fixture.secret_id);
        let request = ActivationRequest {
            runtime_root: &fixture.runtime,
            runtime_generation: Some(1),
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

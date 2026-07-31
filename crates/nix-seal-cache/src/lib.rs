#![forbid(unsafe_code)]
//! Ciphertext-only transactional content cache.

use fs2::FileExt;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;

const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const ARTIFACT_FORMAT: &str = "nix-seal.cache-artifact.v2";

/// Cache error that never includes cache contents.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Filesystem operation failed.
    #[error("ciphertext cache operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Supplied object hash did not match its bytes.
    #[error("ciphertext cache object hash mismatch")]
    HashMismatch,
    /// Artifact address fields are malformed.
    #[error("invalid ciphertext cache artifact address")]
    InvalidAddress,
    /// A bounded cache input is too large.
    #[error("ciphertext cache artifact exceeds safety limits")]
    Limit,
    /// The deterministic artifact address is already populated.
    #[error("ciphertext cache artifact already exists")]
    ArtifactExists,
    /// An export directory must be created rather than overwritten.
    #[error("ciphertext cache export destination already exists")]
    DestinationExists,
    /// An existing address has different verified ciphertext or public metadata.
    #[error("ciphertext cache import conflicts with an existing entry")]
    Conflict,
    /// A bundle entry is not a private regular file/directory.
    #[error("ciphertext cache artifact has unsafe filesystem metadata")]
    UnsafeMetadata,
}

/// Deterministic public inputs to a target artifact cache address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactAddress {
    /// Canonical plan hash.
    pub plan_hash: String,
    /// Deterministic target-policy projection hash.
    pub target_policy_hash: String,
    /// Canonical source ciphertext hash.
    pub source_ciphertext_hash: String,
    /// Normalized recipient fingerprint.
    pub recipient_fingerprint: String,
    /// Target ID bound by the stored envelope.
    pub target_id: String,
    /// Secret ID bound by the stored envelope.
    pub secret_id: String,
    /// Monotonic artifact generation bound by the stored envelope.
    pub artifact_generation: u64,
}

impl ArtifactAddress {
    /// Constructs a validated v1 address.
    pub fn new(
        plan_hash: impl Into<String>,
        target_policy_hash: impl Into<String>,
        source_ciphertext_hash: impl Into<String>,
        recipient_fingerprint: impl Into<String>,
        target_id: impl Into<String>,
        secret_id: impl Into<String>,
        artifact_generation: u64,
    ) -> Result<Self, CacheError> {
        let address = Self {
            plan_hash: plan_hash.into(),
            target_policy_hash: target_policy_hash.into(),
            source_ciphertext_hash: source_ciphertext_hash.into(),
            recipient_fingerprint: recipient_fingerprint.into(),
            target_id: target_id.into(),
            secret_id: secret_id.into(),
            artifact_generation,
        };
        address.validate()?;
        Ok(address)
    }

    /// Returns the domain-separated deterministic cache key.
    pub fn key(&self) -> Result<String, CacheError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nix-seal.cache-address.v2\0");
        for field in [
            ARTIFACT_FORMAT,
            &self.plan_hash,
            &self.target_policy_hash,
            &self.source_ciphertext_hash,
            &self.recipient_fingerprint,
            &self.target_id,
            &self.secret_id,
        ] {
            let length = u64::try_from(field.len()).map_err(|_| CacheError::InvalidAddress)?;
            hasher.update(&length.to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(&self.artifact_generation.to_be_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn validate(&self) -> Result<(), CacheError> {
        if [
            &self.plan_hash,
            &self.target_policy_hash,
            &self.source_ciphertext_hash,
            &self.recipient_fingerprint,
        ]
        .into_iter()
        .all(|value| is_digest(value))
            && is_id(&self.target_id)
            && is_id(&self.secret_id)
            && self.artifact_generation > 0
        {
            Ok(())
        } else {
            Err(CacheError::InvalidAddress)
        }
    }
}

fn is_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

/// Verified public metadata for one cached target artifact bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRecord {
    /// Deterministic address key.
    pub key: String,
    /// Hash calculated from the stored target ciphertext.
    pub artifact_ciphertext_hash: String,
    /// Stored signed-envelope bytes.
    pub envelope: Vec<u8>,
    /// Path to the verified ciphertext file.
    pub ciphertext_path: PathBuf,
}

/// Verified, ciphertext-only cache inventory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheInventory {
    /// Number of content-addressed generic ciphertext objects.
    pub object_count: u64,
    /// Total byte count of generic ciphertext objects.
    pub object_bytes: u64,
    /// Number of target artifact bundles.
    pub artifact_count: u64,
    /// Total byte count of target ciphertext files.
    pub artifact_ciphertext_bytes: u64,
    /// Total byte count of signed public artifact envelopes.
    pub artifact_envelope_bytes: u64,
}

/// Explicit, validated cache retention policy for one garbage-collection run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GcRequest {
    /// Artifact keys that remain reachable from active policy.
    pub retained_artifacts: BTreeSet<String>,
    /// Generic object digests that remain reachable from active policy.
    pub retained_objects: BTreeSet<String>,
    /// Whether to remove candidates after the dry-run calculation.
    pub execute: bool,
}

/// Public result of a validated garbage-collection transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GcReport {
    /// Whether candidates were actually removed.
    pub executed: bool,
    /// Number of retained target artifact bundles.
    pub retained_artifacts: u64,
    /// Number of retained generic objects.
    pub retained_objects: u64,
    /// Number of target artifact bundles selected for deletion.
    pub candidate_artifacts: u64,
    /// Number of generic objects selected for deletion.
    pub candidate_objects: u64,
    /// Total candidate bytes, including envelopes.
    pub candidate_bytes: u64,
}

/// Public result of a ciphertext-only cache exchange operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheTransferReport {
    /// Generic ciphertext objects copied or verified.
    pub object_count: u64,
    /// Target artifact bundles copied or verified.
    pub artifact_count: u64,
    /// Total ciphertext and envelope bytes copied or verified.
    pub bytes: u64,
}

/// Versioned ciphertext cache.
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Opens or creates a v1 cache root with restrictive permissions.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        let metadata = std::fs::symlink_metadata(&root)?;
        if !metadata.file_type().is_dir() {
            return Err(CacheError::UnsafeMetadata);
        }
        set_private_permissions(&root, true)?;
        Ok(Self { root })
    }
    /// Returns an object's content address.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> String {
        blake3::hash(bytes).to_hex().to_string()
    }
    /// Atomically stores bytes under their digest while holding the cache lock.
    pub fn put(&self, bytes: &[u8]) -> Result<String, CacheError> {
        let digest = Self::digest(bytes);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(".lock"))?;
        lock.lock_exclusive()?;
        let objects = self.root.join("objects");
        std::fs::create_dir_all(&objects)?;
        set_private_permissions(&objects, true)?;
        let destination = objects.join(&digest);
        match std::fs::symlink_metadata(&destination) {
            Ok(_) => {
                let _ = self.get(&digest)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut temporary = NamedTempFile::new_in(&objects)?;
                set_private_permissions(temporary.path(), false)?;
                temporary.write_all(bytes)?;
                temporary.as_file().sync_all()?;
                temporary
                    .persist_noclobber(&destination)
                    .map_err(|error| error.error)?;
                std::fs::File::open(&objects)?.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
        FileExt::unlock(&lock)?;
        Ok(digest)
    }
    /// Reads and verifies an object.
    pub fn get(&self, digest: &str) -> Result<Vec<u8>, CacheError> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CacheError::HashMismatch);
        }
        let path = self.root.join("objects").join(digest);
        let mut file = open_private_regular(&path)?;
        let bytes = read_bounded(&mut file, MAX_CIPHERTEXT_BYTES)?;
        if Self::digest(&bytes) != digest {
            return Err(CacheError::HashMismatch);
        }
        Ok(bytes)
    }

    /// Atomically stores a target ciphertext and its signed manifest as one bundle.
    pub fn put_artifact<R: Read>(
        &self,
        address: &ArtifactAddress,
        ciphertext: R,
        envelope: &[u8],
    ) -> Result<ArtifactRecord, CacheError> {
        let key = address.key()?;
        self.put_artifact_by_key(key, ciphertext, envelope)
    }

    /// Exports a verified ciphertext-only cache snapshot to a new directory.
    ///
    /// The destination is atomically published only after every source entry
    /// has been copied and revalidated. It contains no private identities or
    /// plaintext, and deliberately omits lock and transaction files.
    pub fn export_to(&self, destination: &Path) -> Result<CacheTransferReport, CacheError> {
        if std::fs::symlink_metadata(destination).is_ok() {
            return Err(CacheError::DestinationExists);
        }
        let parent = destination.parent().ok_or(CacheError::UnsafeMetadata)?;
        let parent_metadata = std::fs::symlink_metadata(parent)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(CacheError::UnsafeMetadata);
        }
        let transaction = TempDir::new_in(parent)?;
        set_private_permissions(transaction.path(), true)?;
        let staged = transaction.path().join("cache");
        let exported = Cache::open(&staged)?;
        let report = self.copy_into(&exported)?;
        File::open(&staged)?.sync_all()?;
        let lock_path = staged.join(".lock");
        if lock_path.exists() {
            std::fs::remove_file(lock_path)?;
        }
        File::open(&staged)?.sync_all()?;
        let staged = transaction.keep();
        let published = staged.join("cache");
        std::fs::rename(&published, destination)?;
        File::open(parent)?.sync_all()?;
        std::fs::remove_dir(staged)?;
        Ok(report)
    }

    /// Imports every verified ciphertext-only entry from an existing exchange directory.
    ///
    /// Existing byte-identical entries are reused. A matching object or artifact
    /// address with different content fails closed and leaves that entry intact.
    pub fn import_from(&self, source: &Path) -> Result<CacheTransferReport, CacheError> {
        let source = Self::open_existing(source)?;
        if source.root.canonicalize()? == self.root.canonicalize()? {
            return Err(CacheError::UnsafeMetadata);
        }
        source.copy_into_unlocked(self)
    }

    fn put_artifact_by_key<R: Read>(
        &self,
        key: String,
        ciphertext: R,
        envelope: &[u8],
    ) -> Result<ArtifactRecord, CacheError> {
        if !is_digest(&key) {
            return Err(CacheError::InvalidAddress);
        }
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(CacheError::Limit);
        }
        let lock = self.lock()?;
        let artifacts = self.artifacts_directory()?;
        let destination = artifacts.join(&key);
        if destination.exists() {
            FileExt::unlock(&lock)?;
            return Err(CacheError::ArtifactExists);
        }

        let transaction = TempDir::new_in(&artifacts)?;
        set_private_permissions(transaction.path(), true)?;
        let ciphertext_path = transaction.path().join("ciphertext.age");
        let envelope_path = transaction.path().join("manifest.dsse.json");
        let mut ciphertext_file = create_private_file(&ciphertext_path)?;
        let artifact_ciphertext_hash =
            copy_and_hash_bounded(ciphertext, &mut ciphertext_file, MAX_CIPHERTEXT_BYTES)?;
        ciphertext_file.sync_all()?;
        let mut envelope_file = create_private_file(&envelope_path)?;
        envelope_file.write_all(envelope)?;
        envelope_file.sync_all()?;
        File::open(transaction.path())?.sync_all()?;

        let staged = transaction.keep();
        if let Err(error) = std::fs::rename(&staged, &destination) {
            let _ = std::fs::remove_dir_all(&staged);
            return Err(error.into());
        }
        File::open(&artifacts)?.sync_all()?;
        FileExt::unlock(&lock)?;

        Ok(ArtifactRecord {
            key,
            artifact_ciphertext_hash,
            envelope: envelope.to_vec(),
            ciphertext_path: destination.join("ciphertext.age"),
        })
    }

    fn open_existing(root: &Path) -> Result<Self, CacheError> {
        let metadata = std::fs::symlink_metadata(root)?;
        validate_private_metadata(&metadata, true)?;
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn copy_into(&self, destination: &Cache) -> Result<CacheTransferReport, CacheError> {
        let lock = self.lock()?;
        let report = self.copy_into_unlocked(destination);
        FileExt::unlock(&lock)?;
        report
    }

    fn copy_into_unlocked(&self, destination: &Cache) -> Result<CacheTransferReport, CacheError> {
        let mut report = CacheTransferReport::default();
        let objects = self.root.join("objects");
        if let Some(entries) = read_directory_if_present(&objects)? {
            for entry in entries {
                let entry = entry?;
                let digest = entry
                    .file_name()
                    .to_str()
                    .ok_or(CacheError::UnsafeMetadata)?
                    .to_owned();
                let bytes = self.get(&digest)?;
                let destination_digest = destination.put(&bytes)?;
                if destination_digest != digest {
                    return Err(CacheError::HashMismatch);
                }
                report.object_count = report
                    .object_count
                    .checked_add(1)
                    .ok_or(CacheError::Limit)?;
                report.bytes = report
                    .bytes
                    .checked_add(u64::try_from(bytes.len()).map_err(|_| CacheError::Limit)?)
                    .ok_or(CacheError::Limit)?;
            }
        }
        for record in self.artifact_records()? {
            let ciphertext_bytes = file_length(&record.ciphertext_path)?;
            match destination.put_artifact_by_key(
                record.key.clone(),
                open_private_regular(&record.ciphertext_path)?,
                &record.envelope,
            ) {
                Ok(imported)
                    if imported.artifact_ciphertext_hash == record.artifact_ciphertext_hash => {}
                Ok(_) => return Err(CacheError::Conflict),
                Err(CacheError::ArtifactExists) => {
                    let existing = destination.load_artifact_by_key(&record.key)?;
                    if existing.artifact_ciphertext_hash != record.artifact_ciphertext_hash
                        || existing.envelope != record.envelope
                    {
                        return Err(CacheError::Conflict);
                    }
                }
                Err(error) => return Err(error),
            }
            report.artifact_count = report
                .artifact_count
                .checked_add(1)
                .ok_or(CacheError::Limit)?;
            report.bytes = checked_transfer_bytes(report.bytes, ciphertext_bytes)?;
            report.bytes = checked_transfer_bytes(
                report.bytes,
                u64::try_from(record.envelope.len()).map_err(|_| CacheError::Limit)?,
            )?;
        }
        Ok(report)
    }

    /// Loads a bundle and recalculates its ciphertext hash before returning it.
    pub fn load_artifact(
        &self,
        address: &ArtifactAddress,
    ) -> Result<Option<ArtifactRecord>, CacheError> {
        let key = address.key()?;
        let directory = self.root.join("artifacts").join(&key);
        match std::fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                validate_private_metadata(&metadata, true)?;
            }
            Ok(_) => return Err(CacheError::UnsafeMetadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        self.load_artifact_by_key(&key).map(Some)
    }

    /// Verifies every cache entry and returns only aggregate public metadata.
    pub fn inventory(&self) -> Result<CacheInventory, CacheError> {
        let mut inventory = CacheInventory::default();
        let objects = self.root.join("objects");
        if let Some(entries) = read_directory_if_present(&objects)? {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let digest = name.to_str().ok_or(CacheError::UnsafeMetadata)?;
                if !is_digest(digest) {
                    return Err(CacheError::UnsafeMetadata);
                }
                let mut file = open_private_regular(&entry.path())?;
                let bytes = read_bounded(&mut file, MAX_CIPHERTEXT_BYTES)?;
                if Self::digest(&bytes) != digest {
                    return Err(CacheError::HashMismatch);
                }
                inventory.object_count = inventory
                    .object_count
                    .checked_add(1)
                    .ok_or(CacheError::Limit)?;
                inventory.object_bytes = inventory
                    .object_bytes
                    .checked_add(u64::try_from(bytes.len()).map_err(|_| CacheError::Limit)?)
                    .ok_or(CacheError::Limit)?;
            }
        }
        let artifacts = self.root.join("artifacts");
        if let Some(entries) = read_directory_if_present(&artifacts)? {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let key = name.to_str().ok_or(CacheError::UnsafeMetadata)?;
                if !is_digest(key) {
                    return Err(CacheError::UnsafeMetadata);
                }
                let record = self.load_artifact_by_key(key)?;
                inventory.artifact_count = inventory
                    .artifact_count
                    .checked_add(1)
                    .ok_or(CacheError::Limit)?;
                inventory.artifact_ciphertext_bytes = inventory
                    .artifact_ciphertext_bytes
                    .checked_add(file_length(&record.ciphertext_path)?)
                    .ok_or(CacheError::Limit)?;
                inventory.artifact_envelope_bytes = inventory
                    .artifact_envelope_bytes
                    .checked_add(
                        u64::try_from(record.envelope.len()).map_err(|_| CacheError::Limit)?,
                    )
                    .ok_or(CacheError::Limit)?;
            }
        }
        Ok(inventory)
    }

    /// Returns every strictly validated target artifact record in key order.
    ///
    /// Envelope signatures are intentionally not interpreted by the cache; the
    /// policy layer must authenticate them before treating a record as active.
    pub fn artifact_records(&self) -> Result<Vec<ArtifactRecord>, CacheError> {
        let artifacts = self.root.join("artifacts");
        let Some(entries) = read_directory_if_present(&artifacts)? else {
            return Ok(Vec::new());
        };
        let mut keys = BTreeSet::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let key = name.to_str().ok_or(CacheError::UnsafeMetadata)?;
            if !is_digest(key) {
                return Err(CacheError::UnsafeMetadata);
            }
            keys.insert(key.to_owned());
        }
        keys.into_iter()
            .map(|key| self.load_artifact_by_key(&key))
            .collect()
    }

    /// Validates all entries, reports unreachable candidates, and optionally removes them.
    ///
    /// Callers must derive the retention sets from authenticated active policy.
    /// The default `execute = false` is a dry run.
    pub fn garbage_collect(&self, request: &GcRequest) -> Result<GcReport, CacheError> {
        if !request.retained_artifacts.iter().all(|key| is_digest(key))
            || !request.retained_objects.iter().all(|key| is_digest(key))
        {
            return Err(CacheError::InvalidAddress);
        }
        let lock = self.lock()?;
        let mut report = GcReport {
            executed: request.execute,
            ..GcReport::default()
        };
        let objects = self.root.join("objects");
        if let Some(entries) = read_directory_if_present(&objects)? {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let digest = name.to_str().ok_or(CacheError::UnsafeMetadata)?;
                if !is_digest(digest) {
                    return Err(CacheError::UnsafeMetadata);
                }
                let mut file = open_private_regular(&entry.path())?;
                let bytes = read_bounded(&mut file, MAX_CIPHERTEXT_BYTES)?;
                if Self::digest(&bytes) != digest {
                    return Err(CacheError::HashMismatch);
                }
                if request.retained_objects.contains(digest) {
                    report.retained_objects = report
                        .retained_objects
                        .checked_add(1)
                        .ok_or(CacheError::Limit)?;
                } else {
                    report.candidate_objects = report
                        .candidate_objects
                        .checked_add(1)
                        .ok_or(CacheError::Limit)?;
                    report.candidate_bytes = report
                        .candidate_bytes
                        .checked_add(u64::try_from(bytes.len()).map_err(|_| CacheError::Limit)?)
                        .ok_or(CacheError::Limit)?;
                    if request.execute {
                        std::fs::remove_file(entry.path())?;
                    }
                }
            }
            if request.execute {
                File::open(&objects)?.sync_all()?;
            }
        }
        let artifacts = self.root.join("artifacts");
        if let Some(entries) = read_directory_if_present(&artifacts)? {
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name();
                let key = name.to_str().ok_or(CacheError::UnsafeMetadata)?;
                if !is_digest(key) {
                    return Err(CacheError::UnsafeMetadata);
                }
                let record = self.load_artifact_by_key(key)?;
                let bytes = file_length(&record.ciphertext_path)?
                    .checked_add(
                        u64::try_from(record.envelope.len()).map_err(|_| CacheError::Limit)?,
                    )
                    .ok_or(CacheError::Limit)?;
                if request.retained_artifacts.contains(key) {
                    report.retained_artifacts = report
                        .retained_artifacts
                        .checked_add(1)
                        .ok_or(CacheError::Limit)?;
                } else {
                    report.candidate_artifacts = report
                        .candidate_artifacts
                        .checked_add(1)
                        .ok_or(CacheError::Limit)?;
                    report.candidate_bytes = report
                        .candidate_bytes
                        .checked_add(bytes)
                        .ok_or(CacheError::Limit)?;
                    if request.execute {
                        remove_artifact_bundle(&record)?;
                    }
                }
            }
            if request.execute {
                File::open(&artifacts)?.sync_all()?;
            }
        }
        FileExt::unlock(&lock)?;
        Ok(report)
    }
    /// Returns the cache root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock(&self) -> Result<File, CacheError> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.root.join(".lock"))?;
        set_private_permissions(&self.root.join(".lock"), false)?;
        lock.lock_exclusive()?;
        Ok(lock)
    }

    fn artifacts_directory(&self) -> Result<PathBuf, CacheError> {
        let artifacts = self.root.join("artifacts");
        std::fs::create_dir_all(&artifacts)?;
        set_private_permissions(&artifacts, true)?;
        Ok(artifacts)
    }

    fn load_artifact_by_key(&self, key: &str) -> Result<ArtifactRecord, CacheError> {
        if !is_digest(key) {
            return Err(CacheError::InvalidAddress);
        }
        let directory = self.root.join("artifacts").join(key);
        let metadata = std::fs::symlink_metadata(&directory)?;
        validate_private_metadata(&metadata, true)?;
        let mut entries = BTreeSet::new();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            entries.insert(name.to_str().ok_or(CacheError::UnsafeMetadata)?.to_owned());
        }
        if entries != BTreeSet::from(["ciphertext.age".to_owned(), "manifest.dsse.json".to_owned()])
        {
            return Err(CacheError::UnsafeMetadata);
        }
        let ciphertext_path = directory.join("ciphertext.age");
        let envelope_path = directory.join("manifest.dsse.json");
        let artifact_ciphertext_hash = copy_and_hash_bounded(
            open_private_regular(&ciphertext_path)?,
            std::io::sink(),
            MAX_CIPHERTEXT_BYTES,
        )?;
        let mut envelope_file = open_private_regular(&envelope_path)?;
        let envelope = read_bounded(&mut envelope_file, MAX_ENVELOPE_BYTES as u64)?;
        Ok(ArtifactRecord {
            key: key.to_owned(),
            artifact_ciphertext_hash,
            envelope,
            ciphertext_path,
        })
    }
}

fn checked_transfer_bytes(total: u64, additional: u64) -> Result<u64, CacheError> {
    total.checked_add(additional).ok_or(CacheError::Limit)
}

fn read_directory_if_present(path: &Path) -> Result<Option<std::fs::ReadDir>, CacheError> {
    match std::fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn file_length(path: &Path) -> Result<u64, CacheError> {
    let metadata = std::fs::symlink_metadata(path)?;
    validate_private_metadata(&metadata, false)?;
    Ok(metadata.len())
}

fn remove_artifact_bundle(record: &ArtifactRecord) -> Result<(), CacheError> {
    let directory = record
        .ciphertext_path
        .parent()
        .ok_or(CacheError::UnsafeMetadata)?;
    let manifest = directory.join("manifest.dsse.json");
    let ciphertext = directory.join("ciphertext.age");
    validate_private_metadata(&std::fs::symlink_metadata(&ciphertext)?, false)?;
    validate_private_metadata(&std::fs::symlink_metadata(&manifest)?, false)?;
    std::fs::remove_file(ciphertext)?;
    std::fs::remove_file(manifest)?;
    std::fs::remove_dir(directory)?;
    Ok(())
}

fn read_bounded(file: &mut File, limit: u64) -> Result<Vec<u8>, CacheError> {
    let length = file.metadata()?.len();
    if length > limit {
        return Err(CacheError::Limit);
    }
    let capacity = usize::try_from(length).map_err(|_| CacheError::Limit)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)?;
    if bytes.len() > capacity {
        return Err(CacheError::Limit);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_private_regular(path: &Path) -> Result<File, CacheError> {
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
        || metadata.st_mode & 0o077 != 0
    {
        return Err(CacheError::UnsafeMetadata);
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_private_regular(path: &Path) -> Result<File, CacheError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(CacheError::UnsafeMetadata);
    }
    File::open(path).map_err(CacheError::from)
}

fn create_private_file(path: &Path) -> Result<File, CacheError> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_private_permissions(path, false)?;
    Ok(file)
}

fn copy_and_hash_bounded<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    limit: u64,
) -> Result<String, CacheError> {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = limit;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let maximum =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| CacheError::Limit)?;
        if maximum == 0 {
            let mut overflow = [0_u8; 1];
            if input.read(&mut overflow)? != 0 {
                return Err(CacheError::Limit);
            }
            break;
        }
        let read = input.read(&mut buffer[..maximum])?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| CacheError::Limit)?)
            .ok_or(CacheError::Limit)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_private_metadata(
    metadata: &std::fs::Metadata,
    directory: bool,
) -> Result<(), CacheError> {
    if metadata.file_type().is_dir() != directory || metadata.file_type().is_file() == directory {
        return Err(CacheError::UnsafeMetadata);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || (!directory && metadata.nlink() != 1) {
            return Err(CacheError::UnsafeMetadata);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
}
#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    #[test]
    fn stores_and_verifies_content() -> Result<(), CacheError> {
        let temp = tempfile::tempdir()?;
        let cache = Cache::open(temp.path())?;
        let digest = cache.put(b"ciphertext only")?;
        assert_eq!(cache.get(&digest)?, b"ciphertext only");

        let address = ArtifactAddress::new(
            "0".repeat(64),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "host.test",
            "db/password",
            1,
        )?;
        let mut other_target = address.clone();
        other_target.target_id = "host.other".to_owned();
        assert_ne!(address.key()?, other_target.key()?);
        let mut other_generation = address.clone();
        other_generation.artifact_generation = 2;
        assert_ne!(address.key()?, other_generation.key()?);
        let artifact = cache.put_artifact(&address, b"age ciphertext".as_slice(), b"envelope")?;
        assert_eq!(
            artifact.artifact_ciphertext_hash,
            Cache::digest(b"age ciphertext")
        );
        let loaded = cache
            .load_artifact(&address)?
            .ok_or(CacheError::HashMismatch)?;
        assert_eq!(loaded, artifact);
        assert_eq!(
            cache.inventory()?,
            CacheInventory {
                object_count: 1,
                object_bytes: 15,
                artifact_count: 1,
                artifact_ciphertext_bytes: 14,
                artifact_envelope_bytes: 8,
            }
        );
        assert!(matches!(
            cache.put_artifact(&address, b"other".as_slice(), b"envelope"),
            Err(CacheError::ArtifactExists)
        ));
        let report = cache.garbage_collect(&GcRequest {
            retained_artifacts: BTreeSet::from([artifact.key.clone()]),
            retained_objects: BTreeSet::new(),
            execute: false,
        })?;
        assert_eq!(
            report,
            GcReport {
                executed: false,
                retained_artifacts: 1,
                retained_objects: 0,
                candidate_artifacts: 0,
                candidate_objects: 1,
                candidate_bytes: 15,
            }
        );
        assert_eq!(cache.get(&digest)?, b"ciphertext only");
        let removed = cache.garbage_collect(&GcRequest {
            retained_artifacts: BTreeSet::from([artifact.key.clone()]),
            retained_objects: BTreeSet::new(),
            execute: true,
        })?;
        assert!(removed.executed);
        assert!(cache.get(&digest).is_err());
        assert!(cache.load_artifact(&address)?.is_some());

        let concurrent = ArtifactAddress::new(
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            "7".repeat(64),
            "host.other",
            "api/token",
            2,
        )?;
        let cache = Arc::new(cache);
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            let address = concurrent.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cache.put_artifact(&address, b"race".as_slice(), b"envelope")
            }));
        }
        let mut stored = 0;
        for handle in handles {
            match handle.join().map_err(|_| CacheError::UnsafeMetadata)? {
                Ok(_) => stored += 1,
                Err(CacheError::ArtifactExists) => {}
                Err(error) => return Err(error),
            }
        }
        assert_eq!(stored, 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_link_substitution_for_objects_and_artifacts() -> Result<(), CacheError> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let cache = Cache::open(temp.path())?;
        let digest = cache.put(b"ciphertext only")?;
        let object = cache.root().join("objects").join(&digest);
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"not-cache-content")?;
        std::fs::remove_file(&object)?;
        symlink(&outside, &object)?;
        assert!(matches!(cache.get(&digest), Err(CacheError::Io(_))));

        let address = ArtifactAddress::new(
            "0".repeat(64),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "host.test",
            "db/password",
            1,
        )?;
        let artifact = cache.put_artifact(&address, b"age ciphertext".as_slice(), b"envelope")?;
        let manifest = artifact
            .ciphertext_path
            .parent()
            .ok_or(CacheError::UnsafeMetadata)?
            .join("manifest.dsse.json");
        std::fs::remove_file(&manifest)?;
        symlink(&outside, &manifest)?;
        assert!(cache.load_artifact(&address).is_err());
        Ok(())
    }

    #[test]
    fn exports_and_imports_verified_ciphertext_only_entries() -> Result<(), CacheError> {
        let temporary = tempfile::tempdir()?;
        let source = Cache::open(temporary.path().join("source"))?;
        source.put(b"ciphertext object")?;
        let address = ArtifactAddress::new(
            "0".repeat(64),
            "1".repeat(64),
            "2".repeat(64),
            "3".repeat(64),
            "host.test",
            "db/password",
            1,
        )?;
        source.put_artifact(&address, b"target ciphertext".as_slice(), b"envelope")?;
        let exchange = temporary.path().join("exchange");
        let exported = source.export_to(&exchange)?;
        assert_eq!(exported.object_count, 1);
        assert_eq!(exported.artifact_count, 1);
        assert!(!exchange.join(".lock").exists());
        assert!(matches!(
            source.export_to(&exchange),
            Err(CacheError::DestinationExists)
        ));

        let destination = Cache::open(temporary.path().join("destination"))?;
        let imported = destination.import_from(&exchange)?;
        assert_eq!(imported, exported);
        assert_eq!(destination.inventory()?, source.inventory()?);
        assert_eq!(destination.import_from(&exchange)?, exported);
        assert!(!exchange.join(".lock").exists());

        let conflicting = Cache::open(temporary.path().join("conflicting"))?;
        conflicting.put_artifact(&address, b"different ciphertext".as_slice(), b"envelope")?;
        assert!(matches!(
            conflicting.import_from(&exchange),
            Err(CacheError::Conflict)
        ));
        Ok(())
    }
}

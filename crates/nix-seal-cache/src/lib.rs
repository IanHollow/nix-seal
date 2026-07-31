#![forbid(unsafe_code)]
//! Ciphertext-only transactional content cache.

use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;

const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
const ARTIFACT_FORMAT: &str = "nix-seal.cache-artifact.v1";

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
    /// A bundle entry is not a private regular file/directory.
    #[error("ciphertext cache artifact has unsafe filesystem metadata")]
    UnsafeMetadata,
}

/// Deterministic public inputs to a target artifact cache address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactAddress {
    /// Canonical plan hash.
    pub plan_hash: String,
    /// Canonical source ciphertext hash.
    pub source_ciphertext_hash: String,
    /// Normalized recipient fingerprint.
    pub recipient_fingerprint: String,
}

impl ArtifactAddress {
    /// Constructs a validated v1 address.
    pub fn new(
        plan_hash: impl Into<String>,
        source_ciphertext_hash: impl Into<String>,
        recipient_fingerprint: impl Into<String>,
    ) -> Result<Self, CacheError> {
        let address = Self {
            plan_hash: plan_hash.into(),
            source_ciphertext_hash: source_ciphertext_hash.into(),
            recipient_fingerprint: recipient_fingerprint.into(),
        };
        address.validate()?;
        Ok(address)
    }

    /// Returns the domain-separated deterministic cache key.
    pub fn key(&self) -> Result<String, CacheError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"nix-seal.cache-address.v1\0");
        for field in [
            ARTIFACT_FORMAT,
            &self.plan_hash,
            &self.source_ciphertext_hash,
            &self.recipient_fingerprint,
        ] {
            let length = u64::try_from(field.len()).map_err(|_| CacheError::InvalidAddress)?;
            hasher.update(&length.to_be_bytes());
            hasher.update(field.as_bytes());
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn validate(&self) -> Result<(), CacheError> {
        if [
            &self.plan_hash,
            &self.source_ciphertext_hash,
            &self.recipient_fingerprint,
        ]
        .into_iter()
        .all(|value| is_digest(value))
        {
            Ok(())
        } else {
            Err(CacheError::InvalidAddress)
        }
    }
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

/// Versioned ciphertext cache.
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Opens or creates a v1 cache root with restrictive permissions.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CacheError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
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
        if !destination.exists() {
            let mut temporary = NamedTempFile::new_in(&objects)?;
            set_private_permissions(temporary.path(), false)?;
            temporary.write_all(bytes)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist(&destination)
                .map_err(|error| error.error)?;
            std::fs::File::open(&objects)?.sync_all()?;
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
        if std::fs::metadata(&path)?.len() > MAX_CIPHERTEXT_BYTES {
            return Err(CacheError::Limit);
        }
        let bytes = std::fs::read(path)?;
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
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(CacheError::Limit);
        }
        let key = address.key()?;
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
        let ciphertext_path = directory.join("ciphertext.age");
        let envelope_path = directory.join("manifest.dsse.json");
        let ciphertext_metadata = std::fs::symlink_metadata(&ciphertext_path)?;
        let envelope_metadata = std::fs::symlink_metadata(&envelope_path)?;
        validate_private_metadata(&ciphertext_metadata, false)?;
        validate_private_metadata(&envelope_metadata, false)?;
        if envelope_metadata.len() > MAX_ENVELOPE_BYTES as u64 {
            return Err(CacheError::Limit);
        }
        let artifact_ciphertext_hash = copy_and_hash_bounded(
            File::open(&ciphertext_path)?,
            std::io::sink(),
            MAX_CIPHERTEXT_BYTES,
        )?;
        let envelope = std::fs::read(&envelope_path)?;
        Ok(Some(ArtifactRecord {
            key,
            artifact_ciphertext_hash,
            envelope,
            ciphertext_path,
        }))
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

        let address = ArtifactAddress::new("0".repeat(64), "1".repeat(64), "2".repeat(64))?;
        let artifact = cache.put_artifact(&address, b"age ciphertext".as_slice(), b"envelope")?;
        assert_eq!(
            artifact.artifact_ciphertext_hash,
            Cache::digest(b"age ciphertext")
        );
        let loaded = cache
            .load_artifact(&address)?
            .ok_or(CacheError::HashMismatch)?;
        assert_eq!(loaded, artifact);
        assert!(matches!(
            cache.put_artifact(&address, b"other".as_slice(), b"envelope"),
            Err(CacheError::ArtifactExists)
        ));

        let concurrent = ArtifactAddress::new("3".repeat(64), "4".repeat(64), "5".repeat(64))?;
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
}

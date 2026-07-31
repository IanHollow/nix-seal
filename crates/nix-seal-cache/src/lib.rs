#![forbid(unsafe_code)]
//! Ciphertext-only transactional content cache.

use fs2::FileExt;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Cache error that never includes cache contents.
#[derive(Debug, Error)]
pub enum CacheError {
    /// Filesystem operation failed.
    #[error("ciphertext cache operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Supplied object hash did not match its bytes.
    #[error("ciphertext cache object hash mismatch")]
    HashMismatch,
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
        let bytes = std::fs::read(self.root.join("objects").join(digest))?;
        if Self::digest(&bytes) != digest {
            return Err(CacheError::HashMismatch);
        }
        Ok(bytes)
    }
    /// Returns the cache root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
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
    #[test]
    fn stores_and_verifies_content() -> Result<(), CacheError> {
        let temp = tempfile::tempdir()?;
        let cache = Cache::open(temp.path())?;
        let digest = cache.put(b"ciphertext only")?;
        assert_eq!(cache.get(&digest)?, b"ciphertext only");
        Ok(())
    }
}

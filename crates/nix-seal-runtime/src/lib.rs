#![forbid(unsafe_code)]
//! Transactional runtime generation primitives.

use nix_seal_core::Id;
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use thiserror::Error;

/// Runtime materialization failure.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Filesystem operation failed without plaintext context.
    #[error("runtime generation operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// A destination name or mode violated runtime constraints.
    #[error("invalid runtime destination")]
    InvalidDestination,
}

/// An uncommitted restrictive generation directory.
pub struct Generation {
    root: PathBuf,
    transaction: TempDir,
}

impl Generation {
    /// Starts a generation on the same filesystem as the runtime root.
    pub fn begin(root: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        set_mode(&root, 0o700)?;
        let transaction = tempfile::Builder::new()
            .prefix(".generation-")
            .tempdir_in(&root)?;
        set_mode(transaction.path(), 0o700)?;
        Ok(Self { root, transaction })
    }
    /// Writes a single regular file with exclusive creation.
    pub fn write(&self, id: &Id, plaintext: &[u8], mode: u32) -> Result<(), RuntimeError> {
        if mode & 0o077 != 0 {
            return Err(RuntimeError::InvalidDestination);
        }
        let path = self.transaction.path().join(id.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            set_mode(parent, 0o700)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        set_mode(&path, mode)?;
        file.write_all(plaintext)?;
        file.sync_all()?;
        Ok(())
    }
    /// Makes the completed generation immutable-by-name and returns its path.
    pub fn commit(self, generation: &str) -> Result<PathBuf, RuntimeError> {
        if generation.is_empty() || !generation.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(RuntimeError::InvalidDestination);
        }
        std::fs::File::open(self.transaction.path())?.sync_all()?;
        let destination = self.root.join(format!("generation-{generation}"));
        let source = self.transaction.keep();
        std::fs::rename(source, &destination)?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(destination)
    }
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

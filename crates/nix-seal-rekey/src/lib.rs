#![forbid(unsafe_code)]
//! Explicit administrator-to-target rekey transactions.

use nix_seal_cache::{ArtifactAddress, ArtifactRecord, Cache, CacheError};
use nix_seal_core::Id;
use nix_seal_manifest::{
    ARTIFACT_SCHEMA, ApprovalSigningKey, ExpectedBinding, ManifestError, SignedEnvelopeV1,
    TargetManifestV2, TrustedKeys,
};
use secrecy::SecretString;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;

const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;

/// Inputs whose actual bytes and identifiers are bound into one artifact.
pub struct RekeyRequest<'a> {
    /// Canonical administrator-encrypted age file.
    pub source: &'a Path,
    /// Administrator age identity; never persisted by this operation.
    pub administrator_identity: &'a SecretString,
    /// Exact target X25519 recipient.
    pub target_recipient: &'a str,
    /// Canonical plan hash.
    pub plan_hash: &'a str,
    /// Hash of the deterministic target policy derived from the plan.
    pub target_policy_hash: &'a str,
    /// Bound target ID.
    pub target_id: &'a Id,
    /// Bound secret ID.
    pub secret_id: &'a Id,
    /// Artifact generation selected by policy.
    pub artifact_generation: u64,
    /// Issue time in Unix seconds.
    pub issued_at: u64,
    /// Optional approval expiry in Unix seconds.
    pub expires_at: Option<u64>,
    /// Producer tool version.
    pub tool_version: &'a str,
    /// Initial approval signer, kept separate from decryption identity.
    pub signing_key: &'a ApprovalSigningKey,
}

/// Inputs for staging a canonical direct-delivery ciphertext as a signed
/// target artifact. This intentionally does not decrypt or re-encrypt the
/// source: direct mode already addresses its canonical age file to the target.
pub struct DirectRequest<'a> {
    /// Canonical direct-delivery age ciphertext.
    pub source: &'a Path,
    /// Exact target recipient bound into the artifact address and manifest.
    pub target_recipient: &'a str,
    /// Canonical plan hash.
    pub plan_hash: &'a str,
    /// Hash of the deterministic target policy derived from the plan.
    pub target_policy_hash: &'a str,
    /// Bound target ID.
    pub target_id: &'a Id,
    /// Bound secret ID.
    pub secret_id: &'a Id,
    /// Monotonic artifact generation selected by policy.
    pub artifact_generation: u64,
    /// Issue time in Unix seconds.
    pub issued_at: u64,
    /// Optional approval expiry in Unix seconds.
    pub expires_at: Option<u64>,
    /// Producer tool version.
    pub tool_version: &'a str,
    /// Initial approval signer, kept separate from any age identity.
    pub signing_key: &'a ApprovalSigningKey,
}

/// Metadata returned without plaintext or private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RekeyResult {
    /// Deterministic bundle address.
    pub cache_key: String,
    /// Canonical source ciphertext hash.
    pub source_ciphertext_hash: String,
    /// Target ciphertext hash.
    pub artifact_ciphertext_hash: String,
    /// Target recipient fingerprint.
    pub recipient_fingerprint: String,
    /// Cache path containing only target ciphertext.
    pub ciphertext_path: PathBuf,
    /// Whether a previously authenticated cache entry was reused.
    pub reused: bool,
}

/// Redacted rekey transaction failure.
#[derive(Debug, Error)]
pub enum RekeyError {
    /// Source is a link, directory, device, or other unsupported object.
    #[error("canonical ciphertext source is not a no-follow regular file")]
    UnsafeSource,
    /// Source/ciphertext exceeded the v1 safety bound.
    #[error("canonical ciphertext exceeds the 70 MiB safety limit")]
    Limit,
    /// Filesystem staging failed.
    #[error("rekey transaction filesystem operation failed")]
    Io(#[source] std::io::Error),
    /// Standard age processing failed.
    #[error(transparent)]
    Crypto(#[from] nix_seal_crypto::CryptoError),
    /// Cache processing failed.
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// Approval construction or verification failed.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Stored public envelope JSON is malformed.
    #[error("cached artifact envelope is malformed")]
    Envelope,
}

/// Creates or safely reuses one target-bound signed cache artifact.
pub fn rekey(cache: &Cache, request: &RekeyRequest<'_>) -> Result<RekeyResult, RekeyError> {
    let transactions = cache.root().join("transactions");
    std::fs::create_dir_all(&transactions).map_err(RekeyError::Io)?;
    set_private_permissions(&transactions, true).map_err(RekeyError::Io)?;

    // Copy public ciphertext once into a private transaction file. Hashing and
    // later decryption therefore operate on the exact same immutable bytes.
    let mut canonical = NamedTempFile::new_in(&transactions).map_err(RekeyError::Io)?;
    set_private_permissions(canonical.path(), false).map_err(RekeyError::Io)?;
    let source = open_regular_nofollow(request.source)?;
    let source_ciphertext_hash =
        copy_and_hash_bounded(source, canonical.as_file_mut(), MAX_CIPHERTEXT_BYTES)?;
    canonical.as_file().sync_all().map_err(RekeyError::Io)?;
    canonical
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(RekeyError::Io)?;

    let recipient_fingerprint = nix_seal_crypto::recipient_fingerprint(request.target_recipient)?;
    let address = ArtifactAddress::new(
        request.plan_hash,
        request.target_policy_hash,
        &source_ciphertext_hash,
        &recipient_fingerprint,
        request.target_id.as_str(),
        request.secret_id.as_str(),
        request.artifact_generation,
    )?;

    if let Some(record) = cache.load_artifact(&address)? {
        return authenticate_record(
            record,
            request,
            source_ciphertext_hash,
            recipient_fingerprint,
            true,
        );
    }

    let mut target = NamedTempFile::new_in(&transactions).map_err(RekeyError::Io)?;
    set_private_permissions(target.path(), false).map_err(RekeyError::Io)?;
    nix_seal_crypto::rekey(
        canonical.as_file_mut(),
        target.as_file_mut(),
        request.administrator_identity,
        &[request.target_recipient.to_owned()],
    )?;
    target.as_file().sync_all().map_err(RekeyError::Io)?;
    target
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(RekeyError::Io)?;
    let artifact_ciphertext_hash =
        copy_and_hash_bounded(target.as_file_mut(), std::io::sink(), MAX_CIPHERTEXT_BYTES)?;

    let manifest = TargetManifestV2 {
        schema: ARTIFACT_SCHEMA.to_owned(),
        tool_version: request.tool_version.to_owned(),
        plan_hash: request.plan_hash.to_owned(),
        target_policy_hash: request.target_policy_hash.to_owned(),
        source_ciphertext_hash: source_ciphertext_hash.clone(),
        artifact_ciphertext_hash: artifact_ciphertext_hash.clone(),
        target_id: request.target_id.clone(),
        secret_id: request.secret_id.clone(),
        recipient_fingerprint: recipient_fingerprint.clone(),
        artifact_generation: request.artifact_generation,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
    };
    let envelope = nix_seal_manifest::sign_manifest(&manifest, request.signing_key)?;
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|_| RekeyError::Envelope)?;
    target
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(RekeyError::Io)?;

    let record = match cache.put_artifact(&address, target.as_file_mut(), &envelope_bytes) {
        Ok(record) => record,
        Err(CacheError::ArtifactExists) => cache
            .load_artifact(&address)?
            .ok_or(CacheError::ArtifactExists)?,
        Err(error) => return Err(error.into()),
    };
    if record.artifact_ciphertext_hash != artifact_ciphertext_hash {
        // A racing writer won. It is acceptable only after full authentication.
        return authenticate_record(
            record,
            request,
            source_ciphertext_hash,
            recipient_fingerprint,
            true,
        );
    }
    authenticate_record(
        record,
        request,
        source_ciphertext_hash,
        recipient_fingerprint,
        false,
    )
}

/// Copies a direct-delivery canonical ciphertext into the target-artifact
/// cache, signs its exact binding, and verifies the stored result. The source
/// and artifact hashes must be identical: any re-encryption here would defeat
/// the explicit direct-delivery model.
pub fn stage_direct(cache: &Cache, request: &DirectRequest<'_>) -> Result<RekeyResult, RekeyError> {
    let transactions = cache.root().join("transactions");
    std::fs::create_dir_all(&transactions).map_err(RekeyError::Io)?;
    set_private_permissions(&transactions, true).map_err(RekeyError::Io)?;

    let mut canonical = NamedTempFile::new_in(&transactions).map_err(RekeyError::Io)?;
    set_private_permissions(canonical.path(), false).map_err(RekeyError::Io)?;
    let source = open_regular_nofollow(request.source)?;
    let source_ciphertext_hash =
        copy_and_hash_bounded(source, canonical.as_file_mut(), MAX_CIPHERTEXT_BYTES)?;
    canonical.as_file().sync_all().map_err(RekeyError::Io)?;
    canonical
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(RekeyError::Io)?;
    nix_seal_crypto::validate_ciphertext_header(canonical.as_file_mut())?;

    let recipient_fingerprint = nix_seal_crypto::recipient_fingerprint(request.target_recipient)?;
    let address = ArtifactAddress::new(
        request.plan_hash,
        request.target_policy_hash,
        &source_ciphertext_hash,
        &recipient_fingerprint,
        request.target_id.as_str(),
        request.secret_id.as_str(),
        request.artifact_generation,
    )?;
    if let Some(record) = cache.load_artifact(&address)? {
        return authenticate_direct_record(
            record,
            request,
            source_ciphertext_hash,
            recipient_fingerprint,
            true,
        );
    }

    let manifest = TargetManifestV2 {
        schema: ARTIFACT_SCHEMA.to_owned(),
        tool_version: request.tool_version.to_owned(),
        plan_hash: request.plan_hash.to_owned(),
        target_policy_hash: request.target_policy_hash.to_owned(),
        source_ciphertext_hash: source_ciphertext_hash.clone(),
        artifact_ciphertext_hash: source_ciphertext_hash.clone(),
        target_id: request.target_id.clone(),
        secret_id: request.secret_id.clone(),
        recipient_fingerprint: recipient_fingerprint.clone(),
        artifact_generation: request.artifact_generation,
        issued_at: request.issued_at,
        expires_at: request.expires_at,
    };
    let envelope = nix_seal_manifest::sign_manifest(&manifest, request.signing_key)?;
    let envelope_bytes = serde_json::to_vec(&envelope).map_err(|_| RekeyError::Envelope)?;
    canonical
        .as_file_mut()
        .seek(SeekFrom::Start(0))
        .map_err(RekeyError::Io)?;
    let record = match cache.put_artifact(&address, canonical.as_file_mut(), &envelope_bytes) {
        Ok(record) => record,
        Err(CacheError::ArtifactExists) => cache
            .load_artifact(&address)?
            .ok_or(CacheError::ArtifactExists)?,
        Err(error) => return Err(error.into()),
    };
    authenticate_direct_record(
        record,
        request,
        source_ciphertext_hash,
        recipient_fingerprint,
        false,
    )
}

fn authenticate_record(
    record: ArtifactRecord,
    request: &RekeyRequest<'_>,
    source_ciphertext_hash: String,
    recipient_fingerprint: String,
    reused: bool,
) -> Result<RekeyResult, RekeyError> {
    let envelope: SignedEnvelopeV1 =
        serde_json::from_slice(&record.envelope).map_err(|_| RekeyError::Envelope)?;
    let mut trusted = TrustedKeys::new();
    trusted.insert_encoded(&request.signing_key.encode_public())?;
    let expected = ExpectedBinding {
        tool_version: request.tool_version,
        plan_hash: request.plan_hash,
        target_policy_hash: request.target_policy_hash,
        source_ciphertext_hash: &source_ciphertext_hash,
        artifact_ciphertext_hash: &record.artifact_ciphertext_hash,
        target_id: request.target_id,
        secret_id: request.secret_id,
        recipient_fingerprint: &recipient_fingerprint,
        artifact_generation: request.artifact_generation,
        now: request.issued_at,
        allowed_clock_skew: 0,
    };
    nix_seal_manifest::verify(&envelope, &trusted, 1, &expected)?;
    Ok(RekeyResult {
        cache_key: record.key,
        source_ciphertext_hash,
        artifact_ciphertext_hash: record.artifact_ciphertext_hash,
        recipient_fingerprint,
        ciphertext_path: record.ciphertext_path,
        reused,
    })
}

fn authenticate_direct_record(
    record: ArtifactRecord,
    request: &DirectRequest<'_>,
    source_ciphertext_hash: String,
    recipient_fingerprint: String,
    reused: bool,
) -> Result<RekeyResult, RekeyError> {
    if record.artifact_ciphertext_hash != source_ciphertext_hash {
        return Err(RekeyError::Manifest(ManifestError::Binding));
    }
    let envelope: SignedEnvelopeV1 =
        serde_json::from_slice(&record.envelope).map_err(|_| RekeyError::Envelope)?;
    let mut trusted = TrustedKeys::new();
    trusted.insert_encoded(&request.signing_key.encode_public())?;
    let expected = ExpectedBinding {
        tool_version: request.tool_version,
        plan_hash: request.plan_hash,
        target_policy_hash: request.target_policy_hash,
        source_ciphertext_hash: &source_ciphertext_hash,
        artifact_ciphertext_hash: &record.artifact_ciphertext_hash,
        target_id: request.target_id,
        secret_id: request.secret_id,
        recipient_fingerprint: &recipient_fingerprint,
        artifact_generation: request.artifact_generation,
        now: request.issued_at,
        allowed_clock_skew: 0,
    };
    nix_seal_manifest::verify(&envelope, &trusted, 1, &expected)?;
    Ok(RekeyResult {
        cache_key: record.key,
        source_ciphertext_hash,
        artifact_ciphertext_hash: record.artifact_ciphertext_hash,
        recipient_fingerprint,
        ciphertext_path: record.ciphertext_path,
        reused,
    })
}

fn copy_and_hash_bounded<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    limit: u64,
) -> Result<String, RekeyError> {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = limit;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let maximum =
            usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| RekeyError::Limit)?;
        if maximum == 0 {
            let mut overflow = [0_u8; 1];
            if input.read(&mut overflow).map_err(RekeyError::Io)? != 0 {
                return Err(RekeyError::Limit);
            }
            break;
        }
        let read = input.read(&mut buffer[..maximum]).map_err(RekeyError::Io)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read]).map_err(RekeyError::Io)?;
        hasher.update(&buffer[..read]);
        remaining = remaining
            .checked_sub(u64::try_from(read).map_err(|_| RekeyError::Limit)?)
            .ok_or(RekeyError::Limit)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> Result<File, RekeyError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            RekeyError::UnsafeSource
        } else {
            RekeyError::Io(error.into())
        }
    })?;
    let metadata = fstat(&descriptor).map_err(|error| RekeyError::Io(error.into()))?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        return Err(RekeyError::UnsafeSource);
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_nofollow(path: &Path) -> Result<File, RekeyError> {
    let metadata = std::fs::symlink_metadata(path).map_err(RekeyError::Io)?;
    if !metadata.file_type().is_file() {
        return Err(RekeyError::UnsafeSource);
    }
    File::open(path).map_err(RekeyError::Io)
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
    use std::fs::OpenOptions;

    const PLAN_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const TARGET_POLICY_HASH: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";

    fn request<'a>(
        source: &'a Path,
        administrator_identity: &'a SecretString,
        target_recipient: &'a str,
        target_id: &'a Id,
        secret_id: &'a Id,
        signing_key: &'a ApprovalSigningKey,
    ) -> RekeyRequest<'a> {
        RekeyRequest {
            source,
            administrator_identity,
            target_recipient,
            plan_hash: PLAN_HASH,
            target_policy_hash: TARGET_POLICY_HASH,
            target_id,
            secret_id,
            artifact_generation: 1,
            issued_at: 100,
            expires_at: Some(200),
            tool_version: "0.1.0-alpha.1",
            signing_key,
        }
    }

    fn direct_request<'a>(
        source: &'a Path,
        target_recipient: &'a str,
        target_id: &'a Id,
        secret_id: &'a Id,
        signing_key: &'a ApprovalSigningKey,
    ) -> DirectRequest<'a> {
        DirectRequest {
            source,
            target_recipient,
            plan_hash: PLAN_HASH,
            target_policy_hash: TARGET_POLICY_HASH,
            target_id,
            secret_id,
            artifact_generation: 1,
            issued_at: 100,
            expires_at: Some(200),
            tool_version: "0.1.0-alpha.1",
            signing_key,
        }
    }

    #[test]
    fn rekeys_reuses_and_detects_cache_tampering() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("canonical.age");
        let (administrator_identity, administrator_recipient) = nix_seal_crypto::generate_x25519();
        let (target_identity, target_recipient) = nix_seal_crypto::generate_x25519();
        let mut source_file = File::create(&source)?;
        nix_seal_crypto::encrypt(
            b"plaintext-canary".as_slice(),
            &mut source_file,
            &[administrator_recipient],
        )?;
        source_file.sync_all()?;
        let cache = Cache::open(temporary.path().join("cache"))?;
        let target_id = Id::parse("host.web")?;
        let secret_id = Id::parse("db/password")?;
        let signing_key = ApprovalSigningKey::generate()?;
        let request = request(
            &source,
            &administrator_identity,
            &target_recipient,
            &target_id,
            &secret_id,
            &signing_key,
        );

        let created = rekey(&cache, &request)?;
        assert!(!created.reused);
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(
            File::open(&created.ciphertext_path)?,
            &mut plaintext,
            &target_identity,
        )?;
        assert_eq!(plaintext, b"plaintext-canary");
        let reused = rekey(&cache, &request)?;
        assert!(reused.reused);
        assert_eq!(created.cache_key, reused.cache_key);

        for entry in walk_regular_files(cache.root())? {
            let bytes = std::fs::read(entry)?;
            assert!(
                !bytes
                    .windows(b"plaintext-canary".len())
                    .any(|window| window == b"plaintext-canary")
            );
        }

        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&created.ciphertext_path)?;
        file.write_all(b"tampered ciphertext")?;
        file.sync_all()?;
        assert!(matches!(
            rekey(&cache, &request),
            Err(RekeyError::Manifest(ManifestError::Binding))
        ));
        Ok(())
    }

    #[test]
    fn direct_staging_never_decrypts_or_reencrypts_canonical_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("direct.age");
        let (target_identity, target_recipient) = nix_seal_crypto::generate_x25519();
        let mut source_file = File::create(&source)?;
        nix_seal_crypto::encrypt(
            b"direct-canary".as_slice(),
            &mut source_file,
            std::slice::from_ref(&target_recipient),
        )?;
        source_file.sync_all()?;
        let source_bytes = std::fs::read(&source)?;
        let cache = Cache::open(temporary.path().join("cache"))?;
        let target_id = Id::parse("host.direct")?;
        let secret_id = Id::parse("db/direct-password")?;
        let signing_key = ApprovalSigningKey::generate()?;
        let request = direct_request(
            &source,
            &target_recipient,
            &target_id,
            &secret_id,
            &signing_key,
        );

        let created = stage_direct(&cache, &request)?;
        assert!(!created.reused);
        assert_eq!(std::fs::read(&created.ciphertext_path)?, source_bytes);
        assert_eq!(
            created.source_ciphertext_hash,
            created.artifact_ciphertext_hash
        );
        let mut plaintext = Vec::new();
        nix_seal_crypto::decrypt(
            File::open(&created.ciphertext_path)?,
            &mut plaintext,
            &target_identity,
        )?;
        assert_eq!(plaintext, b"direct-canary");
        assert!(stage_direct(&cache, &request)?.reused);
        Ok(())
    }

    fn walk_regular_files(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut pending = vec![root.to_owned()];
        let mut files = Vec::new();
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file() {
                    files.push(entry.path());
                }
            }
        }
        Ok(files)
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_source() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir()?;
        let real = temporary.path().join("real.age");
        File::create(&real)?;
        let link = temporary.path().join("link.age");
        symlink(&real, &link)?;
        let (identity, recipient) = nix_seal_crypto::generate_x25519();
        let target_id = Id::parse("host.web")?;
        let secret_id = Id::parse("db/password")?;
        let signing_key = ApprovalSigningKey::generate()?;
        let cache = Cache::open(temporary.path().join("cache"))?;
        let request = request(
            &link,
            &identity,
            &recipient,
            &target_id,
            &secret_id,
            &signing_key,
        );
        assert!(matches!(
            rekey(&cache, &request),
            Err(RekeyError::UnsafeSource)
        ));
        Ok(())
    }

    #[test]
    fn failed_rekey_leaves_no_artifact_or_transaction_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("canonical.age");
        let (_administrator_identity, administrator_recipient) = nix_seal_crypto::generate_x25519();
        let (_target_identity, target_recipient) = nix_seal_crypto::generate_x25519();
        let mut source_file = File::create(&source)?;
        nix_seal_crypto::encrypt(
            b"plaintext-canary".as_slice(),
            &mut source_file,
            &[administrator_recipient],
        )?;
        source_file.sync_all()?;

        let cache = Cache::open(temporary.path().join("cache"))?;
        let invalid_identity = SecretString::from("not-an-age-identity".to_owned());
        let target_id = Id::parse("host.web")?;
        let secret_id = Id::parse("db/password")?;
        let signing_key = ApprovalSigningKey::generate()?;
        let request = request(
            &source,
            &invalid_identity,
            &target_recipient,
            &target_id,
            &secret_id,
            &signing_key,
        );

        assert!(matches!(
            rekey(&cache, &request),
            Err(RekeyError::Crypto(_))
        ));
        let artifacts = cache.root().join("artifacts");
        assert!(!artifacts.exists() || std::fs::read_dir(artifacts)?.next().is_none());
        assert!(
            std::fs::read_dir(cache.root().join("transactions"))?
                .next()
                .is_none()
        );
        Ok(())
    }
}

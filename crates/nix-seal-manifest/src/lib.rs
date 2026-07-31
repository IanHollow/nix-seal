#![forbid(unsafe_code)]
//! Strict target manifests and DSSE-style Ed25519 approval envelopes.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use nix_seal_core::Id;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Exact artifact schema accepted by this implementation.
pub const ARTIFACT_SCHEMA: &str = "nix-seal.artifact.v1";
/// DSSE payload type for target manifests.
pub const PAYLOAD_TYPE: &str = "application/vnd.nix-seal.target-manifest.v1+json";
/// On-disk private signing-key prefix.
pub const PRIVATE_KEY_PREFIX: &str = "NIX-SEAL-ED25519-PRIVATE-v1:";
/// Public verification-key prefix used in plans and files.
pub const PUBLIC_KEY_PREFIX: &str = "nix-seal-ed25519-v1:";
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 256;

/// Public metadata cryptographically bound to one target ciphertext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetManifestV1 {
    /// Must equal [`ARTIFACT_SCHEMA`].
    pub schema: String,
    /// Version of the tool that produced this artifact.
    pub tool_version: String,
    /// Hash of canonical `plan.v1.json`.
    pub plan_hash: String,
    /// Hash of the canonical administrator ciphertext.
    pub source_ciphertext_hash: String,
    /// Hash of the target ciphertext transported to activation.
    pub artifact_ciphertext_hash: String,
    /// Bound target identifier.
    pub target_id: Id,
    /// Bound secret identifier.
    pub secret_id: Id,
    /// Fingerprint of the intended target recipient.
    pub recipient_fingerprint: String,
    /// Monotonically selected artifact generation.
    pub artifact_generation: u64,
    /// Envelope issue time in Unix seconds.
    pub issued_at: u64,
    /// Optional expiry time in Unix seconds.
    pub expires_at: Option<u64>,
}

/// One signature entry in an envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvelopeSignature {
    /// Stable fingerprint of the signing key.
    pub key_id: String,
    /// Base64-encoded strict Ed25519 signature.
    pub signature: String,
}

/// DSSE-compatible JSON envelope containing a canonical manifest payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedEnvelopeV1 {
    /// Exact DSSE payload type.
    pub payload_type: String,
    /// Base64-encoded RFC 8785 canonical manifest JSON.
    pub payload: String,
    /// Distinct approval signatures.
    pub signatures: Vec<EnvelopeSignature>,
}

/// Private Ed25519 approval key whose bytes are zeroized on drop.
pub struct ApprovalSigningKey(SigningKey);

impl ApprovalSigningKey {
    /// Generates a key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, ManifestError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| ManifestError::Random)?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    /// Parses the versioned private-key encoding.
    pub fn parse(encoded: &str) -> Result<Self, ManifestError> {
        let value = encoded.trim();
        let body = value
            .strip_prefix(PRIVATE_KEY_PREFIX)
            .ok_or(ManifestError::PrivateKeyFormat)?;
        let mut decoded = Zeroizing::new(
            STANDARD
                .decode(body)
                .map_err(|_| ManifestError::PrivateKeyFormat)?,
        );
        let bytes = Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| ManifestError::PrivateKeyFormat)?,
        );
        decoded.zeroize();
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    /// Returns a versioned private-key encoding for initial persistence.
    #[must_use]
    pub fn encode_private(&self) -> Zeroizing<String> {
        let bytes = Zeroizing::new(self.0.to_bytes());
        Zeroizing::new(format!(
            "{PRIVATE_KEY_PREFIX}{}",
            STANDARD.encode(bytes.as_slice())
        ))
    }

    /// Returns the public key encoding.
    #[must_use]
    pub fn encode_public(&self) -> String {
        encode_public_key(&self.0.verifying_key())
    }

    /// Returns the stable public key identifier.
    #[must_use]
    pub fn key_id(&self) -> String {
        key_id(&self.0.verifying_key())
    }
}

/// Exact public binding expected by an activation or verification caller.
#[derive(Clone, Debug)]
pub struct ExpectedBinding<'a> {
    /// Expected producer tool version.
    pub tool_version: &'a str,
    /// Expected plan hash.
    pub plan_hash: &'a str,
    /// Expected canonical source hash.
    pub source_ciphertext_hash: &'a str,
    /// Hash freshly calculated from transported artifact bytes.
    pub artifact_ciphertext_hash: &'a str,
    /// Locally configured target.
    pub target_id: &'a Id,
    /// Locally configured secret.
    pub secret_id: &'a Id,
    /// Locally configured recipient fingerprint.
    pub recipient_fingerprint: &'a str,
    /// Exact expected generation; older and newer envelopes are rejected.
    pub artifact_generation: u64,
    /// Current wall-clock time in Unix seconds.
    pub now: u64,
    /// Maximum accepted clock lead for `issuedAt`.
    pub allowed_clock_skew: u64,
}

/// A successfully authenticated manifest and its distinct valid signers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    /// Authenticated payload.
    pub manifest: TargetManifestV1,
    /// Trusted key IDs that supplied valid signatures.
    pub signers: BTreeSet<String>,
}

/// Explicit set of trusted approval verification keys.
#[derive(Default)]
pub struct TrustedKeys(BTreeMap<String, VerifyingKey>);

impl TrustedKeys {
    /// Creates an empty trust set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses and inserts one public key, rejecting duplicates.
    pub fn insert_encoded(&mut self, encoded: &str) -> Result<String, ManifestError> {
        let key = parse_public_key(encoded)?;
        let id = key_id(&key);
        if self.0.insert(id.clone(), key).is_some() {
            return Err(ManifestError::DuplicateTrustedKey);
        }
        Ok(id)
    }

    /// Returns the number of distinct trusted keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether no keys are trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Redacted manifest/signature failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ManifestError {
    /// Operating-system random generation failed.
    #[error("operating-system random generation failed")]
    Random,
    /// Private key input is malformed.
    #[error("invalid private approval key")]
    PrivateKeyFormat,
    /// Public key input is malformed.
    #[error("invalid public approval key")]
    PublicKeyFormat,
    /// JSON or canonicalization failed.
    #[error("invalid artifact envelope JSON")]
    Json,
    /// Payload is the wrong type or schema.
    #[error("unsupported artifact envelope version")]
    Version,
    /// Payload exceeds the public metadata safety bound.
    #[error("artifact manifest exceeds safety limits")]
    Limit,
    /// Manifest timing metadata is invalid.
    #[error("artifact approval is expired or not yet valid")]
    Time,
    /// A local expected binding differs from the signed value.
    #[error("artifact binding does not match local policy")]
    Binding,
    /// Threshold is invalid or unmet.
    #[error("artifact approval threshold is not satisfied")]
    Threshold,
    /// Duplicate signer is prohibited even if its signature repeats.
    #[error("artifact contains duplicate signer IDs")]
    DuplicateSigner,
    /// An envelope contains a signer outside the explicit trust set.
    #[error("artifact contains an untrusted signer")]
    UntrustedSigner,
    /// The same public key was configured more than once.
    #[error("duplicate trusted approval key")]
    DuplicateTrustedKey,
    /// A signature is malformed or invalid.
    #[error("artifact contains an invalid signature")]
    InvalidSignature,
}

fn parse_public_key(encoded: &str) -> Result<VerifyingKey, ManifestError> {
    let body = encoded
        .trim()
        .strip_prefix(PUBLIC_KEY_PREFIX)
        .ok_or(ManifestError::PublicKeyFormat)?;
    let decoded = STANDARD
        .decode(body)
        .map_err(|_| ManifestError::PublicKeyFormat)?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| ManifestError::PublicKeyFormat)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ManifestError::PublicKeyFormat)
}

fn encode_public_key(key: &VerifyingKey) -> String {
    format!("{PUBLIC_KEY_PREFIX}{}", STANDARD.encode(key.as_bytes()))
}

fn key_id(key: &VerifyingKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nix-seal.ed25519-key-id.v1\0");
    hasher.update(key.as_bytes());
    format!("ed25519:{}", hasher.finalize().to_hex())
}

/// Creates an envelope with one signature.
pub fn sign_manifest(
    manifest: &TargetManifestV1,
    key: &ApprovalSigningKey,
) -> Result<SignedEnvelopeV1, ManifestError> {
    validate_manifest_structure(manifest)?;
    let payload = serde_jcs::to_vec(manifest).map_err(|_| ManifestError::Json)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ManifestError::Limit);
    }
    let message = pae(PAYLOAD_TYPE.as_bytes(), &payload)?;
    let signature = key.0.sign(&message);
    Ok(SignedEnvelopeV1 {
        payload_type: PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![EnvelopeSignature {
            key_id: key.key_id(),
            signature: STANDARD.encode(signature.to_bytes()),
        }],
    })
}

/// Adds one distinct approval signature without changing the payload.
pub fn add_signature(
    envelope: &mut SignedEnvelopeV1,
    key: &ApprovalSigningKey,
) -> Result<(), ManifestError> {
    let (_, payload, message) = decode_envelope(envelope)?;
    if envelope.signatures.len() >= MAX_SIGNATURES {
        return Err(ManifestError::Limit);
    }
    let id = key.key_id();
    if envelope.signatures.iter().any(|entry| entry.key_id == id) {
        return Err(ManifestError::DuplicateSigner);
    }
    let signature = key.0.sign(&message);
    envelope.signatures.push(EnvelopeSignature {
        key_id: id,
        signature: STANDARD.encode(signature.to_bytes()),
    });
    // Ensure the decoded canonical payload is retained and no alternate base64 is propagated.
    envelope.payload = STANDARD.encode(payload);
    Ok(())
}

/// Verifies strict bindings, timing, trust, distinct signatures, and threshold.
pub fn verify(
    envelope: &SignedEnvelopeV1,
    trusted_keys: &TrustedKeys,
    threshold: usize,
    expected: &ExpectedBinding<'_>,
) -> Result<VerifiedManifest, ManifestError> {
    if threshold == 0 || threshold > trusted_keys.len() || envelope.signatures.is_empty() {
        return Err(ManifestError::Threshold);
    }
    let (manifest, _, message) = decode_envelope(envelope)?;
    validate_expected(&manifest, expected)?;
    let mut signers = BTreeSet::new();
    for entry in &envelope.signatures {
        if !signers.insert(entry.key_id.clone()) {
            return Err(ManifestError::DuplicateSigner);
        }
        let key = trusted_keys
            .0
            .get(&entry.key_id)
            .ok_or(ManifestError::UntrustedSigner)?;
        let bytes = STANDARD
            .decode(&entry.signature)
            .map_err(|_| ManifestError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&bytes).map_err(|_| ManifestError::InvalidSignature)?;
        key.verify_strict(&message, &signature)
            .map_err(|_| ManifestError::InvalidSignature)?;
    }
    if signers.len() < threshold {
        return Err(ManifestError::Threshold);
    }
    Ok(VerifiedManifest { manifest, signers })
}

fn decode_envelope(
    envelope: &SignedEnvelopeV1,
) -> Result<(TargetManifestV1, Vec<u8>, Vec<u8>), ManifestError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(ManifestError::Version);
    }
    if envelope.signatures.len() > MAX_SIGNATURES {
        return Err(ManifestError::Limit);
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| ManifestError::Json)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ManifestError::Limit);
    }
    let manifest: TargetManifestV1 =
        serde_json::from_slice(&payload).map_err(|_| ManifestError::Json)?;
    validate_manifest_structure(&manifest)?;
    let canonical = serde_jcs::to_vec(&manifest).map_err(|_| ManifestError::Json)?;
    if canonical != payload {
        return Err(ManifestError::Json);
    }
    let message = pae(envelope.payload_type.as_bytes(), &payload)?;
    Ok((manifest, payload, message))
}

fn validate_manifest_structure(manifest: &TargetManifestV1) -> Result<(), ManifestError> {
    if manifest.schema != ARTIFACT_SCHEMA || manifest.tool_version.is_empty() {
        return Err(ManifestError::Version);
    }
    if !is_digest(&manifest.plan_hash)
        || !is_digest(&manifest.source_ciphertext_hash)
        || !is_digest(&manifest.artifact_ciphertext_hash)
        || !is_digest(&manifest.recipient_fingerprint)
        || manifest.artifact_generation == 0
    {
        return Err(ManifestError::Binding);
    }
    if manifest
        .expires_at
        .is_some_and(|expiry| expiry <= manifest.issued_at)
    {
        return Err(ManifestError::Time);
    }
    Ok(())
}

fn validate_expected(
    manifest: &TargetManifestV1,
    expected: &ExpectedBinding<'_>,
) -> Result<(), ManifestError> {
    let latest_issued = expected
        .now
        .checked_add(expected.allowed_clock_skew)
        .ok_or(ManifestError::Time)?;
    if manifest.issued_at > latest_issued
        || manifest
            .expires_at
            .is_some_and(|expiry| expected.now >= expiry)
    {
        return Err(ManifestError::Time);
    }
    if manifest.tool_version != expected.tool_version
        || manifest.plan_hash != expected.plan_hash
        || manifest.source_ciphertext_hash != expected.source_ciphertext_hash
        || manifest.artifact_ciphertext_hash != expected.artifact_ciphertext_hash
        || &manifest.target_id != expected.target_id
        || &manifest.secret_id != expected.secret_id
        || manifest.recipient_fingerprint != expected.recipient_fingerprint
        || manifest.artifact_generation != expected.artifact_generation
    {
        return Err(ManifestError::Binding);
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn pae(payload_type: &[u8], payload: &[u8]) -> Result<Vec<u8>, ManifestError> {
    let type_len = payload_type.len().to_string();
    let payload_len = payload.len().to_string();
    let capacity = 10_usize
        .checked_add(type_len.len())
        .and_then(|n| n.checked_add(payload_type.len()))
        .and_then(|n| n.checked_add(payload_len.len()))
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(ManifestError::Limit)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(b"DSSEv1 ");
    output.extend_from_slice(type_len.as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload_type);
    output.push(b' ');
    output.extend_from_slice(payload_len.as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> TargetManifestV1 {
        let digest = "0".repeat(64);
        TargetManifestV1 {
            schema: ARTIFACT_SCHEMA.to_owned(),
            tool_version: "0.1.0-alpha.1".to_owned(),
            plan_hash: digest.clone(),
            source_ciphertext_hash: digest.clone(),
            artifact_ciphertext_hash: digest.clone(),
            target_id: Id::parse("host.web").unwrap_or_else(|error| unreachable!("{error}")),
            secret_id: Id::parse("db/password").unwrap_or_else(|error| unreachable!("{error}")),
            recipient_fingerprint: digest,
            artifact_generation: 7,
            issued_at: 100,
            expires_at: Some(200),
        }
    }

    fn expected(manifest: &TargetManifestV1) -> ExpectedBinding<'_> {
        ExpectedBinding {
            tool_version: &manifest.tool_version,
            plan_hash: &manifest.plan_hash,
            source_ciphertext_hash: &manifest.source_ciphertext_hash,
            artifact_ciphertext_hash: &manifest.artifact_ciphertext_hash,
            target_id: &manifest.target_id,
            secret_id: &manifest.secret_id,
            recipient_fingerprint: &manifest.recipient_fingerprint,
            artifact_generation: manifest.artifact_generation,
            now: 150,
            allowed_clock_skew: 0,
        }
    }

    fn trust(keys: &[&ApprovalSigningKey]) -> TrustedKeys {
        let mut trusted = TrustedKeys::new();
        for key in keys {
            trusted
                .insert_encoded(&key.encode_public())
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        trusted
    }

    #[test]
    fn verifies_distinct_threshold_signatures() {
        let one = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let two = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let mut envelope =
            sign_manifest(&manifest, &one).unwrap_or_else(|error| unreachable!("{error}"));
        add_signature(&mut envelope, &two).unwrap_or_else(|error| unreachable!("{error}"));
        let verified = verify(&envelope, &trust(&[&one, &two]), 2, &expected(&manifest))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.signers.len(), 2);
    }

    #[test]
    fn rejects_replay_target_substitution_expiry_and_downgrade() {
        let key = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let envelope =
            sign_manifest(&manifest, &key).unwrap_or_else(|error| unreachable!("{error}"));
        let trusted = trust(&[&key]);

        let mut replay = expected(&manifest);
        replay.artifact_generation = 8;
        assert_eq!(
            verify(&envelope, &trusted, 1, &replay),
            Err(ManifestError::Binding)
        );

        let other = Id::parse("host.other").unwrap_or_else(|error| unreachable!("{error}"));
        let mut substituted = expected(&manifest);
        substituted.target_id = &other;
        assert_eq!(
            verify(&envelope, &trusted, 1, &substituted),
            Err(ManifestError::Binding)
        );

        let mut expired = expected(&manifest);
        expired.now = 200;
        assert_eq!(
            verify(&envelope, &trusted, 1, &expired),
            Err(ManifestError::Time)
        );

        let mut downgraded = envelope.clone();
        downgraded.payload_type = "application/vnd.nix-seal.target-manifest.v0+json".to_owned();
        assert_eq!(
            verify(&downgraded, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::Version)
        );

        let old = TargetManifestV1 {
            tool_version: "0.0.1".to_owned(),
            ..manifest.clone()
        };
        let old_envelope =
            sign_manifest(&old, &key).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            verify(&old_envelope, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::Binding)
        );
    }

    #[test]
    fn rejects_duplicate_untrusted_and_tampered_signatures() {
        let key = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let outsider =
            ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let envelope =
            sign_manifest(&manifest, &key).unwrap_or_else(|error| unreachable!("{error}"));
        let trusted = trust(&[&key]);

        let mut duplicate = envelope.clone();
        duplicate.signatures.push(duplicate.signatures[0].clone());
        assert_eq!(
            verify(&duplicate, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::DuplicateSigner)
        );

        let outsider_envelope =
            sign_manifest(&manifest, &outsider).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            verify(&outsider_envelope, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::UntrustedSigner)
        );

        let mut tampered = envelope;
        tampered.signatures[0].signature = STANDARD.encode([0_u8; 64]);
        assert_eq!(
            verify(&tampered, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::InvalidSignature)
        );

        assert_eq!(
            verify(
                &sign_manifest(&manifest, &key).unwrap_or_else(|error| unreachable!("{error}")),
                &trust(&[&key, &outsider]),
                2,
                &expected(&manifest)
            ),
            Err(ManifestError::Threshold)
        );
    }

    #[test]
    fn rejects_noncanonical_and_unknown_manifest_fields() {
        let key = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let envelope =
            sign_manifest(&manifest, &key).unwrap_or_else(|error| unreachable!("{error}"));
        let payload = STANDARD
            .decode(&envelope.payload)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let pretty: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|error| unreachable!("{error}"));
        let mut noncanonical = envelope.clone();
        noncanonical.payload = STANDARD.encode(
            serde_json::to_vec_pretty(&pretty).unwrap_or_else(|error| unreachable!("{error}")),
        );
        assert_eq!(
            verify(&noncanonical, &trust(&[&key]), 1, &expected(&manifest)),
            Err(ManifestError::Json)
        );

        let mut object = pretty
            .as_object()
            .cloned()
            .unwrap_or_else(|| unreachable!("manifest is an object"));
        object.insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        let mut unknown = envelope;
        unknown.payload = STANDARD
            .encode(serde_jcs::to_vec(&object).unwrap_or_else(|error| unreachable!("{error}")));
        assert_eq!(
            verify(&unknown, &trust(&[&key]), 1, &expected(&manifest)),
            Err(ManifestError::Json)
        );
    }

    #[test]
    fn private_encoding_round_trips_without_debug_exposure() {
        let key = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let encoded = key.encode_private();
        let reparsed =
            ApprovalSigningKey::parse(&encoded).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(key.encode_public(), reparsed.encode_public());
    }
}

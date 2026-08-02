#![forbid(unsafe_code)]
//! Strict target manifests and DSSE-style Ed25519 approval envelopes.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use nix_seal_core::Id;
use serde::{Deserialize, Serialize};
use ssh_key::{
    Algorithm as SshAlgorithm, HashAlg, LineEnding, PrivateKey as SshPrivateKey,
    PublicKey as SshPublicKey, Signature as SshSignature, SshSig,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Exact artifact schema accepted by this implementation.
pub const ARTIFACT_SCHEMA: &str = "nix-seal.artifact.v2";
/// DSSE payload type for target manifests.
pub const PAYLOAD_TYPE: &str = "application/vnd.nix-seal.target-manifest.v2+json";
/// On-disk private signing-key prefix.
pub const PRIVATE_KEY_PREFIX: &str = "NIX-SEAL-ED25519-PRIVATE-v1:";
/// Public verification-key prefix used in plans and files.
pub const PUBLIC_KEY_PREFIX: &str = "nix-seal-ed25519-v1:";
/// Explicit signing-key file prefix for a local SSH-agent-backed Ed25519 key.
pub const SSH_AGENT_KEY_PREFIX: &str = "NIX-SEAL-SSH-AGENT-ED25519-v1:";
const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 32 * 1024;
const MAX_AGENT_MESSAGE_BYTES: usize = 1024 * 1024;
const AGENT_REQUEST_SIGN: u8 = 13;
const AGENT_FAILURE: u8 = 5;
const AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_SIGNATURE_NAMESPACE: &str = "nix-seal-artifact-v2";

/// Public metadata cryptographically bound to one target ciphertext.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetManifestV2 {
    /// Must equal [`ARTIFACT_SCHEMA`].
    pub schema: String,
    /// Version of the tool that produced this artifact.
    pub tool_version: String,
    /// Hash of canonical `plan.v1.json`.
    pub plan_hash: String,
    /// Hash of the deterministic target policy derived from that exact plan.
    pub target_policy_hash: String,
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
    /// Versioned signature encoding. Omitted fields in legacy envelopes are
    /// strict native Ed25519 signatures.
    #[serde(default, skip_serializing_if = "is_native_ed25519_signature")]
    pub algorithm: ApprovalSignatureAlgorithm,
    /// Base64-encoded native signature or PEM-encoded OpenSSH `sshsig`.
    pub signature: String,
}

/// The public signature representation carried by an approval envelope.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalSignatureAlgorithm {
    /// The project's compact native Ed25519 representation.
    #[default]
    Ed25519V1,
    /// An OpenSSH Ed25519 `sshsig` envelope under the nix-seal namespace.
    SshEd25519SshsigV1,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // required by serde's `skip_serializing_if` callback.
fn is_native_ed25519_signature(algorithm: &ApprovalSignatureAlgorithm) -> bool {
    *algorithm == ApprovalSignatureAlgorithm::Ed25519V1
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

/// Private approval key whose secret material is zeroized on drop.
///
/// Native keys are encoded with [`PRIVATE_KEY_PREFIX`]. OpenSSH input is
/// restricted to an unencrypted `ssh-ed25519` private key or an explicitly
/// selected local SSH-agent `ssh-ed25519` public key. FIDO and other SSH
/// algorithms remain rejected until their protocols have a dedicated security
/// review.
pub enum ApprovalSigningKey {
    /// Project-native Ed25519 signing key.
    Ed25519(SigningKey),
    /// Interoperable OpenSSH Ed25519 signing key.
    SshEd25519(SshPrivateKey),
    /// Ed25519 key whose private operation is delegated to a local SSH agent.
    #[cfg(unix)]
    SshAgentEd25519 {
        /// Public key used to select the agent identity and verify its output.
        public_key: SshPublicKey,
        /// Absolute Unix-domain socket path supplied by `SSH_AUTH_SOCK`.
        socket: PathBuf,
    },
}

impl ApprovalSigningKey {
    /// Generates a key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, ManifestError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| ManifestError::Random)?;
        Ok(Self::Ed25519(SigningKey::from_bytes(&bytes)))
    }

    /// Parses a native key or an unencrypted OpenSSH Ed25519 private key.
    pub fn parse(encoded: &str) -> Result<Self, ManifestError> {
        let value = encoded.trim();
        if let Some(body) = value.strip_prefix(PRIVATE_KEY_PREFIX) {
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
            return Ok(Self::Ed25519(SigningKey::from_bytes(&bytes)));
        }

        let key = SshPrivateKey::from_openssh(value.as_bytes())
            .map_err(|_| ManifestError::PrivateKeyFormat)?;
        if key.is_encrypted() || key.algorithm() != SshAlgorithm::Ed25519 {
            return Err(ManifestError::PrivateKeyFormat);
        }
        Ok(Self::SshEd25519(key))
    }

    /// Parses a file-backed key or the explicit SSH-agent key format.
    ///
    /// Agent use is never inferred from `SSH_AUTH_SOCK`: callers must place
    /// [`SSH_AGENT_KEY_PREFIX`] in the selected key file. This prevents a
    /// silently changed environment from redirecting an approval operation to
    /// a different private key. The socket path is validated but not opened
    /// until the signature operation.
    pub fn parse_with_agent(encoded: &str, socket: &Path) -> Result<Self, ManifestError> {
        let value = encoded.trim();
        if let Some(body) = value.strip_prefix(SSH_AGENT_KEY_PREFIX) {
            #[cfg(unix)]
            {
                let socket = validate_agent_socket(socket)?;
                let public_key = parse_ssh_public_key(body)?;
                return Ok(Self::SshAgentEd25519 { public_key, socket });
            }
            #[cfg(not(unix))]
            {
                let _ = (body, socket);
                return Err(ManifestError::AgentUnavailable);
            }
        }
        Self::parse(value)
    }

    /// Returns a versioned native private-key encoding for initial persistence.
    ///
    /// Imported SSH private keys are never re-encoded or written by nix-seal.
    pub fn encode_private(&self) -> Result<Zeroizing<String>, ManifestError> {
        match self {
            Self::Ed25519(key) => {
                let bytes = Zeroizing::new(key.to_bytes());
                Ok(Zeroizing::new(format!(
                    "{PRIVATE_KEY_PREFIX}{}",
                    STANDARD.encode(bytes.as_slice())
                )))
            }
            Self::SshEd25519(_) => Err(ManifestError::PrivateKeyFormat),
            #[cfg(unix)]
            Self::SshAgentEd25519 { .. } => Err(ManifestError::PrivateKeyFormat),
        }
    }

    /// Returns the public key encoding.
    pub fn encode_public(&self) -> Result<String, ManifestError> {
        match self {
            Self::Ed25519(key) => Ok(encode_public_key(&key.verifying_key())),
            Self::SshEd25519(key) => normalize_ssh_public_key(key.public_key()),
            #[cfg(unix)]
            Self::SshAgentEd25519 { public_key, .. } => normalize_ssh_public_key(public_key),
        }
    }

    /// Returns the stable public key identifier.
    pub fn key_id(&self) -> Result<String, ManifestError> {
        match self {
            Self::Ed25519(key) => Ok(native_key_id(&key.verifying_key())),
            Self::SshEd25519(key) => ssh_key_id(key.public_key()),
            #[cfg(unix)]
            Self::SshAgentEd25519 { public_key, .. } => ssh_key_id(public_key),
        }
    }

    /// Returns whether this key matches one configured public approval key.
    #[must_use]
    pub fn matches_public_key(&self, encoded: &str) -> bool {
        let Ok(signing_key_id) = self.key_id() else {
            return false;
        };
        parse_public_key(encoded)
            .is_ok_and(|key| key.key_id().is_ok_and(|key_id| key_id == signing_key_id))
    }

    fn sign(&self, message: &[u8]) -> Result<EnvelopeSignature, ManifestError> {
        match self {
            Self::Ed25519(key) => {
                let signature = key.sign(message);
                Ok(EnvelopeSignature {
                    key_id: native_key_id(&key.verifying_key()),
                    algorithm: ApprovalSignatureAlgorithm::Ed25519V1,
                    signature: STANDARD.encode(signature.to_bytes()),
                })
            }
            Self::SshEd25519(key) => {
                let signature = key
                    .sign(SSH_SIGNATURE_NAMESPACE, HashAlg::Sha512, message)
                    .map_err(|_| ManifestError::InvalidSignature)?
                    .to_pem(LineEnding::LF)
                    .map_err(|_| ManifestError::InvalidSignature)?;
                if signature.len() > MAX_SIGNATURE_BYTES {
                    return Err(ManifestError::Limit);
                }
                Ok(EnvelopeSignature {
                    key_id: ssh_key_id(key.public_key())?,
                    algorithm: ApprovalSignatureAlgorithm::SshEd25519SshsigV1,
                    signature,
                })
            }
            #[cfg(unix)]
            Self::SshAgentEd25519 { public_key, socket } => {
                let signed_data =
                    SshSig::signed_data(SSH_SIGNATURE_NAMESPACE, HashAlg::Sha512, message)
                        .map_err(|_| ManifestError::InvalidSignature)?;
                let key_blob = public_key
                    .to_bytes()
                    .map_err(|_| ManifestError::InvalidSignature)?;
                let signature = ssh_agent_sign(socket, &key_blob, &signed_data)?;
                if signature.algorithm() != SshAlgorithm::Ed25519 {
                    return Err(ManifestError::AgentProtocol);
                }
                let sshsig = SshSig::new(
                    public_key.key_data().clone(),
                    SSH_SIGNATURE_NAMESPACE,
                    HashAlg::Sha512,
                    signature,
                )
                .map_err(|_| ManifestError::InvalidSignature)?;
                let encoded = sshsig
                    .to_pem(LineEnding::LF)
                    .map_err(|_| ManifestError::InvalidSignature)?;
                if encoded.len() > MAX_SIGNATURE_BYTES {
                    return Err(ManifestError::Limit);
                }
                Ok(EnvelopeSignature {
                    key_id: ssh_key_id(public_key)?,
                    algorithm: ApprovalSignatureAlgorithm::SshEd25519SshsigV1,
                    signature: encoded,
                })
            }
        }
    }
}

/// Exact public binding expected by an activation or verification caller.
#[derive(Clone, Debug)]
pub struct ExpectedBinding<'a> {
    /// Expected producer tool version.
    pub tool_version: &'a str,
    /// Expected plan hash.
    pub plan_hash: &'a str,
    /// Expected deterministic target policy hash.
    pub target_policy_hash: &'a str,
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
    pub manifest: TargetManifestV2,
    /// Trusted key IDs that supplied valid signatures.
    pub signers: BTreeSet<String>,
}

/// Explicit set of trusted approval verification keys.
#[derive(Default)]
pub struct TrustedKeys(BTreeMap<String, ApprovalVerificationKey>);

enum ApprovalVerificationKey {
    /// Project-native Ed25519 verifier.
    Ed25519(VerifyingKey),
    /// Interoperable OpenSSH Ed25519 verifier.
    SshEd25519(SshPublicKey),
}

impl ApprovalVerificationKey {
    fn key_id(&self) -> Result<String, ManifestError> {
        match self {
            Self::Ed25519(key) => Ok(native_key_id(key)),
            Self::SshEd25519(key) => ssh_key_id(key),
        }
    }
}

impl TrustedKeys {
    /// Creates an empty trust set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses and inserts one public key, rejecting duplicates.
    pub fn insert_encoded(&mut self, encoded: &str) -> Result<String, ManifestError> {
        let key = parse_public_key(encoded)?;
        let id = key.key_id()?;
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
    /// The configured SSH-agent socket is unavailable or cannot be used.
    #[error("SSH agent is unavailable")]
    AgentUnavailable,
    /// The SSH-agent rejected the signing request.
    #[error("SSH agent rejected the signing request")]
    AgentRejected,
    /// The SSH-agent response was malformed or used an unsupported algorithm.
    #[error("SSH agent protocol response is invalid")]
    AgentProtocol,
}

fn parse_ssh_public_key(encoded: &str) -> Result<SshPublicKey, ManifestError> {
    let key =
        SshPublicKey::from_openssh(encoded.trim()).map_err(|_| ManifestError::PublicKeyFormat)?;
    if key.algorithm() != SshAlgorithm::Ed25519 {
        return Err(ManifestError::PublicKeyFormat);
    }
    Ok(key)
}

#[cfg(unix)]
fn validate_agent_socket(socket: &Path) -> Result<PathBuf, ManifestError> {
    if !socket.is_absolute()
        || socket.as_os_str().len() > 4096
        || socket
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(u8::is_ascii_control)
    {
        return Err(ManifestError::AgentUnavailable);
    }
    Ok(socket.to_owned())
}

#[cfg(unix)]
fn ssh_agent_sign(
    socket: &Path,
    key_blob: &[u8],
    data: &[u8],
) -> Result<SshSignature, ManifestError> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    let body_len = 1_usize
        .checked_add(4)
        .and_then(|length| length.checked_add(key_blob.len()))
        .and_then(|length| length.checked_add(4))
        .and_then(|length| length.checked_add(data.len()))
        .and_then(|length| length.checked_add(4))
        .ok_or(ManifestError::AgentProtocol)?;
    if body_len > MAX_AGENT_MESSAGE_BYTES {
        return Err(ManifestError::Limit);
    }
    let body_len = u32::try_from(body_len).map_err(|_| ManifestError::Limit)?;
    let key_len = u32::try_from(key_blob.len()).map_err(|_| ManifestError::Limit)?;
    let data_len = u32::try_from(data.len()).map_err(|_| ManifestError::Limit)?;
    let mut request = Vec::with_capacity(4 + body_len as usize);
    request.extend_from_slice(&body_len.to_be_bytes());
    request.push(AGENT_REQUEST_SIGN);
    request.extend_from_slice(&key_len.to_be_bytes());
    request.extend_from_slice(key_blob);
    request.extend_from_slice(&data_len.to_be_bytes());
    request.extend_from_slice(data);
    request.extend_from_slice(&0_u32.to_be_bytes());

    let mut stream = UnixStream::connect(socket).map_err(|_| ManifestError::AgentUnavailable)?;
    let timeout = Duration::from_secs(10);
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| ManifestError::AgentUnavailable)?;
    stream
        .write_all(&request)
        .and_then(|()| stream.flush())
        .map_err(|_| ManifestError::AgentUnavailable)?;

    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| ManifestError::AgentUnavailable)?;
    let response_len =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| ManifestError::AgentProtocol)?;
    if response_len == 0 || response_len > MAX_AGENT_MESSAGE_BYTES {
        return Err(ManifestError::AgentProtocol);
    }
    let mut response = vec![0_u8; response_len];
    stream
        .read_exact(&mut response)
        .map_err(|_| ManifestError::AgentUnavailable)?;
    if response[0] == AGENT_FAILURE {
        return Err(ManifestError::AgentRejected);
    }
    if response[0] != AGENT_SIGN_RESPONSE {
        return Err(ManifestError::AgentProtocol);
    }
    let (signature_bytes, rest) = read_agent_string(&response[1..])?;
    if !rest.is_empty() {
        return Err(ManifestError::AgentProtocol);
    }
    SshSignature::try_from(signature_bytes).map_err(|_| ManifestError::AgentProtocol)
}

#[cfg(unix)]
fn read_agent_string(input: &[u8]) -> Result<(&[u8], &[u8]), ManifestError> {
    if input.len() < 4 {
        return Err(ManifestError::AgentProtocol);
    }
    let length = usize::try_from(u32::from_be_bytes(
        input[..4]
            .try_into()
            .map_err(|_| ManifestError::AgentProtocol)?,
    ))
    .map_err(|_| ManifestError::AgentProtocol)?;
    let end = 4_usize
        .checked_add(length)
        .ok_or(ManifestError::AgentProtocol)?;
    if end > input.len() {
        return Err(ManifestError::AgentProtocol);
    }
    Ok((&input[4..end], &input[end..]))
}

fn parse_public_key(encoded: &str) -> Result<ApprovalVerificationKey, ManifestError> {
    let value = encoded.trim();
    if let Some(body) = value.strip_prefix(PUBLIC_KEY_PREFIX) {
        let decoded = STANDARD
            .decode(body)
            .map_err(|_| ManifestError::PublicKeyFormat)?;
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| ManifestError::PublicKeyFormat)?;
        return VerifyingKey::from_bytes(&bytes)
            .map(ApprovalVerificationKey::Ed25519)
            .map_err(|_| ManifestError::PublicKeyFormat);
    }

    let key = SshPublicKey::from_openssh(value).map_err(|_| ManifestError::PublicKeyFormat)?;
    if key.algorithm() != SshAlgorithm::Ed25519 {
        return Err(ManifestError::PublicKeyFormat);
    }
    Ok(ApprovalVerificationKey::SshEd25519(key))
}

/// Validates one versioned public approval verification key without retaining it.
pub fn validate_public_key(encoded: &str) -> Result<(), ManifestError> {
    let _ = parse_public_key(encoded)?;
    Ok(())
}

/// Returns the stable, comment-independent identifier of one approval key.
///
/// Policy code uses this identifier to reject the same OpenSSH public key
/// declared under multiple identity IDs with different comments.
pub fn public_key_id(encoded: &str) -> Result<String, ManifestError> {
    parse_public_key(encoded)?.key_id()
}

fn encode_public_key(key: &VerifyingKey) -> String {
    format!("{PUBLIC_KEY_PREFIX}{}", STANDARD.encode(key.as_bytes()))
}

fn native_key_id(key: &VerifyingKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nix-seal.ed25519-key-id.v1\0");
    hasher.update(key.as_bytes());
    format!("ed25519:{}", hasher.finalize().to_hex())
}

fn normalize_ssh_public_key(key: &SshPublicKey) -> Result<String, ManifestError> {
    let encoded = key
        .to_openssh()
        .map_err(|_| ManifestError::PublicKeyFormat)?;
    let mut fields = encoded.split_ascii_whitespace();
    let algorithm = fields.next().ok_or(ManifestError::PublicKeyFormat)?;
    let body = fields.next().ok_or(ManifestError::PublicKeyFormat)?;
    if algorithm != "ssh-ed25519" {
        return Err(ManifestError::PublicKeyFormat);
    }
    Ok(format!("{algorithm} {body}"))
}

fn ssh_key_id(key: &SshPublicKey) -> Result<String, ManifestError> {
    let encoded = normalize_ssh_public_key(key)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nix-seal.ssh-ed25519-key-id.v1\0");
    hasher.update(encoded.as_bytes());
    Ok(format!("ssh-ed25519:{}", hasher.finalize().to_hex()))
}

/// Creates an envelope with one signature.
pub fn sign_manifest(
    manifest: &TargetManifestV2,
    key: &ApprovalSigningKey,
) -> Result<SignedEnvelopeV1, ManifestError> {
    validate_manifest_structure(manifest)?;
    let payload = serde_jcs::to_vec(manifest).map_err(|_| ManifestError::Json)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ManifestError::Limit);
    }
    let message = pae(PAYLOAD_TYPE.as_bytes(), &payload)?;
    Ok(SignedEnvelopeV1 {
        payload_type: PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![key.sign(&message)?],
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
    let signature = key.sign(&message)?;
    let id = signature.key_id.clone();
    if envelope.signatures.iter().any(|entry| entry.key_id == id) {
        return Err(ManifestError::DuplicateSigner);
    }
    envelope.signatures.push(signature);
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
        match (entry.algorithm, key) {
            (ApprovalSignatureAlgorithm::Ed25519V1, ApprovalVerificationKey::Ed25519(key)) => {
                let bytes = STANDARD
                    .decode(&entry.signature)
                    .map_err(|_| ManifestError::InvalidSignature)?;
                let signature =
                    Signature::from_slice(&bytes).map_err(|_| ManifestError::InvalidSignature)?;
                key.verify_strict(&message, &signature)
                    .map_err(|_| ManifestError::InvalidSignature)?;
            }
            (
                ApprovalSignatureAlgorithm::SshEd25519SshsigV1,
                ApprovalVerificationKey::SshEd25519(key),
            ) => {
                let signature = SshSig::from_pem(entry.signature.as_bytes())
                    .map_err(|_| ManifestError::InvalidSignature)?;
                if signature.algorithm() != SshAlgorithm::Ed25519 {
                    return Err(ManifestError::InvalidSignature);
                }
                key.verify(SSH_SIGNATURE_NAMESPACE, &message, &signature)
                    .map_err(|_| ManifestError::InvalidSignature)?;
            }
            _ => return Err(ManifestError::InvalidSignature),
        }
    }
    if signers.len() < threshold {
        return Err(ManifestError::Threshold);
    }
    Ok(VerifiedManifest { manifest, signers })
}

/// Parses a strict canonical target manifest without asserting any signature trust.
///
/// This is intended for inventory and retention decisions only. Call [`verify`]
/// before using the returned metadata as an authorization decision.
pub fn inspect_unverified(envelope: &SignedEnvelopeV1) -> Result<TargetManifestV2, ManifestError> {
    decode_envelope(envelope).map(|(manifest, _, _)| manifest)
}

fn decode_envelope(
    envelope: &SignedEnvelopeV1,
) -> Result<(TargetManifestV2, Vec<u8>, Vec<u8>), ManifestError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(ManifestError::Version);
    }
    if envelope.signatures.len() > MAX_SIGNATURES {
        return Err(ManifestError::Limit);
    }
    if envelope.signatures.iter().any(|signature| {
        signature.key_id.is_empty() || signature.signature.len() > MAX_SIGNATURE_BYTES
    }) {
        return Err(ManifestError::Limit);
    }
    let payload = STANDARD
        .decode(&envelope.payload)
        .map_err(|_| ManifestError::Json)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ManifestError::Limit);
    }
    let manifest: TargetManifestV2 =
        serde_json::from_slice(&payload).map_err(|_| ManifestError::Json)?;
    validate_manifest_structure(&manifest)?;
    let canonical = serde_jcs::to_vec(&manifest).map_err(|_| ManifestError::Json)?;
    if canonical != payload {
        return Err(ManifestError::Json);
    }
    let message = pae(envelope.payload_type.as_bytes(), &payload)?;
    Ok((manifest, payload, message))
}

fn validate_manifest_structure(manifest: &TargetManifestV2) -> Result<(), ManifestError> {
    if manifest.schema != ARTIFACT_SCHEMA || manifest.tool_version.is_empty() {
        return Err(ManifestError::Version);
    }
    if !is_digest(&manifest.plan_hash)
        || !is_digest(&manifest.target_policy_hash)
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
    manifest: &TargetManifestV2,
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
        || manifest.target_policy_hash != expected.target_policy_hash
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
    use std::{
        env, fs,
        io::{self, Read, Write},
        os::unix::fs::PermissionsExt,
        os::unix::net::UnixListener,
        path::PathBuf,
        process::{Command, Stdio},
        thread,
    };

    const SSH_ED25519_PRIVATE_KEY: &str = "-----BEGIN_OPENSSH_PRIVATE_KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END_OPENSSH_PRIVATE_KEY-----\n";
    const SSH_ED25519_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com";

    fn manifest() -> TargetManifestV2 {
        let digest = "0".repeat(64);
        TargetManifestV2 {
            schema: ARTIFACT_SCHEMA.to_owned(),
            tool_version: "0.1.0-alpha.1".to_owned(),
            plan_hash: digest.clone(),
            target_policy_hash: digest.clone(),
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

    fn expected(manifest: &TargetManifestV2) -> ExpectedBinding<'_> {
        ExpectedBinding {
            tool_version: &manifest.tool_version,
            plan_hash: &manifest.plan_hash,
            target_policy_hash: &manifest.target_policy_hash,
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
            let public = key
                .encode_public()
                .unwrap_or_else(|error| unreachable!("{error}"));
            trusted
                .insert_encoded(&public)
                .unwrap_or_else(|error| unreachable!("{error}"));
        }
        trusted
    }

    #[cfg(unix)]
    fn write_agent_string(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
        output.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "agent test string is too large",
                    )
                })?
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
        Ok(())
    }

    fn ssh_keygen_path(required: bool) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
        let candidate = env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths)
                .map(|directory| directory.join("ssh-keygen"))
                .find(|candidate| candidate.is_file())
        });
        if candidate.is_none() && required {
            return Err("ssh-keygen is required for SSHSIG interoperability tests".into());
        }
        Ok(candidate)
    }

    #[test]
    fn verifies_distinct_threshold_signatures() {
        let one = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let two = ApprovalSigningKey::generate().unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let mut envelope =
            sign_manifest(&manifest, &one).unwrap_or_else(|error| unreachable!("{error}"));
        add_signature(&mut envelope, &two).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            inspect_unverified(&envelope).unwrap_or_else(|error| unreachable!("{error}")),
            manifest
        );
        let verified = verify(&envelope, &trust(&[&one, &two]), 2, &expected(&manifest))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(verified.manifest, manifest);
        assert_eq!(verified.signers.len(), 2);
    }

    #[test]
    fn verifies_openssh_ed25519_sshsig_and_normalizes_comments() {
        let key = ApprovalSigningKey::parse(&SSH_ED25519_PRIVATE_KEY.replace('_', " "))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let manifest = manifest();
        let envelope =
            sign_manifest(&manifest, &key).unwrap_or_else(|error| unreachable!("{error}"));

        assert_eq!(
            envelope.signatures[0].algorithm,
            ApprovalSignatureAlgorithm::SshEd25519SshsigV1
        );
        assert!(
            envelope.signatures[0]
                .signature
                .starts_with("-----BEGIN SSH SIGNATURE-----\n")
        );
        assert_eq!(
            key.encode_public()
                .unwrap_or_else(|error| unreachable!("{error}")),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti"
        );
        assert!(key.matches_public_key(SSH_ED25519_PUBLIC_KEY));

        let mut trusted = TrustedKeys::new();
        trusted
            .insert_encoded(SSH_ED25519_PUBLIC_KEY)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let verified = verify(&envelope, &trusted, 1, &expected(&manifest))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(verified.manifest, manifest);

        let mut wrong_algorithm = envelope;
        wrong_algorithm.signatures[0].algorithm = ApprovalSignatureAlgorithm::Ed25519V1;
        assert_eq!(
            verify(&wrong_algorithm, &trusted, 1, &expected(&manifest)),
            Err(ManifestError::InvalidSignature)
        );
    }

    #[cfg(unix)]
    #[test]
    fn ssh_agent_key_delegates_signing_without_private_key_material()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let private = SshPrivateKey::from_openssh(SSH_ED25519_PRIVATE_KEY.replace('_', " "))
            .map_err(|_| io::Error::other("invalid test private key"))?;
        let keypair = private
            .key_data()
            .ed25519()
            .ok_or_else(|| io::Error::other("test key is not Ed25519"))?;
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(keypair.private.as_ref());
        let agent_signing_key = SigningKey::from_bytes(&seed);
        let public = SshPublicKey::from_openssh(SSH_ED25519_PUBLIC_KEY)
            .map_err(|_| io::Error::other("invalid test public key"))?;
        let key_blob = public
            .to_bytes()
            .map_err(|_| io::Error::other("could not encode test public key"))?;
        let temporary = tempfile::tempdir()?;
        let socket = temporary.path().join("agent.sock");
        let listener = UnixListener::bind(&socket)?;
        let server = thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let (mut stream, _) = listener.accept()?;
                let mut length = [0_u8; 4];
                stream.read_exact(&mut length)?;
                let body_length = u32::from_be_bytes(length) as usize;
                let mut body = vec![0_u8; body_length];
                stream.read_exact(&mut body)?;
                assert_eq!(body.first().copied(), Some(AGENT_REQUEST_SIGN));
                let (requested_key, rest) = read_agent_string(&body[1..])
                    .map_err(|_| io::Error::other("invalid agent key request"))?;
                assert_eq!(requested_key, key_blob.as_slice());
                let (signed_data, rest) = read_agent_string(rest)
                    .map_err(|_| io::Error::other("invalid agent data request"))?;
                assert_eq!(rest, 0_u32.to_be_bytes().as_slice());
                let signature = agent_signing_key.sign(signed_data);
                let mut signature_blob = Vec::new();
                write_agent_string(&mut signature_blob, b"ssh-ed25519")?;
                write_agent_string(&mut signature_blob, signature.to_bytes().as_slice())?;
                let mut response = Vec::new();
                response.push(AGENT_SIGN_RESPONSE);
                write_agent_string(&mut response, &signature_blob)?;
                stream.write_all(&(u32::try_from(response.len())?).to_be_bytes())?;
                stream.write_all(&response)?;
                Ok(())
            },
        );

        let key_spec = format!("{SSH_AGENT_KEY_PREFIX}{SSH_ED25519_PUBLIC_KEY}");
        let key = ApprovalSigningKey::parse_with_agent(&key_spec, &socket)?;
        assert_eq!(
            key.encode_public()?,
            SSH_ED25519_PUBLIC_KEY
                .split(' ')
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let manifest = manifest();
        let envelope = sign_manifest(&manifest, &key)?;
        assert_eq!(
            envelope.signatures[0].algorithm,
            ApprovalSignatureAlgorithm::SshEd25519SshsigV1
        );
        verify(&envelope, &trust(&[&key]), 1, &expected(&manifest))?;
        server
            .join()
            .map_err(|_| io::Error::other("agent test server panicked"))??;
        Ok(())
    }

    #[test]
    fn sshsig_interoperates_with_openssh_when_required() -> Result<(), Box<dyn std::error::Error>> {
        let Some(ssh_keygen) =
            ssh_keygen_path(env::var_os("NIX_SEAL_REQUIRE_SSHSIG_INTEROP").is_some())?
        else {
            return Ok(());
        };
        let private = SSH_ED25519_PRIVATE_KEY.replace('_', " ");
        let key = ApprovalSigningKey::parse(&private)?;
        let manifest = manifest();
        let envelope = sign_manifest(&manifest, &key)?;
        let (_, _, message) = decode_envelope(&envelope)?;
        let temporary = tempfile::tempdir()?;
        let private_path = temporary.path().join("id_ed25519");
        let allowed_signers = temporary.path().join("allowed-signers");
        let message_path = temporary.path().join("message");
        let signature_path = temporary.path().join("nix-seal.sshsig");

        fs::write(&private_path, private.as_bytes())?;
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600))?;
        fs::write(
            &allowed_signers,
            format!("release {SSH_ED25519_PUBLIC_KEY}\n"),
        )?;
        fs::write(&message_path, &message)?;
        fs::write(&signature_path, envelope.signatures[0].signature.as_bytes())?;

        let mut verify = Command::new(&ssh_keygen)
            .args([
                "-Y",
                "verify",
                "-f",
                allowed_signers
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
                "-I",
                "release",
                "-n",
                SSH_SIGNATURE_NAMESPACE,
                "-s",
                signature_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        verify
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("SSH verification stdin unavailable"))?
            .write_all(&message)?;
        assert!(verify.wait()?.success());

        let signed = Command::new(&ssh_keygen)
            .args([
                "-Y",
                "sign",
                "-f",
                private_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
                "-n",
                SSH_SIGNATURE_NAMESPACE,
                message_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        assert!(signed.success());
        let openssh_signature = fs::read_to_string(message_path.with_extension("sig"))?;
        let openssh_signature = SshSig::from_pem(openssh_signature.as_bytes())
            .map_err(|_| io::Error::other("OpenSSH produced an invalid SSHSIG"))?;
        let public = SshPublicKey::from_openssh(SSH_ED25519_PUBLIC_KEY)
            .map_err(|_| io::Error::other("invalid SSH test public key"))?;
        public
            .verify(SSH_SIGNATURE_NAMESPACE, &message, &openssh_signature)
            .map_err(|_| io::Error::other("OpenSSH SSHSIG verification failed"))?;
        Ok(())
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

        let different_policy_hash = "f".repeat(64);
        let mut policy_substituted = expected(&manifest);
        policy_substituted.target_policy_hash = &different_policy_hash;
        assert_eq!(
            verify(&envelope, &trusted, 1, &policy_substituted),
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

        let old = TargetManifestV2 {
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
        let encoded = key
            .encode_private()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let reparsed =
            ApprovalSigningKey::parse(&encoded).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            key.encode_public()
                .unwrap_or_else(|error| unreachable!("{error}")),
            reparsed
                .encode_public()
                .unwrap_or_else(|error| unreachable!("{error}"))
        );
    }
}

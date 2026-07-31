#![forbid(unsafe_code)]
//! Isolated adapter for the pre-1.0 Rust age implementation.

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::ExposeSecret};
use std::io::{Read, Write};
use thiserror::Error;

const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES: u64 = 70 * 1024 * 1024;

/// A redacted cryptographic error.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Recipient text was invalid or unsupported.
    #[error("invalid or unsupported age recipient")]
    Recipient,
    /// Identity text was invalid or unsupported.
    #[error("invalid or unsupported age identity")]
    Identity,
    /// Encryption failed.
    #[error("age encryption failed")]
    Encrypt,
    /// Decryption failed.
    #[error("age decryption failed")]
    Decrypt,
    /// Bounded stream I/O failed.
    #[error("cryptographic stream I/O failed")]
    Io,
    /// Input exceeded the v1 safety bound.
    #[error("secret exceeds the 64 MiB safety limit")]
    InputTooLarge,
}

/// Generates an `X25519` identity and returns `(private, public)`.
#[must_use]
pub fn generate_x25519() -> (secrecy::SecretString, String) {
    let identity = age::x25519::Identity::generate();
    let private = secrecy::SecretString::from(identity.to_string().expose_secret().to_owned());
    (private, identity.to_public().to_string())
}

/// Derives the public recipient from a standard `X25519` identity.
pub fn recipient_from_identity(identity: &secrecy::SecretString) -> Result<String, CryptoError> {
    let parsed = identity
        .expose_secret()
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|_| CryptoError::Identity)?;
    Ok(parsed.to_public().to_string())
}

/// Returns a domain-separated fingerprint of a normalized X25519 recipient.
pub fn recipient_fingerprint(recipient: &str) -> Result<String, CryptoError> {
    let normalized = recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|_| CryptoError::Recipient)?
        .to_string();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nix-seal.age-recipient-fingerprint.v1\0");
    hasher.update(normalized.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// Encrypts a stream to standard age `X25519` recipients, bounded to 64 MiB.
pub fn encrypt<R: Read, W: Write>(
    mut input: R,
    output: W,
    recipients: &[String],
) -> Result<(), CryptoError> {
    let parsed = recipients
        .iter()
        .map(|value| {
            value
                .parse::<age::x25519::Recipient>()
                .map(|recipient| Box::new(recipient) as Box<dyn Recipient + Send>)
                .map_err(|_| CryptoError::Recipient)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        return Err(CryptoError::Recipient);
    }
    let encryptor = Encryptor::with_recipients(
        parsed
            .iter()
            .map(|recipient| recipient.as_ref() as &dyn Recipient),
    )
    .map_err(|_| CryptoError::Encrypt)?;
    let mut writer = encryptor
        .wrap_output(output)
        .map_err(|_| CryptoError::Encrypt)?;
    let copied = std::io::copy(&mut input.by_ref().take(MAX_SECRET_BYTES + 1), &mut writer)
        .map_err(|_| CryptoError::Io)?;
    if copied > MAX_SECRET_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    writer.finish().map_err(|_| CryptoError::Encrypt)?;
    Ok(())
}

/// Decrypts a stream using a standard `X25519` identity, bounded to 64 MiB.
pub fn decrypt<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: &secrecy::SecretString,
) -> Result<(), CryptoError> {
    let parsed = identity
        .expose_secret()
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|_| CryptoError::Identity)?;
    let decryptor = Decryptor::new(input).map_err(|_| CryptoError::Decrypt)?;
    let identities: Vec<&dyn Identity> = vec![&parsed];
    let mut reader = decryptor
        .decrypt(identities.into_iter())
        .map_err(|_| CryptoError::Decrypt)?;
    std::io::copy(&mut reader.by_ref().take(MAX_SECRET_BYTES), &mut output)
        .map_err(|_| CryptoError::Io)?;
    let mut overflow = [0_u8; 1];
    if reader.read(&mut overflow).map_err(|_| CryptoError::Io)? != 0 {
        return Err(CryptoError::InputTooLarge);
    }
    Ok(())
}

/// Parses and bounds a standard age ciphertext header without decrypting plaintext.
pub fn validate_ciphertext_header<R: Read>(input: R) -> Result<(), CryptoError> {
    Decryptor::new(input.take(MAX_CIPHERTEXT_BYTES + 1)).map_err(|_| CryptoError::Decrypt)?;
    Ok(())
}

/// Streams a canonical age payload directly into new target encryption.
///
/// No plaintext is materialized outside the bounded age reader/writer buffers.
pub fn rekey<R: Read, W: Write>(
    input: R,
    output: W,
    identity: &secrecy::SecretString,
    recipients: &[String],
) -> Result<(), CryptoError> {
    let identity = identity
        .expose_secret()
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|_| CryptoError::Identity)?;
    let recipients = recipients
        .iter()
        .map(|value| {
            value
                .parse::<age::x25519::Recipient>()
                .map(|recipient| Box::new(recipient) as Box<dyn Recipient + Send>)
                .map_err(|_| CryptoError::Recipient)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if recipients.is_empty() {
        return Err(CryptoError::Recipient);
    }

    let decryptor = Decryptor::new(input).map_err(|_| CryptoError::Decrypt)?;
    let identities: Vec<&dyn Identity> = vec![&identity];
    let mut plaintext = decryptor
        .decrypt(identities.into_iter())
        .map_err(|_| CryptoError::Decrypt)?;
    let encryptor = Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient.as_ref() as &dyn Recipient),
    )
    .map_err(|_| CryptoError::Encrypt)?;
    let mut ciphertext = encryptor
        .wrap_output(output)
        .map_err(|_| CryptoError::Encrypt)?;

    let copied = std::io::copy(
        &mut plaintext.by_ref().take(MAX_SECRET_BYTES + 1),
        &mut ciphertext,
    )
    .map_err(|_| CryptoError::Io)?;
    if copied > MAX_SECRET_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    ciphertext.finish().map_err(|_| CryptoError::Encrypt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn x25519_round_trip() -> Result<(), CryptoError> {
        let (identity, recipient) = generate_x25519();
        assert_eq!(recipient_from_identity(&identity)?, recipient);
        let mut ciphertext = Vec::new();
        encrypt(b"canary".as_slice(), &mut ciphertext, &[recipient])?;
        assert!(!ciphertext.windows(6).any(|window| window == b"canary"));
        let mut plaintext = Vec::new();
        decrypt(ciphertext.as_slice(), &mut plaintext, &identity)?;
        assert_eq!(plaintext, b"canary");

        let (target_identity, target_recipient) = generate_x25519();
        let mut target_ciphertext = Vec::new();
        rekey(
            ciphertext.as_slice(),
            &mut target_ciphertext,
            &identity,
            std::slice::from_ref(&target_recipient),
        )?;
        let mut target_plaintext = Vec::new();
        decrypt(
            target_ciphertext.as_slice(),
            &mut target_plaintext,
            &target_identity,
        )?;
        assert_eq!(target_plaintext, b"canary");
        assert_eq!(recipient_fingerprint(&target_recipient)?.len(), 64);
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! Isolated adapter for the pre-1.0 Rust age implementation.

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::ExposeSecret};
use std::io::{Read, Write};
use thiserror::Error;

const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;

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
        Ok(())
    }
}

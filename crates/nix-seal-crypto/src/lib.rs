#![forbid(unsafe_code)]
//! Isolated adapter for the pre-1.0 Rust age implementation.

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::ExposeSecret};
use secrecy::{ExposeSecretMut, SecretBox};
use std::io::{BufReader, Cursor, Read, Write};
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
    /// The operating-system CSPRNG failed.
    #[error("operating-system random generation failed")]
    Random,
}

/// Returns CSPRNG bytes in a zeroizing secret container.
pub fn random_bytes(length: usize) -> Result<SecretBox<Vec<u8>>, CryptoError> {
    if u64::try_from(length).map_err(|_| CryptoError::InputTooLarge)? > MAX_SECRET_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    let mut bytes = SecretBox::new(Box::new(vec![0_u8; length]));
    getrandom::fill(bytes.expose_secret_mut().as_mut_slice()).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}

/// Generates an `X25519` identity and returns `(private, public)`.
#[must_use]
pub fn generate_x25519() -> (secrecy::SecretString, String) {
    let identity = age::x25519::Identity::generate();
    let private = secrecy::SecretString::from(identity.to_string().expose_secret().to_owned());
    (private, identity.to_public().to_string())
}

/// Derives the normalized public recipient from a native X25519 or unencrypted
/// OpenSSH compatibility identity.
pub fn recipient_from_identity(identity: &secrecy::SecretString) -> Result<String, CryptoError> {
    if let Ok(parsed) = identity
        .expose_secret()
        .trim()
        .parse::<age::x25519::Identity>()
    {
        return Ok(parsed.to_public().to_string());
    }
    let parsed = parse_ssh_identity(identity)?;
    age::ssh::Recipient::try_from(parsed)
        .map(|recipient| recipient.to_string())
        .map_err(|_| CryptoError::Identity)
}

/// Parses an accepted recipient and returns its canonical serialized form.
///
/// This deliberately removes an OpenSSH public-key comment before policy
/// comparison and fingerprinting, because comments are not key material.
pub fn normalize_recipient(recipient: &str) -> Result<String, CryptoError> {
    if let Ok(parsed) = recipient.parse::<age::x25519::Recipient>() {
        return Ok(parsed.to_string());
    }
    recipient
        .parse::<age::ssh::Recipient>()
        .map(|parsed| parsed.to_string())
        .map_err(|_| CryptoError::Recipient)
}

/// Returns a domain-separated fingerprint of a normalized age recipient.
pub fn recipient_fingerprint(recipient: &str) -> Result<String, CryptoError> {
    let normalized = normalize_recipient(recipient)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nix-seal.age-recipient-fingerprint.v1\0");
    hasher.update(normalized.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

/// Encrypts a stream to native age or OpenSSH-compatibility recipients, bounded
/// to 64 MiB.
pub fn encrypt<R: Read, W: Write>(
    mut input: R,
    output: W,
    recipients: &[String],
) -> Result<(), CryptoError> {
    let parsed = recipients
        .iter()
        .map(|value| parse_recipient(value))
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

/// Decrypts a stream using a native X25519 or unencrypted OpenSSH
/// compatibility identity, bounded to 64 MiB.
pub fn decrypt<R: Read, W: Write>(
    input: R,
    output: W,
    identity: &secrecy::SecretString,
) -> Result<(), CryptoError> {
    let parsed = parse_identity(identity)?;
    decrypt_with_identity(input, output, parsed.as_ref())
}

fn parse_recipient(value: &str) -> Result<Box<dyn Recipient + Send>, CryptoError> {
    if let Ok(recipient) = value.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(recipient));
    }
    value
        .parse::<age::ssh::Recipient>()
        .map(|recipient| Box::new(recipient) as Box<dyn Recipient + Send>)
        .map_err(|_| CryptoError::Recipient)
}

fn parse_identity(
    identity: &secrecy::SecretString,
) -> Result<Box<dyn Identity + Send>, CryptoError> {
    if let Ok(parsed) = identity
        .expose_secret()
        .trim()
        .parse::<age::x25519::Identity>()
    {
        return Ok(Box::new(parsed));
    }
    let parsed = parse_ssh_identity(identity)?;
    if matches!(&parsed, age::ssh::Identity::Encrypted(_)) {
        return Err(CryptoError::Identity);
    }
    Ok(Box::new(parsed))
}

fn parse_ssh_identity(identity: &secrecy::SecretString) -> Result<age::ssh::Identity, CryptoError> {
    age::ssh::Identity::from_buffer(
        BufReader::new(Cursor::new(identity.expose_secret().as_bytes())),
        None,
    )
    .map_err(|_| CryptoError::Identity)
}

fn decrypt_with_identity<R: Read, W: Write>(
    input: R,
    mut output: W,
    identity: &dyn Identity,
) -> Result<(), CryptoError> {
    let decryptor = Decryptor::new(input).map_err(|_| CryptoError::Decrypt)?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
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
    let identity = parse_identity(identity)?;
    let recipients = recipients
        .iter()
        .map(|value| parse_recipient(value))
        .collect::<Result<Vec<_>, _>>()?;
    if recipients.is_empty() {
        return Err(CryptoError::Recipient);
    }

    let decryptor = Decryptor::new(input).map_err(|_| CryptoError::Decrypt)?;
    let mut plaintext = decryptor
        .decrypt(std::iter::once(identity.as_ref() as &dyn Identity))
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

    const SSH_ED25519_RECIPIENT: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const SSH_ED25519_IDENTITY_ARMOR: &str = "-----BEGIN_OPENSSH_PRIVATE_KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\n\
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\n\
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n\
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n\
-----END_OPENSSH_PRIVATE_KEY-----\n";

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

    #[test]
    fn ssh_ed25519_compatibility_round_trip() -> Result<(), CryptoError> {
        let identity = secrecy::SecretString::from(SSH_ED25519_IDENTITY_ARMOR.replace('_', " "));
        let mut ciphertext = Vec::new();
        encrypt(
            b"ssh-canary".as_slice(),
            &mut ciphertext,
            &[SSH_ED25519_RECIPIENT.to_owned()],
        )?;
        assert!(!ciphertext.windows(10).any(|window| window == b"ssh-canary"));
        let mut plaintext = Vec::new();
        decrypt(ciphertext.as_slice(), &mut plaintext, &identity)?;
        assert_eq!(plaintext, b"ssh-canary");
        assert_eq!(
            recipient_fingerprint(SSH_ED25519_RECIPIENT)?,
            recipient_fingerprint(&recipient_from_identity(&identity)?)?
        );
        Ok(())
    }
}

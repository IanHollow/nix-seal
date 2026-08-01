#![forbid(unsafe_code)]
//! Isolated adapter for the pre-1.0 Rust age implementation.

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::ExposeSecret};
use secrecy::{ExposeSecretMut, SecretBox};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use thiserror::Error;

const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AGE_HEADER_BYTES: usize = 1024 * 1024;

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
    let mut reader = BufReader::new(input);
    let header = read_age_header(&mut reader)?;
    validate_age_header_structure(&header)?;
    Decryptor::new(Cursor::new(header).chain(reader)).map_err(|_| CryptoError::Decrypt)?;
    Ok(())
}

fn read_age_header<R: BufRead>(reader: &mut R) -> Result<Vec<u8>, CryptoError> {
    let mut header = Vec::new();
    loop {
        let line_start = header.len();
        loop {
            let available = reader.fill_buf().map_err(|_| CryptoError::Io)?;
            if available.is_empty() || header.len() == MAX_AGE_HEADER_BYTES {
                return Err(CryptoError::Decrypt);
            }
            let capacity = MAX_AGE_HEADER_BYTES
                .checked_sub(header.len())
                .ok_or(CryptoError::InputTooLarge)?;
            let readable = available.len().min(capacity);
            let consumed = available[..readable]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(readable, |index| index + 1);
            let completed_line = consumed <= readable && available[consumed - 1] == b'\n';
            header.extend_from_slice(&available[..consumed]);
            reader.consume(consumed);
            if completed_line {
                break;
            }
        }
        if header[line_start..].starts_with(b"--- ") {
            return Ok(header);
        }
    }
}

fn validate_age_header_structure(ciphertext: &[u8]) -> Result<(), CryptoError> {
    let mut lines = ciphertext.split_inclusive(|byte| *byte == b'\n');
    if lines.next() != Some(b"age-encryption.org/v1\n".as_slice()) {
        return Err(CryptoError::Decrypt);
    }

    let mut stanza_count = 0_u16;
    let mut expects_body = false;
    let mut long_body_stanza = false;
    let mut grease_stanza = false;
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        if expects_body
            && !(grease_stanza && (line.starts_with(b"-> ") || line.starts_with(b"--- ")))
        {
            // A GREASE stanza may have an empty body, including the empty
            // terminating line required for a body whose encoded length is a
            // multiple of 64. Treating that line as malformed made otherwise
            // valid age output fail nondeterministically.
            if (line.is_empty() && !grease_stanza)
                || line.starts_with(b"->")
                || line.starts_with(b"---")
                || (!long_body_stanza && line.len() >= 64)
            {
                return Err(CryptoError::Decrypt);
            }
            if !grease_stanza {
                expects_body = false;
            }
            continue;
        }
        if let Some(stanza) = line.strip_prefix(b"-> ") {
            let fields = stanza.split(|byte| *byte == b' ').collect::<Vec<_>>();
            let valid_fields = match fields.first().copied() {
                Some(b"X25519") => fields.len() == 2,
                Some(b"ssh-ed25519") => fields.len() == 3,
                Some(tag) if tag.ends_with(b"-grease") => true,
                Some(_) => fields.len() >= 2,
                None => false,
            };
            if !valid_fields || fields.iter().any(|value| value.is_empty()) {
                return Err(CryptoError::Decrypt);
            }
            stanza_count = stanza_count
                .checked_add(1)
                .ok_or(CryptoError::InputTooLarge)?;
            long_body_stanza = fields.first() == Some(&b"ssh-rsa".as_slice())
                || fields.first().is_some_and(|tag| tag.ends_with(b"-grease"));
            grease_stanza = fields.first().is_some_and(|tag| tag.ends_with(b"-grease"));
            expects_body = true;
            continue;
        }
        if line.starts_with(b"--- ") && stanza_count > 0 {
            return Ok(());
        }
        return Err(CryptoError::Decrypt);
    }
    Err(CryptoError::Decrypt)
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
    use sha2::{Digest as _, Sha256};
    use std::{
        collections::BTreeMap,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::{Command, Stdio},
    };

    const SSH_ED25519_RECIPIENT: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const SUPPORTED_CCTV_VECTOR_COUNT: u16 = 48;
    const SSH_ED25519_IDENTITY_ARMOR: &str = "-----BEGIN_OPENSSH_PRIVATE_KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQAAAJCfEwtqnxML\n\
agAAAAtzc2gtZWQyNTUxOQAAACB7Ci6nqZYaVvrjm8+XbzII89TsXzP111AflR7WeorBjQ\n\
AAAEADBJvjZT8X6JRJI8xVq/1aU8nMVgOtVnmdwqWwrSlXG3sKLqeplhpW+uObz5dvMgjz\n\
1OxfM/XXUB+VHtZ6isGNAAAADHN0cjRkQGNhcmJvbgE=\n\
-----END_OPENSSH_PRIVATE_KEY-----\n";

    #[test]
    fn accepts_an_empty_grease_stanza_body() {
        // The age format permits a GREASE stanza with an empty body. The
        // Rust age implementation emits these at random, so rejecting one
        // makes otherwise-valid encryption and rekey operations flaky.
        let header = b"age-encryption.org/v1\n\
-> X25519 recipient\n\
body\n\
-> test-grease\n\
\n\
--- mac\n";

        assert!(validate_age_header_structure(header).is_ok());
    }

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

    #[test]
    fn interoperates_with_age_and_rage_when_nix_checks_require_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let required = std::env::var_os("NIX_SEAL_REQUIRE_INTEROP").is_some();
        let mut available = Vec::new();
        for binary in ["age", "rage"] {
            if let Some(binary) = command_available(binary, required)? {
                available.push(binary);
            }
        }
        if available.is_empty() {
            return Ok(());
        }

        let temporary = tempfile::tempdir()?;
        let identity_path = temporary.path().join("identity.txt");
        let (identity, recipient) = generate_x25519();
        std::fs::write(&identity_path, identity.expose_secret())?;
        let private_permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&identity_path, private_permissions)?;
        let plaintext = b"nix-seal-age-interop-canary";

        for binary in available {
            let mut ciphertext = Vec::new();
            encrypt(
                plaintext.as_slice(),
                &mut ciphertext,
                std::slice::from_ref(&recipient),
            )?;
            assert_eq!(
                invoke(
                    binary,
                    &["-d", "-i"],
                    &[identity_path.as_os_str()],
                    &ciphertext
                )?,
                plaintext
            );

            let externally_encrypted = invoke(binary, &["-r"], &[recipient.as_ref()], plaintext)?;
            let mut decrypted = Vec::new();
            decrypt(externally_encrypted.as_slice(), &mut decrypted, &identity)?;
            assert_eq!(decrypted, plaintext);
        }
        Ok(())
    }

    fn command_available(
        binary: &'static str,
        required: bool,
    ) -> Result<Option<&'static str>, Box<dyn std::error::Error>> {
        match Command::new(binary)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => Ok(Some(binary)),
            Ok(_) | Err(_) if required => {
                Err(format!("required interoperability binary unavailable: {binary}").into())
            }
            Ok(_) | Err(_) => Ok(None),
        }
    }

    fn invoke(
        binary: &str,
        arguments: &[&str],
        trailing_arguments: &[&std::ffi::OsStr],
        input: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut child = Command::new(binary)
            .args(arguments)
            .args(trailing_arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .as_mut()
            .ok_or("could not open interoperability command standard input")?
            .write_all(input)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(format!("interoperability command failed: {binary}").into());
        }
        Ok(output.stdout)
    }

    #[test]
    fn cctv_age_vectors_cover_supported_x25519_and_parser_cases()
    -> Result<(), Box<dyn std::error::Error>> {
        let required = std::env::var_os("NIX_SEAL_REQUIRE_CCTV").is_some();
        let Some(directory) = cctv_age_testdata_directory(required)? else {
            return Ok(());
        };
        let mut paths = std::fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();

        let mut executed = 0_u16;
        for path in paths {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() {
                return Err("CCTV age testdata contains a non-regular entry".into());
            }
            let bytes = std::fs::read(&path)?;
            let (metadata, ciphertext) = parse_cctv_vector(&bytes)?;
            if metadata.compressed
                || metadata.armored
                || metadata.has_unsupported_identity()
                || metadata.has_passphrase
            {
                continue;
            }
            match metadata.expect.as_str() {
                "header failure" => {
                    let validation = validate_ciphertext_header(ciphertext);
                    if let Some(identity) = metadata.native_x25519_identity() {
                        let decrypt_result = decrypt(
                            ciphertext,
                            std::io::sink(),
                            &secrecy::SecretString::from(identity.to_owned()),
                        );
                        assert!(
                            validation.is_err() || decrypt_result.is_err(),
                            "accepted official invalid age header: {}",
                            path.display()
                        );
                    } else {
                        assert!(
                            validation.is_err(),
                            "accepted official invalid age header: {}",
                            path.display()
                        );
                    }
                    executed = executed
                        .checked_add(1)
                        .ok_or("CCTV vector count overflow")?;
                }
                "no match" => {
                    assert!(
                        validate_ciphertext_header(ciphertext).is_ok(),
                        "rejected official no-match age header: {}",
                        path.display()
                    );
                    if let Some(identity) = metadata.native_x25519_identity() {
                        let mut plaintext = Vec::new();
                        assert!(
                            decrypt(
                                ciphertext,
                                &mut plaintext,
                                &secrecy::SecretString::from(identity.to_owned()),
                            )
                            .is_err()
                        );
                    }
                    executed = executed
                        .checked_add(1)
                        .ok_or("CCTV vector count overflow")?;
                }
                "HMAC failure" | "payload failure" | "success" => {
                    let Some(identity) = metadata.native_x25519_identity() else {
                        continue;
                    };
                    let mut plaintext = Vec::new();
                    let result = decrypt(
                        ciphertext,
                        &mut plaintext,
                        &secrecy::SecretString::from(identity.to_owned()),
                    );
                    if metadata.expect == "success" {
                        result?;
                        assert_cctv_payload(&metadata, &plaintext)?;
                    } else {
                        assert!(result.is_err());
                        if metadata.expect == "payload failure" {
                            assert_cctv_payload(&metadata, &plaintext)?;
                        }
                    }
                    executed = executed
                        .checked_add(1)
                        .ok_or("CCTV vector count overflow")?;
                }
                _ => return Err("CCTV age vector has an unsupported expectation".into()),
            }
        }
        assert_eq!(executed, SUPPORTED_CCTV_VECTOR_COUNT);
        Ok(())
    }

    #[derive(Default)]
    struct CctvVector {
        expect: String,
        payload_sha256: Option<String>,
        identities: Vec<String>,
        compressed: bool,
        armored: bool,
        has_passphrase: bool,
    }

    impl CctvVector {
        fn native_x25519_identity(&self) -> Option<&str> {
            self.identities
                .iter()
                .map(String::as_str)
                .find(|identity| identity.starts_with("AGE-SECRET-KEY-1"))
        }

        fn has_unsupported_identity(&self) -> bool {
            self.identities
                .iter()
                .any(|identity| identity.starts_with("AGE-SECRET-KEY-PQ-1"))
        }
    }

    fn cctv_age_testdata_directory(
        required: bool,
    ) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
        let Some(path) = std::env::var_os("NIX_SEAL_CCTV_AGE_TESTDATA") else {
            if required {
                return Err("required CCTV age testdata path is absent".into());
            }
            return Ok(None);
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_dir() {
            return Err("CCTV age testdata path is unsafe or absent".into());
        }
        Ok(Some(path))
    }

    fn parse_cctv_vector(bytes: &[u8]) -> Result<(CctvVector, &[u8]), Box<dyn std::error::Error>> {
        let separator = bytes
            .windows(2)
            .position(|window| window == b"\n\n")
            .ok_or("CCTV age vector has no metadata separator")?;
        let header = std::str::from_utf8(&bytes[..separator])?;
        let mut entries = BTreeMap::new();
        let mut identities = Vec::new();
        for line in header.lines() {
            let (key, value) = line
                .split_once(": ")
                .ok_or("CCTV age vector metadata is malformed")?;
            if key == "identity" {
                identities.push(value.to_owned());
            } else if matches!(key, "expect" | "payload" | "compressed" | "armored")
                && entries.insert(key, value).is_some()
            {
                return Err("CCTV age vector repeats singleton metadata".into());
            }
        }
        let expect = entries
            .remove("expect")
            .ok_or("CCTV age vector omits expectation")?
            .to_owned();
        let payload_sha256 = entries.remove("payload").map(str::to_owned);
        let compressed = entries
            .remove("compressed")
            .is_some_and(|value| value == "zlib");
        let armored = entries
            .remove("armored")
            .is_some_and(|value| value == "yes");
        let has_passphrase = header.lines().any(|line| line.starts_with("passphrase: "));
        Ok((
            CctvVector {
                expect,
                payload_sha256,
                identities,
                compressed,
                armored,
                has_passphrase,
            },
            &bytes[separator + 2..],
        ))
    }

    fn assert_cctv_payload(
        metadata: &CctvVector,
        plaintext: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = metadata
            .payload_sha256
            .as_deref()
            .ok_or("CCTV age vector omits payload hash")?;
        assert_eq!(format!("{:x}", Sha256::digest(plaintext)), expected);
        Ok(())
    }
}

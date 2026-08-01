#![forbid(unsafe_code)]
//! Isolated adapter for the pre-1.0 Rust age implementation.

use age::{Decryptor, Encryptor, Identity, NoCallbacks, Recipient, secrecy::ExposeSecret};
use secrecy::{ExposeSecretMut, SecretBox};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{BufRead, BufReader, Cursor, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};
use thiserror::Error;

const MAX_SECRET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_AGE_HEADER_BYTES: usize = 1024 * 1024;
const MAX_PLUGIN_FIELD_BYTES: usize = 64 * 1024;
const MAX_PLUGIN_RECIPIENTS: usize = 256;
const MAX_PLUGIN_CIPHERTEXT_BYTES: u64 = MAX_SECRET_BYTES + (2 * 1024 * 1024);
const PLUGIN_WORKER_TIMEOUT: Duration = Duration::from_mins(2);
const PLUGIN_WORKER_MAGIC: &[u8] = b"nix-seal-age-plugin-worker-v1\n";

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
    /// A plugin worker could not be started or completed safely.
    #[error("age plugin execution failed in the isolated worker")]
    Plugin,
    /// A plugin identity cannot be converted into a public recipient without
    /// invoking a plugin-specific operation.
    #[error("age plugin identity has no generic public-recipient conversion")]
    PluginIdentityPublic,
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
    if identity
        .expose_secret()
        .trim()
        .parse::<age::plugin::Identity>()
        .is_ok()
    {
        return Err(CryptoError::PluginIdentityPublic);
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
    if let Ok(parsed) = recipient.parse::<age::plugin::Recipient>() {
        return Ok(parsed.to_string());
    }
    recipient
        .parse::<age::ssh::Recipient>()
        .map(|parsed| parsed.to_string())
        .map_err(|_| CryptoError::Recipient)
}

/// Returns whether an identity is a plugin identity for the supplied plugin
/// recipient. Plugin identities are intentionally compared only by plugin
/// name here; the age stanza decryption remains the authoritative proof that
/// the opaque identity contains the corresponding private key.
#[must_use]
pub fn identity_matches_recipient(identity: &secrecy::SecretString, recipient: &str) -> bool {
    if let (Ok(identity), Ok(recipient)) = (
        identity
            .expose_secret()
            .trim()
            .parse::<age::plugin::Identity>(),
        recipient.parse::<age::plugin::Recipient>(),
    ) {
        return identity.plugin() == recipient.plugin();
    }
    recipient_from_identity(identity)
        .ok()
        .and_then(|actual| normalize_recipient(&actual).ok())
        .and_then(|actual| {
            normalize_recipient(recipient)
                .ok()
                .map(|expected| actual == expected)
        })
        .unwrap_or(false)
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
pub fn encrypt<R: Read + Send, W: Write>(
    input: R,
    output: W,
    recipients: &[String],
) -> Result<(), CryptoError> {
    if recipients.iter().any(|value| is_plugin_recipient(value)) {
        return run_plugin_operation(
            &PluginOperation::Encrypt {
                identity: None,
                recipients,
            },
            input,
            output,
        );
    }
    encrypt_direct(input, output, recipients)
}

fn encrypt_direct<R: Read, W: Write>(
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
pub fn decrypt<R: Read + Send, W: Write>(
    input: R,
    output: W,
    identity: &secrecy::SecretString,
) -> Result<(), CryptoError> {
    if is_plugin_identity(identity) {
        return run_plugin_operation(
            &PluginOperation::Decrypt {
                identity: Some(identity),
                recipients: &[],
            },
            input,
            output,
        );
    }
    let parsed = parse_identity(identity)?;
    decrypt_with_identity(input, output, parsed.as_ref())
}

fn parse_recipient(value: &str) -> Result<Box<dyn Recipient + Send>, CryptoError> {
    if let Ok(recipient) = value.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(recipient));
    }
    if let Ok(recipient) = value.parse::<age::plugin::Recipient>() {
        let plugin = age::plugin::RecipientPluginV1::new(
            recipient.plugin(),
            std::slice::from_ref(&recipient),
            &[],
            NoCallbacks,
        )
        .map_err(|_| CryptoError::Plugin)?;
        return Ok(Box::new(plugin));
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
    if is_plugin_identity(identity) {
        return parse_plugin_identity(identity);
    }
    let parsed = parse_ssh_identity(identity)?;
    if matches!(&parsed, age::ssh::Identity::Encrypted(_)) {
        return Err(CryptoError::Identity);
    }
    Ok(Box::new(parsed))
}

fn parse_plugin_identity(
    identity: &secrecy::SecretString,
) -> Result<Box<dyn Identity + Send>, CryptoError> {
    let parsed = identity
        .expose_secret()
        .trim()
        .parse::<age::plugin::Identity>()
        .map_err(|_| CryptoError::Identity)?;
    let plugin = age::plugin::IdentityPluginV1::new(
        parsed.plugin(),
        std::slice::from_ref(&parsed),
        NoCallbacks,
    )
    .map_err(|_| CryptoError::Plugin)?;
    Ok(Box::new(plugin))
}

fn is_plugin_recipient(value: &str) -> bool {
    value.parse::<age::plugin::Recipient>().is_ok()
}

fn is_plugin_identity(value: &secrecy::SecretString) -> bool {
    value
        .expose_secret()
        .trim()
        .parse::<age::plugin::Identity>()
        .is_ok()
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
pub fn rekey<R: Read + Send, W: Write>(
    input: R,
    output: W,
    identity: &secrecy::SecretString,
    recipients: &[String],
) -> Result<(), CryptoError> {
    if is_plugin_identity(identity) || recipients.iter().any(|value| is_plugin_recipient(value)) {
        return run_plugin_operation(
            &PluginOperation::Rekey {
                identity: Some(identity),
                recipients,
            },
            input,
            output,
        );
    }
    rekey_direct(input, output, identity, recipients)
}

fn rekey_direct<R: Read, W: Write>(
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

enum PluginOperation<'a> {
    Encrypt {
        identity: Option<&'a secrecy::SecretString>,
        recipients: &'a [String],
    },
    Decrypt {
        identity: Option<&'a secrecy::SecretString>,
        recipients: &'a [String],
    },
    Rekey {
        identity: Option<&'a secrecy::SecretString>,
        recipients: &'a [String],
    },
}

impl PluginOperation<'_> {
    const fn code(&self) -> u8 {
        match self {
            Self::Encrypt { .. } => 1,
            Self::Decrypt { .. } => 2,
            Self::Rekey { .. } => 3,
        }
    }

    fn identity(&self) -> Option<&secrecy::SecretString> {
        match self {
            Self::Encrypt { identity, .. }
            | Self::Decrypt { identity, .. }
            | Self::Rekey { identity, .. } => *identity,
        }
    }

    fn recipients(&self) -> &[String] {
        match self {
            Self::Encrypt { recipients, .. }
            | Self::Decrypt { recipients, .. }
            | Self::Rekey { recipients, .. } => recipients,
        }
    }

    const fn input_limit(&self) -> u64 {
        match self {
            Self::Encrypt { .. } => MAX_SECRET_BYTES,
            Self::Decrypt { .. } | Self::Rekey { .. } => MAX_PLUGIN_CIPHERTEXT_BYTES,
        }
    }

    const fn output_limit(&self) -> u64 {
        match self {
            Self::Encrypt { .. } | Self::Rekey { .. } => MAX_PLUGIN_CIPHERTEXT_BYTES,
            Self::Decrypt { .. } => MAX_SECRET_BYTES,
        }
    }
}

/// Runs the internal age-plugin worker protocol.
///
/// This entrypoint is intentionally not a general-purpose plugin API. The CLI
/// exposes it only as a hidden subcommand, while the public crypto operations
/// use it automatically whenever a standard age plugin recipient or identity
/// is encountered. The framing carries private identities and payload bytes
/// over pipes rather than arguments or environment variables.
pub fn run_plugin_worker_protocol<R: Read, W: Write>(
    mut input: R,
    mut output: W,
) -> Result<(), CryptoError> {
    let mut magic = vec![0_u8; PLUGIN_WORKER_MAGIC.len()];
    input
        .read_exact(&mut magic)
        .map_err(|_| CryptoError::Plugin)?;
    if magic != PLUGIN_WORKER_MAGIC {
        return Err(CryptoError::Plugin);
    }
    let operation = match read_plugin_byte(&mut input)? {
        1 => 1,
        2 => 2,
        3 => 3,
        _ => return Err(CryptoError::Plugin),
    };
    let identity = read_plugin_field(&mut input, true)?.map(secrecy::SecretString::from);
    let recipient_count = read_plugin_u32(&mut input)? as usize;
    if recipient_count > MAX_PLUGIN_RECIPIENTS {
        return Err(CryptoError::Plugin);
    }
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        recipients.push(read_plugin_field(&mut input, false)?.ok_or(CryptoError::Plugin)?);
    }

    match operation {
        1 => encrypt_direct(&mut input, &mut output, &recipients),
        2 => {
            let identity = identity.as_ref().ok_or(CryptoError::Plugin)?;
            decrypt_with_identity(&mut input, &mut output, parse_identity(identity)?.as_ref())
        }
        3 => {
            let identity = identity.as_ref().ok_or(CryptoError::Plugin)?;
            rekey_direct(&mut input, &mut output, identity, &recipients)
        }
        _ => Err(CryptoError::Plugin),
    }
}

fn run_plugin_operation<R: Read + Send, W: Write>(
    operation: &PluginOperation<'_>,
    input: R,
    mut output: W,
) -> Result<(), CryptoError> {
    let plugin_directories = plugin_binary_directories(operation)?;
    let executable = env::current_exe()
        .map_err(|_| CryptoError::Plugin)?
        .canonicalize()
        .map_err(|_| CryptoError::Plugin)?;
    let worker_directory = tempfile::Builder::new()
        .prefix("nix-seal-plugin-worker-")
        .tempdir()
        .map_err(|_| CryptoError::Plugin)?;
    set_private_worker_directory(worker_directory.path())?;

    let mut command = Command::new(executable);
    command
        .arg("__plugin-worker")
        .env_clear()
        .env("NIX_SEAL_PLUGIN_WORKER", "1")
        .env("PATH", plugin_directories)
        .current_dir(worker_directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    copy_plugin_environment(&mut command);
    isolate_plugin_process_group(&mut command);

    let mut child = command.spawn().map_err(|_| CryptoError::Plugin)?;
    let Some(stdin) = child.stdin.take() else {
        terminate_plugin_process_tree(&mut child);
        return Err(CryptoError::Plugin);
    };
    let Some(mut stdout) = child.stdout.take() else {
        terminate_plugin_process_tree(&mut child);
        return Err(CryptoError::Plugin);
    };
    let child = Arc::new(Mutex::new(child));
    let watchdog_child = Arc::clone(&child);
    let (complete_tx, complete_rx) = mpsc::channel();
    let watchdog = thread::spawn(move || {
        if complete_rx.recv_timeout(PLUGIN_WORKER_TIMEOUT).is_err()
            && let Ok(mut child) = watchdog_child.lock()
        {
            terminate_plugin_process_tree(&mut child);
        }
    });

    let (output_result, input_result) = thread::scope(|scope| {
        let writer = scope.spawn(|| write_plugin_request(stdin, operation, input));
        let output_result = copy_bounded(&mut stdout, &mut output, operation.output_limit());
        if output_result.is_err()
            && let Ok(mut child) = child.lock()
        {
            terminate_plugin_process_tree(&mut child);
        }
        let input_result = match writer.join() {
            Ok(result) => result,
            Err(_) => Err(CryptoError::Plugin),
        };
        (output_result, input_result)
    });
    let _ = complete_tx.send(());
    let _ = watchdog.join();
    if output_result.is_err() || input_result.is_err() {
        if let Ok(mut child) = child.lock() {
            terminate_plugin_process_tree(&mut child);
        }
        return Err(CryptoError::Plugin);
    }
    let status = child
        .lock()
        .map_err(|_| CryptoError::Plugin)?
        .wait()
        .map_err(|_| CryptoError::Plugin)?;
    if !status.success() {
        return Err(CryptoError::Plugin);
    }
    Ok(())
}

fn write_plugin_request<W: Write, R: Read>(
    mut output: W,
    operation: &PluginOperation<'_>,
    mut input: R,
) -> Result<(), CryptoError> {
    output
        .write_all(PLUGIN_WORKER_MAGIC)
        .and_then(|()| output.write_all(&[operation.code()]))
        .map_err(|_| CryptoError::Plugin)?;
    if let Some(identity) = operation.identity() {
        write_plugin_field(&mut output, identity.expose_secret().as_bytes())?;
    } else {
        write_plugin_u32(&mut output, 0)?;
    }
    let recipients = operation.recipients();
    if recipients.len() > MAX_PLUGIN_RECIPIENTS {
        return Err(CryptoError::Plugin);
    }
    write_plugin_u32(
        &mut output,
        u32::try_from(recipients.len()).map_err(|_| CryptoError::Plugin)?,
    )?;
    for recipient in recipients {
        write_plugin_field(&mut output, recipient.as_bytes())?;
    }
    let copied = std::io::copy(
        &mut input.by_ref().take(operation.input_limit() + 1),
        &mut output,
    )
    .map_err(|_| CryptoError::Plugin)?;
    if copied > operation.input_limit() {
        return Err(CryptoError::InputTooLarge);
    }
    output.flush().map_err(|_| CryptoError::Plugin)
}

fn plugin_binary_directories(
    operation: &PluginOperation<'_>,
) -> Result<std::ffi::OsString, CryptoError> {
    let mut names = BTreeSet::new();
    for recipient in operation.recipients() {
        if let Ok(parsed) = recipient.parse::<age::plugin::Recipient>() {
            names.insert(parsed.plugin().to_owned());
        }
    }
    if let Some(identity) = operation.identity()
        && let Ok(parsed) = identity
            .expose_secret()
            .trim()
            .parse::<age::plugin::Identity>()
    {
        names.insert(parsed.plugin().to_owned());
    }
    if names.is_empty() {
        return Err(CryptoError::Plugin);
    }
    let path = env::var_os("PATH").ok_or(CryptoError::Plugin)?;
    let mut directories = BTreeSet::new();
    for name in names {
        let binary = format!("age-plugin-{name}");
        let mut found = None;
        for directory in env::split_paths(&path) {
            let candidate = directory.join(&binary);
            let Ok(canonical) = candidate.canonicalize() else {
                continue;
            };
            let Ok(metadata) = fs::metadata(&canonical) else {
                continue;
            };
            if metadata.is_file() && is_executable(&metadata) {
                found = canonical.parent().map(Path::to_owned);
                break;
            }
        }
        directories.insert(found.ok_or(CryptoError::Plugin)?);
    }
    env::join_paths(directories).map_err(|_| CryptoError::Plugin)
}

fn copy_plugin_environment(command: &mut Command) {
    const ALLOWED: &[&str] = &[
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "HOME",
        "SSH_AUTH_SOCK",
        "WAYLAND_DISPLAY",
        "XDG_RUNTIME_DIR",
    ];
    for key in ALLOWED {
        let Some(value) = env::var_os(key) else {
            continue;
        };
        if (*key == "HOME" || *key == "SSH_AUTH_SOCK" || *key == "XDG_RUNTIME_DIR")
            && !Path::new(&value).is_absolute()
        {
            continue;
        }
        command.env(key, value);
    }
}

fn write_plugin_u32<W: Write>(output: &mut W, value: u32) -> Result<(), CryptoError> {
    output
        .write_all(&value.to_be_bytes())
        .map_err(|_| CryptoError::Plugin)
}

fn write_plugin_field<W: Write>(output: &mut W, value: &[u8]) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > MAX_PLUGIN_FIELD_BYTES {
        return Err(CryptoError::Plugin);
    }
    write_plugin_u32(
        output,
        u32::try_from(value.len()).map_err(|_| CryptoError::Plugin)?,
    )?;
    output.write_all(value).map_err(|_| CryptoError::Plugin)
}

fn read_plugin_byte<R: Read>(input: &mut R) -> Result<u8, CryptoError> {
    let mut byte = [0_u8; 1];
    input
        .read_exact(&mut byte)
        .map_err(|_| CryptoError::Plugin)?;
    Ok(byte[0])
}

fn read_plugin_u32<R: Read>(input: &mut R) -> Result<u32, CryptoError> {
    let mut bytes = [0_u8; 4];
    input
        .read_exact(&mut bytes)
        .map_err(|_| CryptoError::Plugin)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_plugin_field<R: Read>(
    input: &mut R,
    optional: bool,
) -> Result<Option<String>, CryptoError> {
    let length = read_plugin_u32(input)? as usize;
    if length == 0 {
        return if optional {
            Ok(None)
        } else {
            Err(CryptoError::Plugin)
        };
    }
    if length > MAX_PLUGIN_FIELD_BYTES {
        return Err(CryptoError::Plugin);
    }
    let mut bytes = vec![0_u8; length];
    input
        .read_exact(&mut bytes)
        .map_err(|_| CryptoError::Plugin)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| CryptoError::Plugin)
}

fn copy_bounded<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    limit: u64,
) -> Result<(), CryptoError> {
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 32 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|_| CryptoError::Plugin)?;
        if read == 0 {
            return Ok(());
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| CryptoError::Plugin)?)
            .ok_or(CryptoError::InputTooLarge)?;
        if copied > limit {
            return Err(CryptoError::InputTooLarge);
        }
        output
            .write_all(&buffer[..read])
            .map_err(|_| CryptoError::Io)?;
    }
}

fn set_private_worker_directory(path: &Path) -> Result<(), CryptoError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CryptoError::Plugin)?;
    }
    Ok(())
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

#[cfg(unix)]
fn isolate_plugin_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn isolate_plugin_process_group(_command: &mut Command) {}

fn terminate_plugin_process_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        if child.try_wait().ok().flatten().is_none()
            && let Some(pid) = rustix::process::Pid::from_raw(child.id().cast_signed())
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
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
    fn plugin_worker_rejects_malformed_frames_before_crypto() {
        assert!(run_plugin_worker_protocol(b"not-a-worker".as_slice(), Vec::new()).is_err());

        let mut oversized = PLUGIN_WORKER_MAGIC.to_vec();
        oversized.push(1);
        let field_limit = u32::try_from(MAX_PLUGIN_FIELD_BYTES).unwrap_or(u32::MAX);
        oversized.extend_from_slice(&(field_limit + 1).to_be_bytes());
        assert!(run_plugin_worker_protocol(oversized.as_slice(), Vec::new()).is_err());

        let mut too_many_recipients = PLUGIN_WORKER_MAGIC.to_vec();
        too_many_recipients.push(1);
        too_many_recipients.extend_from_slice(&0_u32.to_be_bytes());
        let recipient_limit = u32::try_from(MAX_PLUGIN_RECIPIENTS).unwrap_or(u32::MAX);
        too_many_recipients.extend_from_slice(&(recipient_limit + 1).to_be_bytes());
        assert!(run_plugin_worker_protocol(too_many_recipients.as_slice(), Vec::new()).is_err());
    }

    #[test]
    fn plugin_identity_public_conversion_fails_closed() -> Result<(), CryptoError> {
        let identity = secrecy::SecretString::from(
            age::plugin::Identity::default_for_plugin("foobar")
                .map_err(|_| CryptoError::Identity)?
                .to_string(),
        );
        assert!(matches!(
            recipient_from_identity(&identity),
            Err(CryptoError::PluginIdentityPublic)
        ));
        assert!(!identity_matches_recipient(
            &identity,
            "age1not-a-plugin-recipient"
        ));
        Ok(())
    }

    #[test]
    fn plugin_recipient_matching_is_canonical_and_missing_plugins_fail_closed()
    -> Result<(), CryptoError> {
        let identity = secrecy::SecretString::from(
            age::plugin::Identity::default_for_plugin("nixseal-test-missing")
                .map_err(|_| CryptoError::Identity)?
                .to_string(),
        );
        let recipient = bech32::encode_lower::<bech32::Bech32>(
            bech32::Hrp::parse("age1nixseal-test-missing").map_err(|_| CryptoError::Recipient)?,
            &[],
        )
        .map_err(|_| CryptoError::Recipient)?;
        assert_eq!(normalize_recipient(&recipient)?, recipient);
        assert!(identity_matches_recipient(&identity, &recipient));
        assert!(matches!(
            encrypt(
                b"canary".as_slice(),
                Vec::new(),
                std::slice::from_ref(&recipient)
            ),
            Err(CryptoError::Plugin)
        ));
        Ok(())
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

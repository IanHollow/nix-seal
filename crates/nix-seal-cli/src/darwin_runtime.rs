//! Narrow Darwin-specific volatile runtime preparation and inspection.
//!
//! This module deliberately uses only absolute macOS system executables, never
//! a shell, and accepts one fixed mount root. It contains no secret material.

use anyhow::{Context, Result, bail};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "macos")]
const ROOT: &str = "/var/run/nix-seal";
#[cfg(target_os = "macos")]
const MOUNT_FLAGS: &str = "nosuid,nodev,noexec";
#[cfg(target_os = "macos")]
const TRAVERSAL_MODE: u32 = 0o711;

/// Returns public, non-secret runtime storage diagnostics for `nix-seal doctor`.
pub(crate) fn inspect_runtime(root: &Path) -> serde_json::Value {
    let metadata = fs::symlink_metadata(root).ok();
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;

        let mounted_root = mount_root(root).ok();
        let mount_line = mounted_root.as_ref().and_then(|mount| {
            command_stdout("/sbin/mount", std::iter::empty::<&str>())
                .ok()?
                .lines()
                .find(|line| line.contains(&format!(" on {} ", mount.display())))
                .map(str::to_owned)
        });
        let file_system = mount_line
            .as_ref()
            .and_then(|line| line.strip_prefix("tmpfs on ").map(|_| "tmpfs".to_owned()));
        let mount_flags = MOUNT_FLAGS
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let flags_secure = mount_line.as_ref().is_some_and(|line| {
            mount_flags
                .iter()
                .all(|flag| line.split([',', '(', ')', ' ']).any(|item| item == flag))
        });
        serde_json::json!({
            "root": root,
            "mountRoot": mounted_root,
            "filesystem": file_system,
            "volatileTmpfs": file_system.as_deref() == Some("tmpfs") && flags_secure,
            "requiredMountFlags": mount_flags,
            "mountFlagsSecure": flags_secure,
            "mode": metadata.as_ref().map(|value| format!("{:04o}", value.permissions().mode() & 0o7777)),
            "uid": metadata.as_ref().map(MetadataExt::uid),
            "gid": metadata.as_ref().map(MetadataExt::gid),
            "regularDirectory": metadata.as_ref().is_some_and(|value| value.is_dir() && !value.file_type().is_symlink()),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = metadata;
        serde_json::json!({
            "root": root,
            "filesystem": "unsupported-platform",
            "volatileTmpfs": false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum FileVaultState {
    On,
    Off,
    Unknown,
}

impl FileVaultState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Unknown => "unknown",
        }
    }
}

/// Returns the `FileVault` state without consuming credentials or requiring root.
#[cfg(target_os = "macos")]
pub(crate) fn filevault_state() -> FileVaultState {
    match sanitized_command("/usr/bin/fdesetup")
        .arg("isactive")
        .status()
    {
        Ok(status) if status.success() => FileVaultState::On,
        Ok(status) if status.code() == Some(1) => FileVaultState::Off,
        _ => FileVaultState::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) const fn filevault_state() -> FileVaultState {
    FileVaultState::Unknown
}

/// Verifies the exact filesystem and mount hardening needed for volatile output.
#[cfg(target_os = "macos")]
pub(crate) fn ensure_tmpfs(root: &Path) -> Result<()> {
    if root != Path::new(ROOT)
        && !root.starts_with(Path::new(ROOT).join("users"))
        && root != Path::new(ROOT).join("system")
    {
        bail!("Darwin volatile runtime root is outside the nix-seal tmpfs");
    }
    let status = inspect_runtime(root);
    if status["filesystem"] != "tmpfs" {
        bail!("Darwin volatile runtime is not mounted as tmpfs");
    }
    if status["mountFlagsSecure"] != true {
        bail!("Darwin volatile runtime mount lacks required security flags");
    }
    let mount_root_status = inspect_runtime(Path::new(ROOT));
    if mount_root_status["uid"] != 0 || mount_root_status["mode"] != format!("{TRAVERSAL_MODE:04o}")
    {
        bail!("Darwin volatile runtime mount root has unsafe ownership or mode");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn ensure_tmpfs(_root: &Path) -> Result<()> {
    bail!("Darwin volatile runtime is unavailable on this platform")
}

/// Removes legacy APFS plaintext generations without touching the `v1`
/// ciphertext cache. This intentionally accepts only the conventional
/// per-user fallback location and rejects every link encountered.
pub(crate) fn cleanup_legacy_persistent(root: &Path) -> Result<()> {
    let expected = ["Library", "Caches", "nix-seal"];
    if !root.is_absolute()
        || !root
            .components()
            .rev()
            .take(3)
            .map(std::path::Component::as_os_str)
            .eq(expected.iter().rev().map(std::ffi::OsStr::new))
    {
        bail!("legacy runtime cleanup accepts only ~/Library/Caches/nix-seal");
    }
    let metadata = fs::symlink_metadata(root).context("could not inspect legacy runtime root")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("legacy runtime root is unsafe");
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == "current" {
            let target = fs::read_link(entry.path())?;
            if target.is_absolute()
                || target.components().count() != 1
                || !target
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.starts_with("generation-"))
            {
                bail!("legacy runtime cleanup encountered an unsafe current link");
            }
            fs::remove_file(entry.path())?;
        } else if name.starts_with("generation-") {
            remove_tree_without_links(&entry.path())?;
        }
    }
    Ok(())
}

fn remove_tree_without_links(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        bail!("legacy runtime cleanup encountered a symlink");
    }
    if metadata.is_file() {
        fs::remove_file(path)?;
    } else if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_tree_without_links(&entry?.path())?;
        }
        fs::remove_dir(path)?;
    } else {
        bail!("legacy runtime cleanup encountered an unsafe file type");
    }
    Ok(())
}

/// Mounts the fixed shared tmpfs and creates private roots for embedded users.
#[cfg(target_os = "macos")]
pub(crate) fn prepare(root: &Path, users: &[String], size: &str) -> Result<PathBuf> {
    if root != Path::new(ROOT) {
        bail!("Darwin volatile runtime root must be {ROOT}");
    }
    if rustix::process::geteuid().as_raw() != 0 {
        bail!("Darwin volatile runtime preparation requires root");
    }
    if users.len() > 256 || users.iter().any(|user| !valid_username(user)) || !valid_size(size) {
        bail!("Darwin volatile runtime users are invalid");
    }
    ensure_existing_directory(root)?;
    if !is_tmpfs(root)? {
        let status = sanitized_command("/sbin/mount_tmpfs")
            .args(["-s", size, "-o", MOUNT_FLAGS])
            .arg(root)
            .status()
            .context("could not run mount_tmpfs")?;
        if !status.success() && !is_tmpfs(root)? {
            bail!("could not mount the Darwin volatile runtime tmpfs");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(TRAVERSAL_MODE))
        .context("could not set Darwin volatile runtime mount root mode")?;
    ensure_tmpfs(root)?;
    create_private_root(&root.join("system"), 0, 0)?;
    let users_root = root.join("users");
    create_directory(&users_root, TRAVERSAL_MODE)?;
    for user in users {
        let (uid, gid) = resolve_user(user)?;
        create_private_root(&users_root.join(user), uid, gid)?;
    }
    Ok(root.to_owned())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn prepare(_root: &Path, _users: &[String], _size: &str) -> Result<PathBuf> {
    bail!("Darwin volatile runtime is unavailable on this platform")
}

#[cfg(target_os = "macos")]
fn mount_root(root: &Path) -> Result<PathBuf> {
    let canonical = root
        .canonicalize()
        .context("could not canonicalize Darwin volatile runtime root")?;
    let mut current = PathBuf::from("/");
    let mut mounted = None;
    for component in canonical.components() {
        if let std::path::Component::Normal(segment) = component {
            current.push(segment);
            if is_tmpfs(&current)? {
                mounted = Some(current.clone());
            }
        }
    }
    mounted.context("Darwin volatile tmpfs mount is missing")
}

#[cfg(target_os = "macos")]
fn is_tmpfs(path: &Path) -> Result<bool> {
    let canonical = path
        .canonicalize()
        .context("could not canonicalize Darwin volatile runtime path")?;
    let mounts = command_stdout("/sbin/mount", std::iter::empty::<&str>())?;
    Ok(mounts.lines().any(|line| {
        line.starts_with("tmpfs on ") && line.contains(&format!(" on {} ", canonical.display()))
    }))
}

#[cfg(target_os = "macos")]
fn ensure_existing_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => bail!("Darwin volatile runtime mount root is not a regular directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).context("could not create Darwin volatile runtime mount root")?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn create_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("Darwin volatile runtime contains an unsafe path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn create_private_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    create_directory(path, 0o700)?;
    let owner = format!("{uid}:{gid}");
    let status = sanitized_command("/usr/sbin/chown")
        .arg(owner)
        .arg(path)
        .status()
        .context("could not set Darwin volatile runtime ownership")?;
    if !status.success() {
        bail!("could not set Darwin volatile runtime ownership");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("Darwin volatile runtime ownership or mode verification failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn resolve_user(user: &str) -> Result<(u32, u32)> {
    let output = command_stdout(
        "/usr/bin/dscl",
        [
            ".",
            "-read",
            &format!("/Users/{user}"),
            "UniqueID",
            "PrimaryGroupID",
        ],
    )?;
    parse_dscl_ids(&output).context("could not resolve Darwin Home Manager account")
}

#[cfg(target_os = "macos")]
fn sanitized_command(executable: &str) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(target_os = "macos")]
fn command_stdout<I, S>(executable: &str, arguments: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = sanitized_command(executable)
        .args(arguments)
        .output()
        .with_context(|| format!("could not run {executable}"))?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        bail!("{executable} did not return accepted runtime metadata");
    }
    String::from_utf8(output.stdout).context("runtime metadata was not UTF-8")
}

#[cfg(any(target_os = "macos", test))]
fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(any(target_os = "macos", test))]
fn valid_size(value: &str) -> bool {
    let Some((digits, suffix)) = value.split_at_checked(value.len().saturating_sub(1)) else {
        return false;
    };
    let multiplier = match suffix {
        "m" | "M" => 1,
        "g" | "G" => 1024,
        _ => return false,
    };
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && digits
            .parse::<u32>()
            .ok()
            .and_then(|size| size.checked_mul(multiplier))
            .is_some_and(|megabytes| (16..=4096).contains(&megabytes))
}

#[cfg(any(target_os = "macos", test))]
fn parse_dscl_ids(output: &str) -> Option<(u32, u32)> {
    let parse = |label: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(label))?
            .trim()
            .parse::<u32>()
            .ok()
    };
    Some((parse("UniqueID:")?, parse("PrimaryGroupID:")?))
}

#[cfg(test)]
mod tests {
    use super::{parse_dscl_ids, valid_size, valid_username};

    #[test]
    fn accepts_only_safe_account_names() {
        assert!(valid_username("ianmh"));
        assert!(valid_username("build-user_1"));
        assert!(!valid_username("../root"));
        assert!(!valid_username("name with space"));
        assert!(!valid_username(""));
    }

    #[test]
    fn parses_dscl_numeric_ids() {
        assert_eq!(
            parse_dscl_ids("UniqueID: 501\nPrimaryGroupID: 20\n"),
            Some((501, 20))
        );
        assert_eq!(parse_dscl_ids("UniqueID: no\nPrimaryGroupID: 20\n"), None);
    }

    #[test]
    fn accepts_bounded_tmpfs_sizes() {
        assert!(valid_size("256m"));
        assert!(valid_size("1G"));
        assert!(!valid_size("15m"));
        assert!(!valid_size("4097m"));
        assert!(!valid_size("256"));
    }
}

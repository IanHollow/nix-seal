//! Linux-specific volatile runtime preparation and inspection.
//!
//! NixOS owns the mount declaration. This module verifies that the mounted
//! filesystem is the expected `tmpfs` with the explicit `noswap`, `nosuid`,
//! `nodev`, and `noexec` options, then creates private system and user roots.
//! It never attempts a fallback to persistent storage.

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(any(target_os = "linux", test))]
use std::collections::BTreeSet;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
const ROOT: &str = "/run/nix-seal";
const REQUIRED_FLAGS: [&str; 4] = ["noswap", "nosuid", "nodev", "noexec"];

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "linux", test))]
struct MountInfo {
    mountpoint: PathBuf,
    filesystem: String,
    options: BTreeSet<String>,
}

/// Returns public, non-secret Linux runtime diagnostics for `nix-seal doctor`.
pub(crate) fn inspect_runtime(root: &Path) -> serde_json::Value {
    let metadata = fs::symlink_metadata(root).ok();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mount = fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|contents| find_mount(&contents, root));
        let filesystem = mount.as_ref().map(|value| value.filesystem.clone());
        let options = mount
            .as_ref()
            .map(|value| value.options.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        let flags_secure = mount.as_ref().is_some_and(|value| {
            value.filesystem == "tmpfs"
                && REQUIRED_FLAGS
                    .iter()
                    .all(|flag| value.options.contains(*flag))
        });
        serde_json::json!({
            "root": root,
            "mountRoot": mount.as_ref().map(|value| &value.mountpoint),
            "filesystem": filesystem,
            "volatileTmpfsNoSwap": flags_secure,
            "noswap": mount.as_ref().is_some_and(|value| value.options.contains("noswap")),
            "requiredMountFlags": REQUIRED_FLAGS,
            "mountFlagsSecure": flags_secure,
            "mountOptions": options,
            "mode": metadata.as_ref().map(|value| format!("{:04o}", value.permissions().mode() & 0o7777)),
            "uid": metadata.as_ref().map(MetadataExt::uid),
            "gid": metadata.as_ref().map(MetadataExt::gid),
            "regularDirectory": metadata.as_ref().is_some_and(|value| value.is_dir() && !value.file_type().is_symlink()),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = metadata;
        serde_json::json!({
            "root": root,
            "filesystem": "unsupported-platform",
            "volatileTmpfsNoSwap": false,
            "noswap": false,
            "requiredMountFlags": REQUIRED_FLAGS,
            "mountFlagsSecure": false,
        })
    }
}

/// Fail closed unless the runtime is inside the fixed NixOS `noswap` tmpfs.
pub(crate) fn ensure_noswap_tmpfs(root: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        validate_runtime_path(root)?;
        let mount = fs::read_to_string("/proc/self/mountinfo")
            .context("could not read Linux mount information")
            .and_then(|contents| {
                find_mount(&contents, root).context("nix-seal tmpfs mount is missing")
            })?;
        if mount.mountpoint != Path::new(ROOT) {
            bail!("Linux volatile runtime is not mounted at {ROOT}");
        }
        if mount.filesystem != "tmpfs" {
            bail!("Linux volatile runtime is not mounted as tmpfs");
        }
        if let Ok(metadata) = fs::symlink_metadata(root) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("Linux volatile runtime root is not a regular directory");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                let mode = metadata.permissions().mode() & 0o7777;
                if root == Path::new(ROOT) {
                    if metadata.uid() != 0 || metadata.gid() != 0 || mode != 0o711 {
                        bail!("Linux volatile runtime mount root has unsafe ownership or mode");
                    }
                } else if mode & 0o077 != 0 {
                    bail!(
                        "Linux volatile runtime child root is accessible by group or other users"
                    );
                }
            }
        }
        if !REQUIRED_FLAGS
            .iter()
            .all(|flag| mount.options.contains(*flag))
        {
            bail!("Linux volatile runtime tmpfs lacks required noswap or restrictive mount flags");
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        bail!("Linux volatile runtime is unavailable on this platform");
    }
}

/// Prepare the NixOS system root and private Home Manager user roots.
pub(crate) fn prepare(root: &Path, users: &[String]) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        if root != Path::new(ROOT) {
            bail!("Linux volatile runtime root must be {ROOT}");
        }
        if rustix::process::geteuid().as_raw() != 0 {
            bail!("Linux volatile runtime preparation requires root");
        }
        if users.len() > 256 || users.iter().any(|user| !valid_username(user)) {
            bail!("Linux volatile runtime users are invalid");
        }
        ensure_noswap_tmpfs(root)?;
        create_private_root(&root.join("system"), 0, 0)?;
        create_directory(&root.join("users"), 0o755, 0, 0)?;
        for user in users {
            let account = uzers::get_user_by_name(user)
                .with_context(|| format!("could not resolve Linux Home Manager account {user}"))?;
            create_private_root(
                &root.join("users").join(user),
                account.uid(),
                account.primary_group_id(),
            )?;
        }
        Ok(root.to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, users);
        bail!("Linux volatile runtime is unavailable on this platform");
    }
}

#[cfg(any(target_os = "linux", test))]
fn find_mount(contents: &str, root: &Path) -> Option<MountInfo> {
    contents
        .lines()
        .filter_map(parse_mountinfo_line)
        .filter(|mount| root == mount.mountpoint || root.starts_with(&mount.mountpoint))
        .max_by_key(|mount| mount.mountpoint.components().count())
}

#[cfg(any(target_os = "linux", test))]
fn parse_mountinfo_line(line: &str) -> Option<MountInfo> {
    let (left, right) = line.split_once(" - ")?;
    let left_fields = left.split_whitespace().collect::<Vec<_>>();
    let right_fields = right.split_whitespace().collect::<Vec<_>>();
    let mountpoint = decode_mount_field(left_fields.get(4)?)?;
    let mut options = BTreeSet::new();
    for value in left_fields
        .get(5)?
        .split(',')
        .chain(right_fields.get(2)?.split(','))
    {
        options.insert(value.to_owned());
    }
    Some(MountInfo {
        mountpoint: PathBuf::from(mountpoint),
        filesystem: right_fields.first()?.to_string(),
        options,
    })
}

#[cfg(any(target_os = "linux", test))]
fn decode_mount_field(value: &str) -> Option<String> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let code = chars.by_ref().take(3).collect::<String>();
        match code.as_str() {
            "040" => decoded.push(' '),
            "011" => decoded.push('\t'),
            "134" => decoded.push('\\'),
            _ => return None,
        }
    }
    Some(decoded)
}

#[cfg(target_os = "linux")]
fn validate_runtime_path(root: &Path) -> Result<()> {
    if root.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        bail!("Linux volatile runtime root contains dot path components");
    }
    if root != Path::new(ROOT)
        && !root.starts_with(Path::new(ROOT).join("system"))
        && !root.starts_with(Path::new(ROOT).join("users"))
    {
        bail!("Linux volatile runtime root is outside the nix-seal tmpfs");
    }
    let mut current = PathBuf::from(ROOT);
    for component in root.strip_prefix(ROOT)?.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            if let Ok(metadata) = fs::symlink_metadata(&current)
                && (metadata.file_type().is_symlink() || !metadata.is_dir())
            {
                bail!("Linux volatile runtime contains an unsafe path component");
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(target_os = "linux")]
fn create_directory(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("Linux volatile runtime contains an unsafe path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error.into()),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    rustix::fs::chown(
        path,
        Some(rustix::process::Uid::from_raw(uid)),
        Some(rustix::process::Gid::from_raw(gid)),
    )?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o777 != mode & 0o777
    {
        bail!("Linux volatile runtime ownership or mode verification failed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_private_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    create_directory(path, 0o700, uid, gid)
}

#[cfg(test)]
mod tests {
    use super::{find_mount, parse_mountinfo_line};
    use std::path::Path;

    const TMPFS_LINE: &str = "42 24 0:40 / /run/nix-seal rw,nosuid,nodev,noexec,noswap,relatime - tmpfs tmpfs rw,nosuid,nodev,noexec,noswap";

    #[test]
    fn parses_linux_tmpfs_mount_flags() -> Result<(), &'static str> {
        let mount = parse_mountinfo_line(TMPFS_LINE).ok_or("valid mountinfo")?;
        assert_eq!(mount.mountpoint, Path::new("/run/nix-seal"));
        assert_eq!(mount.filesystem, "tmpfs");
        assert!(mount.options.contains("noswap"));
        assert!(mount.options.contains("noexec"));
        Ok(())
    }

    #[test]
    fn selects_the_longest_matching_mount() -> Result<(), &'static str> {
        let contents = format!("{TMPFS_LINE}\n43 24 0:41 / /run rw,relatime - ext4 /dev/root rw\n");
        let mount = find_mount(&contents, Path::new("/run/nix-seal/system/users/alice"))
            .ok_or("matching mount")?;
        assert_eq!(mount.mountpoint, Path::new("/run/nix-seal"));
        Ok(())
    }

    #[test]
    fn rejects_mounts_without_noswap() -> Result<(), &'static str> {
        let line = TMPFS_LINE.replace(",noswap", "");
        let mount = parse_mountinfo_line(&line).ok_or("valid mountinfo")?;
        assert!(!mount.options.contains("noswap"));
        Ok(())
    }
}

#![forbid(unsafe_code)]
//! End-to-end plan-directed CLI authoring guarantees.

use nix_seal_core::{
    ActivationPhase, DeliveryMode, Id, Identity, IdentityKind, Lifecycle, PlanV1, RuntimeSettings,
    Secret,
};
use secrecy::ExposeSecret;
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[test]
fn plan_directed_create_rotate_and_reveal() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let root = &fixture.root;
    let plan_path = &fixture.plan_path;
    let identity_path = &fixture.identity_path;

    let created = run_with_stdin(
        root,
        &[
            "secret",
            "create",
            "--plan",
            path_text(plan_path)?,
            "--repository-root",
            path_text(root)?,
            "--secret",
            "db/password",
            "--identity",
            path_text(identity_path)?,
        ],
        b"initial-value",
    )?;
    assert!(created.status.success());
    assert!(
        !created
            .stdout
            .windows(13)
            .any(|window| window == b"initial-value")
    );
    let checked = run(
        root,
        &[
            "check",
            "--nix-plan",
            path_text(plan_path)?,
            "--deep",
            "--repository-root",
            path_text(root)?,
        ],
    )?;
    assert!(checked.status.success());

    let revealed = run(root, &reveal_args(plan_path, root, identity_path)?)?;
    assert!(revealed.status.success());
    assert_eq!(revealed.stdout, b"initial-value");

    let rotated = run_with_stdin(
        root,
        &[
            "rotate",
            "--plan",
            path_text(plan_path)?,
            "--repository-root",
            path_text(root)?,
            "--secret",
            "db/password",
            "--identity",
            path_text(identity_path)?,
        ],
        b"rotated-value",
    )?;
    assert!(rotated.status.success());
    assert!(String::from_utf8(rotated.stderr)?.contains("record lifecycle.rotatedAt = "));
    let revealed = run(root, &reveal_args(plan_path, root, identity_path)?)?;
    assert_eq!(revealed.stdout, b"rotated-value");

    let forbidden_json = run(
        root,
        &[
            "--json",
            "secret",
            "reveal",
            "--plan",
            path_text(plan_path)?,
            "--repository-root",
            path_text(root)?,
            "--secret",
            "db/password",
            "--identity",
            path_text(identity_path)?,
        ],
    )?;
    assert!(!forbidden_json.status.success());
    assert!(forbidden_json.stdout.is_empty());
    Ok(())
}

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    plan_path: PathBuf,
    identity_path: PathBuf,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().canonicalize()?;
    let plan_path = root.join("plan.v1.json");
    let identity_path = root.join("admin.identity");
    let (identity, recipient) = nix_seal_crypto::generate_x25519();
    write_private(&identity_path, identity.expose_secret().as_bytes())?;

    let mut plan = PlanV1::default();
    plan.identities.insert(
        Id::parse("admin")?,
        Identity {
            kind: IdentityKind::Administrator,
            public: recipient,
        },
    );
    plan.identities.insert(
        Id::parse("signer")?,
        Identity {
            kind: IdentityKind::Signer,
            public: nix_seal_manifest::ApprovalSigningKey::generate()?.encode_public(),
        },
    );
    plan.secrets.insert(
        Id::parse("db/password")?,
        Secret {
            source: "secrets/db.age".to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
        },
    );
    nix_seal_policy::validate(&plan)?;
    std::fs::write(&plan_path, nix_seal_policy::canonical_json(&plan)?)?;
    Ok(Fixture {
        _temporary: temporary,
        root,
        plan_path,
        identity_path,
    })
}

fn reveal_args<'a>(
    plan: &'a Path,
    root: &'a Path,
    identity: &'a Path,
) -> Result<[&'a str; 10], Box<dyn std::error::Error>> {
    Ok([
        "secret",
        "reveal",
        "--plan",
        path_text(plan)?,
        "--repository-root",
        path_text(root)?,
        "--secret",
        "db/password",
        "--identity",
        path_text(identity)?,
    ])
}

fn path_text(path: &Path) -> Result<&str, Box<dyn std::error::Error>> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}

fn run(root: &Path, arguments: &[&str]) -> Result<std::process::Output, std::io::Error> {
    Command::new(env!("CARGO_BIN_EXE_nix-seal"))
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
}

fn run_with_stdin(
    root: &Path,
    arguments: &[&str],
    value: &[u8],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nix-seal"))
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("child stdin is unavailable")?
        .write_all(value)?;
    Ok(child.wait_with_output()?)
}

fn write_private(path: &Path, value: &[u8]) -> Result<(), std::io::Error> {
    let mut file = File::create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(value)?;
    file.sync_all()
}

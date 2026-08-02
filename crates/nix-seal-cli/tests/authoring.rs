#![forbid(unsafe_code)]
//! End-to-end plan-directed CLI authoring guarantees.

use nix_seal_core::{
    ActivationPhase, DeliveryMode, Id, Identity, IdentityKind, Lifecycle, PlanV1, RuntimeSettings,
    Secret, TargetSelectors,
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
    assert!(
        checked.status.success(),
        "deep check failed: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

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

#[test]
fn plan_directed_delete_is_explicit_and_recoverable() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let create = run_with_stdin(
        &fixture.root,
        &[
            "secret",
            "create",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--secret",
            "db/password",
            "--identity",
            path_text(&fixture.identity_path)?,
        ],
        b"delete-canary",
    )?;
    assert!(create.status.success());
    let source = fixture.root.join("secrets/db.age");
    let ciphertext = std::fs::read(&source)?;

    let without_acknowledgement = run(
        &fixture.root,
        &[
            "secret",
            "delete",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--secret",
            "db/password",
        ],
    )?;
    assert!(!without_acknowledgement.status.success());
    assert_eq!(std::fs::read(&source)?, ciphertext);

    let deleted = run(
        &fixture.root,
        &[
            "--json",
            "secret",
            "delete",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--secret",
            "db/password",
            "--yes",
        ],
    )?;
    assert!(deleted.status.success());
    assert!(!source.exists());
    assert!(
        !deleted
            .stdout
            .windows(13)
            .any(|value| value == b"delete-canary")
    );
    let output: serde_json::Value = serde_json::from_slice(&deleted.stdout)?;
    let tombstone = PathBuf::from(
        output["tombstonePath"]
            .as_str()
            .ok_or("missing tombstone path")?,
    );
    assert_eq!(std::fs::read(tombstone.join("ciphertext.age"))?, ciphertext);

    let deep_check = run(
        &fixture.root,
        &[
            "check",
            "--nix-plan",
            path_text(&fixture.plan_path)?,
            "--deep",
            "--repository-root",
            path_text(&fixture.root)?,
        ],
    )?;
    assert!(!deep_check.status.success());
    Ok(())
}

#[test]
fn logical_collection_batch_authors_independent_ciphertexts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let mut plan: PlanV1 = serde_json::from_slice(&std::fs::read(&fixture.plan_path)?)?;
    plan.secrets.insert(
        Id::parse("db/token")?,
        Secret {
            source: "secrets/token.age".to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            selectors: TargetSelectors::default(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            runtime_overrides: Default::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
            repository_only: false,
        },
    );
    nix_seal_policy::validate(&plan)?;
    std::fs::write(&fixture.plan_path, nix_seal_policy::canonical_json(&plan)?)?;
    let mapping = fixture.root.join("collection-map.json");
    std::fs::write(
        &mapping,
        br#"{
          "schema": "nix-seal.collection.v1",
          "entries": [
            {"secret": "db/password", "path": "database.password"},
            {"secret": "db/token", "path": "database.token"}
          ]
        }"#,
    )?;
    let authored = run_with_stdin(
        &fixture.root,
        &[
            "--json",
            "secret",
            "batch",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--identity",
            path_text(&fixture.identity_path)?,
            "--mapping",
            path_text(&mapping)?,
            "--format",
            "json",
        ],
        br#"{"database":{"password":"batch-password","token":"batch-token"}}"#,
    )?;
    assert!(
        authored.status.success(),
        "batch authoring failed: {}",
        String::from_utf8_lossy(&authored.stderr)
    );
    assert!(
        !authored
            .stdout
            .windows(14)
            .any(|window| window == b"batch-password")
    );
    assert!(
        !authored
            .stdout
            .windows(10)
            .any(|window| window == b"batch-token")
    );
    let password = run(
        &fixture.root,
        &[
            "secret",
            "reveal",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--secret",
            "db/password",
            "--identity",
            path_text(&fixture.identity_path)?,
        ],
    )?;
    assert_eq!(password.stdout, b"batch-password");
    let token = run(
        &fixture.root,
        &[
            "secret",
            "reveal",
            "--plan",
            path_text(&fixture.plan_path)?,
            "--repository-root",
            path_text(&fixture.root)?,
            "--secret",
            "db/token",
            "--identity",
            path_text(&fixture.identity_path)?,
        ],
    )?;
    assert_eq!(token.stdout, b"batch-token");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn production_generator_worker_emits_a_bounded_isolation_status()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let workspace = temporary.path().join("workspace");
    let outputs = workspace.join("outputs");
    let public_outputs = workspace.join("public-outputs");
    let prompts = workspace.join("prompts");
    let secrets = workspace.join("secrets");
    for directory in [&workspace, &outputs, &public_outputs, &prompts, &secrets] {
        std::fs::create_dir(directory)?;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_nix-seal"))
        .arg("__generator-worker")
        .arg("--executable")
        .arg(env!("CARGO_BIN_EXE_nix-seal"))
        .arg("--workspace")
        .arg(&workspace)
        .arg("--output-directory")
        .arg(&outputs)
        .arg("--public-output-directory")
        .arg(&public_outputs)
        .arg("--prompt-directory")
        .arg(&prompts)
        .arg("--prompt-count")
        .arg("0")
        .arg("--secret-directory")
        .arg(&secrets)
        .arg("--secret-count")
        .arg("0")
        .arg("--output-count")
        .arg("0")
        .arg("--public-output-count")
        .arg("0")
        .env_clear()
        .env("NIX_SEAL_GENERATOR_WORKER", "1")
        .output()?;
    let magic = b"nix-seal-generator-worker-v1\n";
    assert!(output.stdout.starts_with(magic));
    assert_eq!(output.stdout.len(), magic.len() + 1);
    assert!(matches!(output.stdout.last(), Some(0 | 1)));
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
            public: nix_seal_manifest::ApprovalSigningKey::generate()?.encode_public()?,
        },
    );
    plan.secrets.insert(
        Id::parse("db/password")?,
        Secret {
            source: "secrets/db.age".to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            selectors: TargetSelectors::default(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            runtime_overrides: Default::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
            repository_only: false,
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

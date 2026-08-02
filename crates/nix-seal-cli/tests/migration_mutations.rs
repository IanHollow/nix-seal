#![forbid(unsafe_code)]
//! Negative migration fixtures. Each mutation must fail before it emits a
//! migration report or changes a source tree.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::{ffi::OsString, path::Path, process::Command};

const FIXTURE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-mutations"
);
const PUBLIC_AGE_FIXTURE: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBUNHQvVGhqamJ1RG9jMnJwVzA3dnI3bWd4RHFoakM5Q205UmhsbXBRT0JjClJZcnZnTFNORWlOc2kxaVVKVlJWeERBaGVJSVpRelpMV0taU293aWdOdGcKLS0tIGt3cWJwdmhHaTd3V2RQNWNoSk1HTE1SV3RwcFZGRGM2VEJoRDZ1VFE3MW8KO/7gWgxZblFTMbqttXFt7ydx1T99f1GghKjdb+JQPv7qhCCjEP/GEssJF7hITV64tA==";

fn run_failure(arguments: &[OsString]) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-seal"))
        .args(arguments)
        .output()?;
    assert!(!output.status.success(), "mutation unexpectedly succeeded");
    assert!(
        output.stdout.is_empty(),
        "failed migrations must not emit a public report"
    );
    Ok(output)
}

#[test]
fn structured_mutation_fixtures_fail_closed_without_a_report()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;

    let agenix_metadata = temporary.path().join("agenix-rekey.json");
    std::fs::copy(
        Path::new(FIXTURE_ROOT).join("agenix-rekey/path-traversal.json"),
        &agenix_metadata,
    )?;
    let _ = run_failure(&[
        "migrate".into(),
        "agenix-rekey".into(),
        "--metadata".into(),
        agenix_metadata.into_os_string(),
        "--json".into(),
    ])?;

    let sops_directory = temporary.path().join("sops");
    std::fs::create_dir(&sops_directory)?;
    std::fs::copy(
        Path::new(FIXTURE_ROOT).join("sops-json/invalid-age-recipient.json"),
        sops_directory.join("token.json"),
    )?;
    let _ = run_failure(&[
        "migrate".into(),
        "sops-json".into(),
        "--directory".into(),
        sops_directory.into_os_string(),
        "--json".into(),
    ])?;

    assert!(!temporary.path().join("migrated").exists());
    Ok(())
}

#[cfg(unix)]
fn write_public_age(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, BASE64.decode(PUBLIC_AGE_FIXTURE)?)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn agenix_symlink_mutation_fails_without_reading_outside_tree()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("agenix");
    let real = root.join("real");
    let outside = temporary.path().join("outside");
    std::fs::create_dir_all(&real)?;
    std::fs::create_dir(&outside)?;
    write_public_age(&real.join("token.age"))?;
    std::fs::write(outside.join("sentinel"), b"unchanged")?;
    symlink(&outside, root.join("linked"))?;

    let _ = run_failure(&[
        "migrate".into(),
        "agenix".into(),
        "--directory".into(),
        root.into_os_string(),
        "--json".into(),
    ])?;
    assert_eq!(std::fs::read(outside.join("sentinel"))?, b"unchanged");
    Ok(())
}

#[cfg(unix)]
#[test]
fn clan_vars_and_facts_symlink_mutations_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let vars = temporary.path().join("vars");
    std::fs::create_dir_all(vars.join("desktop/generator/output"))?;
    std::fs::write(vars.join("desktop/generator/output/value"), b"opaque")?;
    let vars_outside = temporary.path().join("vars-outside");
    std::fs::create_dir(&vars_outside)?;
    symlink(&vars_outside, vars.join("linked"))?;
    let _ = run_failure(&[
        "migrate".into(),
        "clan-vars".into(),
        "--directory".into(),
        vars.into_os_string(),
        "--json".into(),
    ])?;

    let facts = temporary.path().join("machines");
    std::fs::create_dir_all(facts.join("desktop/facts"))?;
    std::fs::write(facts.join("desktop/facts/serial"), b"public")?;
    let facts_outside = temporary.path().join("facts-outside");
    std::fs::create_dir(&facts_outside)?;
    symlink(&facts_outside, facts.join("linked"))?;
    let _ = run_failure(&[
        "migrate".into(),
        "clan-facts".into(),
        "--directory".into(),
        facts.into_os_string(),
        "--json".into(),
    ])?;

    Ok(())
}

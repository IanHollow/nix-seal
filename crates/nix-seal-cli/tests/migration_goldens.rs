#![forbid(unsafe_code)]
//! Public migration compatibility goldens.
//!
//! These fixtures contain only public metadata or empty/public leaves. The
//! tests exercise the actual released binary and compare its versioned JSON
//! reports to checked-in outputs, without opening a private identity or
//! decrypting a legacy value.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;
use std::{path::Path, process::Command};

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/migrations");

fn run_json(arguments: &[String]) -> Result<Value, Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-seal"))
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "nix-seal migration failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn golden(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(Path::new(FIXTURE_ROOT).join(name))?;
    Ok(serde_json::from_str(&contents)?)
}

#[test]
fn public_migration_reports_match_versioned_goldens() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(FIXTURE_ROOT);
    let path = |relative: &str| -> Result<String, Box<dyn std::error::Error>> {
        Ok(root.join(relative).to_str().ok_or("path")?.to_owned())
    };
    let cases = vec![
        (
            vec![
                "migrate".to_owned(),
                "agenix-rekey".to_owned(),
                "--metadata".to_owned(),
                path("agenix-rekey/export.json")?,
                "--json".to_owned(),
            ],
            "../migration-goldens/agenix-rekey.json",
        ),
        (
            vec![
                "migrate".to_owned(),
                "sops-json".to_owned(),
                "--directory".to_owned(),
                path("sops-json")?,
                "--json".to_owned(),
            ],
            "../migration-goldens/sops-json.json",
        ),
        (
            vec![
                "migrate".to_owned(),
                "clan-vars".to_owned(),
                "--directory".to_owned(),
                path("clan-vars")?,
                "--json".to_owned(),
            ],
            "../migration-goldens/clan-vars.json",
        ),
        (
            vec![
                "migrate".to_owned(),
                "clan-facts".to_owned(),
                "--directory".to_owned(),
                path("clan-facts")?,
                "--json".to_owned(),
            ],
            "../migration-goldens/clan-facts.json",
        ),
    ];
    for (arguments, expected_path) in cases {
        assert_eq!(
            run_json(&arguments)?,
            golden(expected_path)?,
            "{expected_path}"
        );
    }
    Ok(())
}

#[test]
fn age_and_ragenix_inventory_golden_is_interoperable() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempfile::tempdir()?;
    let legacy = temporary.path().join("legacy/nested");
    std::fs::create_dir_all(&legacy)?;
    // Public age ciphertext fixture generated with the documented X25519
    // recipient. The private identity and plaintext are intentionally absent.
    let ciphertext = BASE64.decode(
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBUNHQvVGhqamJ1RG9jMnJwVzA3dnI3bWd4RHFoakM5Q205UmhsbXBRT0JjClJZcnZnTFNORWlOc2kxaVVKVlJWeERBaGVJSVpRelpMV0taU293aWdOdGcKLS0tIGt3cWJwdmhHaTd3V2RQNWNoSk1HTE1SV3RwcWZZRGM2VEJoRDZ1VFE3MW8KO/7gWgxZblFTMbqttXFt7ydx1T99f1GghKjdb+JQPv7qhCCjEP/GEssJF7hITV64tA==",
    )?;
    std::fs::write(legacy.join("token.age"), ciphertext)?;
    for source in ["agenix", "ragenix"] {
        let arguments = vec![
            "migrate".to_owned(),
            source.to_owned(),
            "--directory".to_owned(),
            temporary
                .path()
                .join("legacy")
                .to_str()
                .ok_or("path")?
                .to_owned(),
            "--json".to_owned(),
        ];
        let mut expected = serde_json::json!({
            "dryRun": true,
            "recipientPolicy": null,
            "schema": "nix-seal.migration-report.v1",
            "secrets": [{
                "legacyId": "nested/token",
                "nixSealId": format!("{source}/nested/token"),
                "source": "nested/token.age"
            }],
            "source": source,
            "warnings": []
        });
        expected["warnings"] = serde_json::json!([
            "dry run only: no ciphertext, configuration, or source manager was changed",
            "ciphertext headers were validated but recipient policy is not encoded in agenix ciphertext paths; provide an explicit nix-seal recipient and target mapping before import",
            "only regular .age files were accepted; symlinks and non-regular entries are rejected"
        ]);
        assert_eq!(run_json(&arguments)?, expected, "{source}");
    }
    Ok(())
}

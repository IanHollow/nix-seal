#![forbid(unsafe_code)]

//! Reproducible scale measurements for the public policy path.
//!
//! The benchmark reports machine-readable samples for the documented
//! 1/100/1,000/10,000 object sizes. It uses synthetic metadata only and never
//! prints or persists decrypted values.

use nix_seal_core::{
    ActivationPhase, DeliveryMode, Id, Identity, IdentityKind, Lifecycle, PlanV2, RuntimeSettings,
    Secret, Target, TargetKind, TargetSelectors,
};
use nix_seal_policy::{canonical_json, target_policy, validate};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::Cursor,
    process,
    time::{Duration, Instant},
};

const RECIPIENT: &str = "age1ml79lp4sk2gz59n3xux5xhasg7p5qa0pnm634rd8pnw80avag4js2etr0l";
const SIGNER: &str = "nix-seal-ed25519-v1:EcFcZVkcYsuXdMDG2JyOsyuoCExdGk0yUwLVriY0Vyw=";
const DEFAULT_SIZES: &[usize] = &[1, 100, 1_000, 10_000];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Sample {
    schema: &'static str,
    package_version: &'static str,
    os: &'static str,
    arch: &'static str,
    secrets: usize,
    targets: usize,
    plan_bytes: usize,
    target_policy_bytes: usize,
    validation_ms: u128,
    canonicalization_ms: u128,
    target_policy_ms: u128,
    encryption_ms: u128,
    encryption_iterations: usize,
}

fn main() {
    let sizes = requested_sizes();
    let mut failed = false;
    for size in sizes {
        match run_sample(size) {
            Ok(sample) => match serde_json::to_string(&sample) {
                Ok(line) => println!("{line}"),
                Err(error) => {
                    eprintln!("unable to encode benchmark result: {error}");
                    failed = true;
                }
            },
            Err(error) => {
                eprintln!("benchmark case failed for size {size}: {error}");
                failed = true;
            }
        }
    }
    if failed {
        process::exit(1);
    }
}

fn requested_sizes() -> Vec<usize> {
    let mut sizes = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        if let Some(value) = argument.strip_prefix("--size=") {
            if let Ok(size) = value.parse::<usize>() {
                sizes.push(size);
            }
        } else if argument == "--size"
            && let Some(value) = args.next()
            && let Ok(size) = value.parse::<usize>()
        {
            sizes.push(size);
        }
    }
    if sizes.is_empty() {
        DEFAULT_SIZES.to_vec()
    } else {
        sizes
    }
}

fn run_sample(size: usize) -> Result<Sample, Box<dyn std::error::Error>> {
    if !(1..=10_000).contains(&size) {
        return Err("size must be between 1 and 10000".into());
    }
    let plan = build_plan(size)?;

    let started = Instant::now();
    validate(&plan)?;
    let validation_ms = elapsed_ms(started.elapsed());

    let started = Instant::now();
    let plan_json = canonical_json(&plan)?;
    let canonicalization_ms = elapsed_ms(started.elapsed());

    let target_id = Id::parse("target-00000")?;
    let started = Instant::now();
    let target = target_policy(&plan, &target_id)?;
    let target_policy_json = nix_seal_policy::canonical_target_policy_json(&target)?;
    let target_policy_ms = elapsed_ms(started.elapsed());

    let payload = vec![0x5a; 1024];
    let started = Instant::now();
    for _ in 0..size {
        let mut encrypted = Vec::with_capacity(payload.len() + 256);
        nix_seal_crypto::encrypt(
            Cursor::new(payload.as_slice()),
            &mut encrypted,
            &[RECIPIENT.to_owned()],
        )?;
        std::hint::black_box(encrypted);
    }
    let encryption_ms = elapsed_ms(started.elapsed());

    Ok(Sample {
        schema: "nix-seal.benchmark.v1",
        package_version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        secrets: size,
        targets: size,
        plan_bytes: plan_json.len(),
        target_policy_bytes: target_policy_json.len(),
        validation_ms,
        canonicalization_ms,
        target_policy_ms,
        encryption_ms,
        encryption_iterations: size,
    })
}

fn elapsed_ms(duration: Duration) -> u128 {
    duration.as_micros().div_ceil(1_000)
}

fn build_plan(size: usize) -> Result<PlanV2, Box<dyn std::error::Error>> {
    let admin = Id::parse("administrator")?;
    let mut plan = PlanV2 {
        identities: BTreeMap::from([
            (
                admin.clone(),
                Identity {
                    kind: IdentityKind::Administrator,
                    public: RECIPIENT.to_owned(),
                },
            ),
            (
                Id::parse("signer")?,
                Identity {
                    kind: IdentityKind::Signer,
                    public: SIGNER.to_owned(),
                },
            ),
        ]),
        ..PlanV2::default()
    };
    let target_identity = Id::parse("target-identity")?;
    plan.identities.insert(
        target_identity.clone(),
        Identity {
            kind: IdentityKind::Target,
            public: RECIPIENT.to_owned(),
        },
    );
    for index in 0..size {
        let suffix = format!("{index:05}");
        let target_id = Id::parse(format!("target-{suffix}"))?;
        plan.targets.insert(
            target_id.clone(),
            Target {
                kind: TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: target_identity.clone(),
                username: None,
                configuration: Some("benchmark".to_owned()),
                environment: Some("ci".to_owned()),
                tags: vec!["benchmark".to_owned()],
            },
        );
        plan.secrets.insert(
            Id::parse(format!("secret-{suffix}"))?,
            Secret {
                source: format!("secrets/{suffix}.age"),
                source_ciphertext_hash: "0".repeat(64),
                administrators: vec![admin.clone()],
                consumers: vec![target_id],
                runtime: RuntimeSettings::default(),
                runtime_overrides: BTreeMap::default(),
                delivery: DeliveryMode::default(),
                selectors: TargetSelectors::default(),
                phase: ActivationPhase::default(),
                lifecycle: Lifecycle::default(),
                repository_only: false,
                approval_policy: None,
            },
        );
    }
    Ok(plan)
}

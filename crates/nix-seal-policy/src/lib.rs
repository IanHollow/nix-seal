#![forbid(unsafe_code)]
//! Strict loading, merging, validation, and canonicalization of public plans.

use nix_seal_core::{
    ActivationPhase, ApprovalPolicy, DeliveryMode, Generator, GeneratorPromptMode, Id,
    IdentityKind, PLAN_SCHEMA, PlanV1, RuntimeSettings, TargetKind, TemplatePlaceholder,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
    path::Path,
    time::{Duration, SystemTime},
};
use thiserror::Error;

const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;

/// Exact schema for one deterministic target-specific policy projection.
pub const TARGET_POLICY_SCHEMA: &str = "nix-seal.target-policy.v1";
/// Exact schema for one secret's canonical authoring recipient set.
pub const SECRET_RECIPIENTS_SCHEMA: &str = "nix-seal.secret-recipients.v1";

/// Deterministic public recipients used for one canonical ciphertext source.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretRecipientsV1 {
    /// Must equal [`SECRET_RECIPIENTS_SCHEMA`].
    pub schema: String,
    /// Exact compiled plan hash.
    pub plan_hash: String,
    /// Selected secret ID.
    pub secret_id: Id,
    /// Configured ciphertext delivery model.
    pub delivery: DeliveryMode,
    /// Identity IDs mapped to public age/plugin recipients.
    pub recipients: BTreeMap<Id, String>,
}

/// Public lifecycle state of a secret at one explicit observation time.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleStateV1 {
    /// No expiry or rotation schedule is configured.
    Unmanaged,
    /// Neither expiry nor scheduled rotation is due.
    Current,
    /// The application credential is due for rotation.
    RotationDue,
    /// The configured expiry instant has passed.
    Expired,
}

/// Versioned public lifecycle report for one secret.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretLifecycleReportV1 {
    /// Secret ID.
    pub secret_id: Id,
    /// Calculated lifecycle state.
    pub state: LifecycleStateV1,
    /// Parsed expiry instant, normalized to UTC RFC 3339.
    pub expires_at: Option<String>,
    /// Calculated next rotation instant, normalized to UTC RFC 3339.
    pub rotation_due_at: Option<String>,
}

/// Canonical public policy that one target is allowed to activate.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetPolicyV1 {
    /// Must equal [`TARGET_POLICY_SCHEMA`].
    pub schema: String,
    /// Hash of the complete canonical `plan.v1` source.
    pub plan_hash: String,
    /// Exact selected target ID.
    pub target_id: Id,
    /// Selected target integration type.
    pub target_kind: TargetKind,
    /// Selected target Nix system.
    pub system: String,
    /// Optional Home Manager username.
    pub username: Option<String>,
    /// Plan identity ID containing the target recipient.
    pub recipient_identity: Id,
    /// Exact public age or plugin recipient from the plan.
    pub recipient: String,
    /// Authorized secret policy keyed by secret ID.
    pub secrets: BTreeMap<Id, TargetSecretPolicyV1>,
    /// Templates whose complete secret dependency set is authorized.
    pub templates: BTreeMap<Id, TargetTemplatePolicyV1>,
}

/// Exact target-specific policy for one secret.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetSecretPolicyV1 {
    /// Canonical repository source path from the plan.
    pub source: String,
    /// Ciphertext delivery model.
    pub delivery: DeliveryMode,
    /// Required activation phase.
    pub phase: ActivationPhase,
    /// Runtime owner, group, mode, and service actions.
    pub runtime: RuntimeSettings,
    /// Exact approval rule for this secret.
    pub approval: TargetApprovalPolicyV1,
}

/// Distinct trusted approval keys and threshold for one target artifact.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetApprovalPolicyV1 {
    /// Required number of distinct valid signers.
    pub threshold: u16,
    /// Signer identity IDs mapped to encoded public verification keys.
    pub signers: BTreeMap<Id, String>,
}

/// Target-specific runtime template policy.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetTemplatePolicyV1 {
    /// Public template source path from the plan.
    pub source: String,
    /// Required activation phase derived from every referenced secret.
    pub phase: ActivationPhase,
    /// Strict placeholder-to-secret bindings.
    pub placeholders: BTreeMap<String, TemplatePlaceholder>,
    /// Runtime owner, group, mode, and service actions.
    pub runtime: RuntimeSettings,
}

/// Policy compilation error with no secret-bearing context.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// File read failed.
    #[error("unable to read plan source {path}: {source}")]
    Read {
        /// Public plan path.
        path: String,
        /// Operating-system error.
        source: std::io::Error,
    },
    /// `TOML` decoding failed.
    #[error("invalid TOML plan: {0}")]
    Toml(#[from] toml::de::Error),
    /// `JSON` decoding failed.
    #[error("invalid JSON plan: {0}")]
    Json(#[from] serde_json::Error),
    /// Schema version is unsupported.
    #[error("unsupported plan schema {0:?}; expected {PLAN_SCHEMA:?}")]
    Schema(String),
    /// Two sources declare the same object `ID`.
    #[error("duplicate {kind} ID {id:?} across Nix and TOML plans")]
    Duplicate {
        /// Object collection.
        kind: &'static str,
        /// Conflicting `ID`.
        id: Id,
    },
    /// A policy invariant failed.
    #[error("policy violation: {0}")]
    Violation(String),
}

/// Loads a strict `TOML` plan.
pub fn load_toml(path: &Path) -> Result<PlanV1, PolicyError> {
    let value = String::from_utf8(read_plan_source(path)?)
        .map_err(|_| PolicyError::Violation("TOML plan source must be valid UTF-8".to_owned()))?;
    Ok(toml::from_str(&value)?)
}

/// Loads a strict `JSON` plan, including Nix-emitted plans.
pub fn load_json(path: &Path) -> Result<PlanV1, PolicyError> {
    let value = read_plan_source(path)?;
    Ok(serde_json::from_slice(&value)?)
}

fn read_plan_source(path: &Path) -> Result<Vec<u8>, PolicyError> {
    let mut file = std::fs::File::open(path).map_err(|source| PolicyError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let mut value = Vec::new();
    file.by_ref()
        .take(MAX_PLAN_BYTES + 1)
        .read_to_end(&mut value)
        .map_err(|source| PolicyError::Read {
            path: path.display().to_string(),
            source,
        })?;
    if value.len() as u64 > MAX_PLAN_BYTES {
        return Err(PolicyError::Violation(format!(
            "plan source exceeds the {MAX_PLAN_BYTES} byte limit"
        )));
    }
    Ok(value)
}

/// Merges disjoint authoritative sources. Any overlapping `ID` is fatal.
pub fn merge(mut left: PlanV1, right: PlanV1) -> Result<PlanV1, PolicyError> {
    macro_rules! disjoint_append {
        ($field:ident) => {
            for (id, value) in right.$field {
                if left.$field.insert(id.clone(), value).is_some() {
                    return Err(PolicyError::Duplicate {
                        kind: stringify!($field),
                        id,
                    });
                }
            }
        };
    }
    ensure_schema(&left)?;
    ensure_schema(&right)?;
    disjoint_append!(identities);
    disjoint_append!(groups);
    disjoint_append!(targets);
    disjoint_append!(secrets);
    disjoint_append!(generators);
    disjoint_append!(templates);
    disjoint_append!(approval_policies);
    disjoint_append!(backends);
    Ok(left)
}

fn ensure_schema(plan: &PlanV1) -> Result<(), PolicyError> {
    if plan.schema == PLAN_SCHEMA {
        Ok(())
    } else {
        Err(PolicyError::Schema(plan.schema.clone()))
    }
}

/// Validates cross-object policy invariants.
pub fn validate(plan: &PlanV1) -> Result<(), PolicyError> {
    ensure_schema(plan)?;
    if [
        plan.identities.len(),
        plan.groups.len(),
        plan.targets.len(),
        plan.secrets.len(),
        plan.generators.len(),
        plan.templates.len(),
        plan.approval_policies.len(),
        plan.backends.len(),
    ]
    .into_iter()
    .any(|count| count > 10_000)
    {
        return Err(PolicyError::Violation(
            "plan object collections are limited to 10000 entries each".to_owned(),
        ));
    }
    validate_group_graph(plan)?;
    if plan
        .identities
        .values()
        .any(|identity| identity.public.is_empty() || identity.public.len() > 16 * 1024)
    {
        return Err(PolicyError::Violation(
            "identity public values must be nonempty and bounded".to_owned(),
        ));
    }
    for (id, identity) in &plan.identities {
        if matches!(
            identity.kind,
            IdentityKind::Administrator
                | IdentityKind::Target
                | IdentityKind::Recovery
                | IdentityKind::Plugin
        ) && nix_seal_crypto::normalize_recipient(&identity.public).is_err()
        {
            return Err(PolicyError::Violation(format!(
                "identity {id} has an invalid age recipient"
            )));
        }
        if matches!(identity.kind, IdentityKind::Signer)
            && nix_seal_manifest::validate_public_key(&identity.public).is_err()
        {
            return Err(PolicyError::Violation(format!(
                "identity {id} has an invalid approval verification key"
            )));
        }
    }
    let mut signer_keys = BTreeMap::new();
    for (id, identity) in &plan.identities {
        if matches!(identity.kind, IdentityKind::Signer)
            && let Some(previous) = signer_keys.insert(
                nix_seal_manifest::public_key_id(&identity.public).map_err(|_| {
                    PolicyError::Violation(format!(
                        "identity {id} has an invalid approval verification key"
                    ))
                })?,
                id,
            )
        {
            return Err(PolicyError::Violation(format!(
                "signer identities {previous} and {id} reuse one public verification key"
            )));
        }
    }
    for (id, target) in &plan.targets {
        validate_target(id, target)?;
        let identity = plan.identities.get(&target.identity).ok_or_else(|| {
            PolicyError::Violation(format!(
                "target {id} references missing identity {}",
                target.identity
            ))
        })?;
        if !matches!(identity.kind, IdentityKind::Target) {
            return Err(PolicyError::Violation(format!(
                "target {id} identity {} is not target kind",
                target.identity
            )));
        }
    }
    validate_secrets(plan)?;
    validate_templates(plan)?;
    for (id, policy) in &plan.approval_policies {
        validate_approval(id, policy, plan)?;
    }
    validate_generator_graph(plan)
}

#[allow(clippy::too_many_lines)]
fn validate_secrets(plan: &PlanV1) -> Result<(), PolicyError> {
    let mut sources = BTreeSet::new();
    for (id, secret) in &plan.secrets {
        if !valid_repository_relative_path(&secret.source) {
            return Err(PolicyError::Violation(format!(
                "secret {id} source must be a normalized repository-relative path"
            )));
        }
        if !sources.insert(&secret.source) {
            return Err(PolicyError::Violation(format!(
                "secret {id} reuses a canonical ciphertext source path"
            )));
        }
        for consumer in &secret.consumers {
            if !plan.targets.contains_key(consumer) && !plan.groups.contains_key(consumer) {
                return Err(PolicyError::Violation(format!(
                    "secret {id} references missing consumer {consumer}"
                )));
            }
        }
        for administrator in &secret.administrators {
            if !plan.identities.contains_key(administrator)
                && !plan.groups.contains_key(administrator)
            {
                return Err(PolicyError::Violation(format!(
                    "secret {id} references missing administrator {administrator}"
                )));
            }
        }
        validate_target_selectors(plan, id, secret)?;
        validate_repository_only_secret(id, secret)?;
        let administrator_leaves = expand_group_leaves(plan, &secret.administrators)?;
        if administrator_leaves.iter().any(|identity_id| {
            !plan.identities.get(identity_id).is_some_and(|identity| {
                matches!(
                    identity.kind,
                    IdentityKind::Administrator | IdentityKind::Recovery
                )
            })
        }) {
            return Err(PolicyError::Violation(format!(
                "secret {id} administrator groups contain incompatible members"
            )));
        }
        let consumer_leaves = selected_consumer_targets(plan, secret)?;
        if consumer_leaves
            .iter()
            .any(|target_id| !plan.targets.contains_key(target_id))
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} consumer groups contain non-target members"
            )));
        }
        let default_administrator_exists = plan.identities.values().any(|identity| {
            matches!(
                identity.kind,
                IdentityKind::Administrator | IdentityKind::Recovery
            )
        });
        let has_administrator = !administrator_leaves.is_empty()
            || secret.administrators.is_empty() && default_administrator_exists;
        if matches!(secret.delivery, DeliveryMode::Rekeyed) && !has_administrator
            || matches!(secret.delivery, DeliveryMode::Direct)
                && !has_administrator
                && consumer_leaves.is_empty()
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} has no canonical encryption recipients"
            )));
        }
        if let Some(policy) = &secret.approval_policy
            && !plan.approval_policies.contains_key(policy)
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} references missing approval policy {policy}"
            )));
        }
        if secret.approval_policy.is_none()
            && !plan
                .identities
                .values()
                .any(|identity| matches!(identity.kind, IdentityKind::Signer))
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} requires an explicit approval policy or at least one default signer"
            )));
        }
        if !is_private_runtime_mode(&secret.runtime.mode) {
            return Err(PolicyError::Violation(format!(
                "secret {id} runtime mode must be a nonzero owner-only four-digit octal mode"
            )));
        }
        if let Some(path) = &secret.runtime.compatibility_symlink
            && !nix_seal_core::valid_compatibility_symlink(path)
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} compatibility symlink must be a safe absolute path without '.' or '..' components"
            )));
        }
        validate_lifecycle(id, &secret.lifecycle)?;
    }
    Ok(())
}

fn validate_repository_only_secret(
    id: &Id,
    secret: &nix_seal_core::Secret,
) -> Result<(), PolicyError> {
    if secret.repository_only
        && (!secret.consumers.is_empty()
            || secret.selectors != nix_seal_core::TargetSelectors::default())
    {
        return Err(PolicyError::Violation(format!(
            "repository-only secret {id} cannot declare target consumers or selectors"
        )));
    }
    if secret.repository_only && matches!(secret.delivery, DeliveryMode::Direct) {
        return Err(PolicyError::Violation(format!(
            "repository-only secret {id} cannot use direct delivery"
        )));
    }
    Ok(())
}

fn validate_target(id: &Id, target: &nix_seal_core::Target) -> Result<(), PolicyError> {
    validate_bounded_selector_values(
        &format!("target {id}"),
        [
            Some(target.system.as_str()),
            target.username.as_deref(),
            target.configuration.as_deref(),
            target.environment.as_deref(),
        ]
        .into_iter()
        .flatten(),
    )?;
    validate_bounded_selector_values(
        &format!("target {id} tags"),
        target.tags.iter().map(String::as_str),
    )?;
    if target.tags.iter().collect::<BTreeSet<_>>().len() != target.tags.len() {
        return Err(PolicyError::Violation(format!(
            "target {id} contains duplicate tags"
        )));
    }
    Ok(())
}

fn validate_target_selectors(
    plan: &PlanV1,
    secret_id: &Id,
    secret: &nix_seal_core::Secret,
) -> Result<(), PolicyError> {
    let selectors = &secret.selectors;
    for (label, values) in [
        ("targets", &selectors.targets),
        ("groups", &selectors.groups),
    ] {
        if values.len() > 10_000 || values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            return Err(PolicyError::Violation(format!(
                "secret {secret_id} selectors.{label} contains duplicate or excessive IDs"
            )));
        }
    }
    for target in &selectors.targets {
        if !plan.targets.contains_key(target) {
            return Err(PolicyError::Violation(format!(
                "secret {secret_id} selector references missing target {target}"
            )));
        }
    }
    for group in &selectors.groups {
        if !plan.groups.contains_key(group) {
            return Err(PolicyError::Violation(format!(
                "secret {secret_id} selector references missing group {group}"
            )));
        }
        if expand_group_leaves(plan, std::slice::from_ref(group))?
            .iter()
            .any(|member| !plan.targets.contains_key(member))
        {
            return Err(PolicyError::Violation(format!(
                "secret {secret_id} selector group {group} contains a non-target member"
            )));
        }
    }
    if selectors.kinds.iter().collect::<BTreeSet<_>>().len() != selectors.kinds.len() {
        return Err(PolicyError::Violation(format!(
            "secret {secret_id} selectors.kinds contains duplicates"
        )));
    }
    validate_bounded_selector_values(
        &format!("secret {secret_id} selectors"),
        selectors
            .systems
            .iter()
            .chain(&selectors.usernames)
            .chain(&selectors.configurations)
            .chain(&selectors.environments)
            .chain(&selectors.tags)
            .map(String::as_str),
    )?;
    for (label, values) in [
        ("systems", &selectors.systems),
        ("usernames", &selectors.usernames),
        ("configurations", &selectors.configurations),
        ("environments", &selectors.environments),
        ("tags", &selectors.tags),
    ] {
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            return Err(PolicyError::Violation(format!(
                "secret {secret_id} selectors.{label} contains duplicates"
            )));
        }
    }
    Ok(())
}

fn validate_bounded_selector_values<'a>(
    label: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), PolicyError> {
    for value in values {
        if value.is_empty()
            || value.len() > 256
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(PolicyError::Violation(format!(
                "{label} contains an empty, oversized, or control-character selector value"
            )));
        }
    }
    Ok(())
}

fn selected_consumer_targets(
    plan: &PlanV1,
    secret: &nix_seal_core::Secret,
) -> Result<BTreeSet<Id>, PolicyError> {
    let mut selected = expand_group_leaves(plan, &secret.consumers)?;
    let selectors = &secret.selectors;
    if *selectors == nix_seal_core::TargetSelectors::default() {
        return Ok(selected);
    }
    let has_base = !selectors.targets.is_empty() || !selectors.groups.is_empty();
    let mut candidates = if has_base {
        selectors.targets.iter().cloned().collect::<BTreeSet<_>>()
    } else {
        plan.targets.keys().cloned().collect::<BTreeSet<_>>()
    };
    for group in &selectors.groups {
        candidates.extend(expand_group_leaves(plan, std::slice::from_ref(group))?);
    }
    candidates.retain(|target_id| {
        let Some(target) = plan.targets.get(target_id) else {
            return false;
        };
        (selectors.kinds.is_empty() || selectors.kinds.contains(&target.kind))
            && (selectors.systems.is_empty() || selectors.systems.contains(&target.system))
            && (selectors.usernames.is_empty()
                || target
                    .username
                    .as_ref()
                    .is_some_and(|username| selectors.usernames.contains(username)))
            && (selectors.configurations.is_empty()
                || target
                    .configuration
                    .as_ref()
                    .is_some_and(|configuration| selectors.configurations.contains(configuration)))
            && (selectors.environments.is_empty()
                || target
                    .environment
                    .as_ref()
                    .is_some_and(|environment| selectors.environments.contains(environment)))
            && selectors
                .tags
                .iter()
                .all(|tag| target.tags.iter().any(|candidate| candidate == tag))
    });
    selected.extend(candidates);
    if selected
        .iter()
        .any(|target_id| !plan.targets.contains_key(target_id))
    {
        return Err(PolicyError::Violation(
            "secret consumer references a non-target object".to_owned(),
        ));
    }
    Ok(selected)
}

fn parse_timestamp(label: &str, value: &str) -> Result<jiff::Timestamp, PolicyError> {
    value.parse().map_err(|_| {
        PolicyError::Violation(format!(
            "{label} must be a valid RFC 3339 timestamp with an explicit offset"
        ))
    })
}

fn validate_lifecycle(id: &Id, lifecycle: &nix_seal_core::Lifecycle) -> Result<(), PolicyError> {
    let created = lifecycle
        .created_at
        .as_deref()
        .map(|value| parse_timestamp(&format!("secret {id} createdAt"), value))
        .transpose()?;
    let rotated = lifecycle
        .rotated_at
        .as_deref()
        .map(|value| parse_timestamp(&format!("secret {id} rotatedAt"), value))
        .transpose()?;
    let expires = lifecycle
        .expires_at
        .as_deref()
        .map(|value| parse_timestamp(&format!("secret {id} expiresAt"), value))
        .transpose()?;
    if rotated
        .zip(created)
        .is_some_and(|(rotated, created)| rotated < created)
        || expires
            .zip(created)
            .is_some_and(|(expires, created)| expires <= created)
        || lifecycle.rotate_after_days == Some(0)
        || lifecycle.rotate_after_days.is_some() && rotated.or(created).is_none()
    {
        return Err(PolicyError::Violation(format!(
            "secret {id} has inconsistent lifecycle chronology or rotation interval"
        )));
    }
    Ok(())
}

/// Calculates deterministic lifecycle states at an explicit system time.
pub fn lifecycle_report(
    plan: &PlanV1,
    now: SystemTime,
) -> Result<Vec<SecretLifecycleReportV1>, PolicyError> {
    validate(plan)?;
    let now = jiff::Timestamp::try_from(now).map_err(|_| {
        PolicyError::Violation("system time is outside supported lifecycle range".to_owned())
    })?;
    plan.secrets
        .iter()
        .map(|(secret_id, secret)| {
            let lifecycle = &secret.lifecycle;
            let expires = lifecycle
                .expires_at
                .as_deref()
                .map(|value| parse_timestamp("expiresAt", value))
                .transpose()?;
            let rotation_base = lifecycle
                .rotated_at
                .as_deref()
                .or(lifecycle.created_at.as_deref());
            let rotation_due = rotation_base
                .zip(lifecycle.rotate_after_days)
                .map(|(base, days)| {
                    let base = parse_timestamp("rotation base", base)?;
                    let seconds = u64::from(days).checked_mul(86_400).ok_or_else(|| {
                        PolicyError::Violation(
                            "rotation interval exceeds supported range".to_owned(),
                        )
                    })?;
                    base.checked_add(Duration::from_secs(seconds)).map_err(|_| {
                        PolicyError::Violation(
                            "rotation due time exceeds supported range".to_owned(),
                        )
                    })
                })
                .transpose()?;
            let state = if expires.is_some_and(|expiry| expiry <= now) {
                LifecycleStateV1::Expired
            } else if rotation_due.is_some_and(|due| due <= now) {
                LifecycleStateV1::RotationDue
            } else if expires.is_none() && rotation_due.is_none() {
                LifecycleStateV1::Unmanaged
            } else {
                LifecycleStateV1::Current
            };
            Ok(SecretLifecycleReportV1 {
                secret_id: secret_id.clone(),
                state,
                expires_at: expires.map(|value| value.to_string()),
                rotation_due_at: rotation_due.map(|value| value.to_string()),
            })
        })
        .collect()
}

fn validate_templates(plan: &PlanV1) -> Result<(), PolicyError> {
    for (id, template) in &plan.templates {
        if !is_normalized_public_path(&template.source) {
            return Err(PolicyError::Violation(format!(
                "template {id} source must be a normalized public path"
            )));
        }
        if template.placeholders.is_empty() || template.placeholders.len() > 256 {
            return Err(PolicyError::Violation(format!(
                "template {id} must declare between 1 and 256 placeholders"
            )));
        }
        for (name, placeholder) in &template.placeholders {
            if !is_placeholder_name(name) {
                return Err(PolicyError::Violation(format!(
                    "template {id} has invalid placeholder name {name:?}"
                )));
            }
            if !plan.secrets.contains_key(&placeholder.secret) {
                return Err(PolicyError::Violation(format!(
                    "template {id} placeholder {name:?} references missing secret {}",
                    placeholder.secret
                )));
            }
        }
        template_phase(plan, id, template)?;
        if !is_private_runtime_mode(&template.runtime.mode) {
            return Err(PolicyError::Violation(format!(
                "template {id} runtime mode must be a nonzero owner-only four-digit octal mode"
            )));
        }
        if template.runtime.compatibility_symlink.is_some() {
            return Err(PolicyError::Violation(format!(
                "template {id} cannot declare a compatibility symlink"
            )));
        }
        let output_id = Id::parse(format!("templates/{id}"))
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        if plan.secrets.contains_key(&output_id) {
            return Err(PolicyError::Violation(format!(
                "template {id} output collides with secret {output_id}"
            )));
        }
    }
    Ok(())
}

fn template_phase(
    plan: &PlanV1,
    template_id: &Id,
    template: &nix_seal_core::Template,
) -> Result<ActivationPhase, PolicyError> {
    let mut phases = template.placeholders.values().map(|placeholder| {
        plan.secrets
            .get(&placeholder.secret)
            .map(|secret| secret.phase)
            .ok_or_else(|| {
                PolicyError::Violation(format!(
                    "template {template_id} references missing secret {}",
                    placeholder.secret
                ))
            })
    });
    let phase = phases.next().transpose()?.ok_or_else(|| {
        PolicyError::Violation(format!("template {template_id} has no placeholders"))
    })?;
    for candidate in phases {
        if candidate? != phase {
            return Err(PolicyError::Violation(format!(
                "template {template_id} references secrets from multiple activation phases"
            )));
        }
    }
    Ok(phase)
}

fn is_private_runtime_mode(value: &str) -> bool {
    value.len() == 4
        && value.starts_with('0')
        && u32::from_str_radix(value, 8)
            .is_ok_and(|mode| mode != 0 && mode <= 0o700 && mode.trailing_zeros() >= 6)
}

fn is_normalized_public_path(value: &str) -> bool {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    value.split('/').enumerate().all(|(index, segment)| {
        (index == 0 && segment.is_empty() && value.starts_with('/'))
            || (!segment.is_empty() && segment != "." && segment != "..")
    })
}

fn is_placeholder_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn validate_group_graph(plan: &PlanV1) -> Result<(), PolicyError> {
    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<&Id, Vec<&Id>> = BTreeMap::new();
    for (group_id, group) in &plan.groups {
        if group.members.len() > 10_000 {
            return Err(PolicyError::Violation(format!(
                "group {group_id} exceeds the 10000 member limit"
            )));
        }
        for member in &group.members {
            let matches = usize::from(plan.groups.contains_key(member))
                + usize::from(plan.targets.contains_key(member))
                + usize::from(plan.identities.contains_key(member));
            if matches != 1 {
                return Err(PolicyError::Violation(format!(
                    "group {group_id} member {member} must resolve to exactly one group, target, or identity"
                )));
            }
        }
        let dependencies: BTreeSet<_> = group
            .members
            .iter()
            .filter(|member| plan.groups.contains_key(*member))
            .collect();
        indegree.insert(group_id, dependencies.len());
        for dependency in dependencies {
            dependents.entry(dependency).or_default().push(group_id);
        }
    }
    let mut ready: VecDeque<_> = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0_usize;
    while let Some(group_id) = ready.pop_front() {
        visited = visited.checked_add(1).ok_or_else(|| {
            PolicyError::Violation("group graph exceeds implementation limits".to_owned())
        })?;
        if let Some(entries) = dependents.get(group_id) {
            for dependent in entries {
                let count = indegree.get_mut(dependent).ok_or_else(|| {
                    PolicyError::Violation("group graph is internally inconsistent".to_owned())
                })?;
                *count = count.checked_sub(1).ok_or_else(|| {
                    PolicyError::Violation("group graph is internally inconsistent".to_owned())
                })?;
                if *count == 0 {
                    ready.push_back(dependent);
                }
            }
        }
    }
    if visited != plan.groups.len() {
        return Err(PolicyError::Violation(
            "group membership graph contains a cycle".to_owned(),
        ));
    }
    Ok(())
}

fn target_is_consumer(plan: &PlanV1, secret: &nix_seal_core::Secret, target_id: &Id) -> bool {
    if selected_consumer_targets(plan, secret).is_ok_and(|targets| targets.contains(target_id)) {
        return true;
    }
    let consumers = &secret.consumers;
    let mut pending = Vec::new();
    let mut visited = BTreeSet::new();
    for consumer in consumers {
        if consumer == target_id {
            return true;
        }
        if plan.groups.contains_key(consumer) && visited.insert(consumer) {
            pending.push(consumer);
        }
    }
    while let Some(group_id) = pending.pop() {
        let Some(group) = plan.groups.get(group_id) else {
            continue;
        };
        for member in &group.members {
            if member == target_id {
                return true;
            }
            if plan.groups.contains_key(member) && visited.insert(member) {
                pending.push(member);
            }
        }
    }
    false
}

fn expand_group_leaves(plan: &PlanV1, references: &[Id]) -> Result<BTreeSet<Id>, PolicyError> {
    let mut leaves = BTreeSet::new();
    let mut pending = Vec::new();
    let mut visited = BTreeSet::new();
    for reference in references {
        if plan.groups.contains_key(reference) {
            if visited.insert(reference.clone()) {
                pending.push(reference.clone());
            }
        } else {
            leaves.insert(reference.clone());
        }
    }
    while let Some(group_id) = pending.pop() {
        let group = plan
            .groups
            .get(&group_id)
            .ok_or_else(|| PolicyError::Violation(format!("missing group {group_id}")))?;
        for member in &group.members {
            if plan.groups.contains_key(member) {
                if visited.insert(member.clone()) {
                    pending.push(member.clone());
                }
            } else {
                leaves.insert(member.clone());
            }
        }
    }
    Ok(leaves)
}

/// Derives the canonical encryption recipients for one secret source.
pub fn secret_recipients(plan: &PlanV1, secret_id: &Id) -> Result<SecretRecipientsV1, PolicyError> {
    validate(plan)?;
    let secret = plan.secrets.get(secret_id).ok_or_else(|| {
        PolicyError::Violation(format!(
            "recipient policy references missing secret {secret_id}"
        ))
    })?;
    let mut recipients = BTreeMap::new();
    let administrator_ids = if secret.administrators.is_empty() {
        plan.identities
            .iter()
            .filter_map(|(id, identity)| {
                matches!(
                    identity.kind,
                    IdentityKind::Administrator | IdentityKind::Recovery
                )
                .then_some(id.clone())
            })
            .collect()
    } else {
        expand_group_leaves(plan, &secret.administrators)?
    };
    for identity_id in administrator_ids {
        let identity = plan.identities.get(&identity_id).ok_or_else(|| {
            PolicyError::Violation(format!(
                "administrator reference {identity_id} does not resolve to an identity"
            ))
        })?;
        if !matches!(
            identity.kind,
            IdentityKind::Administrator | IdentityKind::Recovery
        ) {
            return Err(PolicyError::Violation(format!(
                "administrator reference {identity_id} has an incompatible identity kind"
            )));
        }
        recipients.insert(identity_id, identity.public.clone());
    }
    for (identity_id, identity) in &plan.identities {
        if matches!(identity.kind, IdentityKind::Recovery) {
            recipients.insert(identity_id.clone(), identity.public.clone());
        }
    }
    if matches!(secret.delivery, DeliveryMode::Direct) {
        for target_id in selected_consumer_targets(plan, secret)? {
            let target = plan.targets.get(&target_id).ok_or_else(|| {
                PolicyError::Violation(format!(
                    "direct consumer reference {target_id} does not resolve to a target"
                ))
            })?;
            let identity = plan.identities.get(&target.identity).ok_or_else(|| {
                PolicyError::Violation(format!(
                    "target {target_id} references missing identity {}",
                    target.identity
                ))
            })?;
            recipients.insert(target.identity.clone(), identity.public.clone());
        }
    }
    if recipients.is_empty() {
        return Err(PolicyError::Violation(format!(
            "secret {secret_id} has no canonical encryption recipients"
        )));
    }
    Ok(SecretRecipientsV1 {
        schema: SECRET_RECIPIENTS_SCHEMA.to_owned(),
        plan_hash: plan_hash(plan)?,
        secret_id: secret_id.clone(),
        delivery: secret.delivery.clone(),
        recipients,
    })
}

fn target_approval_policy(
    plan: &PlanV1,
    policy_id: Option<&Id>,
) -> Result<TargetApprovalPolicyV1, PolicyError> {
    let (threshold, signer_ids): (u16, Vec<&Id>) = if let Some(policy_id) = policy_id {
        let policy = plan.approval_policies.get(policy_id).ok_or_else(|| {
            PolicyError::Violation(format!("missing approval policy {policy_id}"))
        })?;
        (policy.threshold, policy.signers.iter().collect())
    } else {
        (
            1,
            plan.identities
                .iter()
                .filter_map(|(id, identity)| {
                    matches!(identity.kind, IdentityKind::Signer).then_some(id)
                })
                .collect(),
        )
    };
    let mut signers = BTreeMap::new();
    for signer_id in signer_ids {
        let identity = plan.identities.get(signer_id).ok_or_else(|| {
            PolicyError::Violation(format!("missing signer identity {signer_id}"))
        })?;
        if !matches!(identity.kind, IdentityKind::Signer) {
            return Err(PolicyError::Violation(format!(
                "approval identity {signer_id} is not a signer"
            )));
        }
        signers.insert(signer_id.clone(), identity.public.clone());
    }
    if threshold == 0 || usize::from(threshold) > signers.len() {
        return Err(PolicyError::Violation(
            "target approval policy has an impossible threshold".to_owned(),
        ));
    }
    Ok(TargetApprovalPolicyV1 { threshold, signers })
}

fn validate_approval(id: &Id, policy: &ApprovalPolicy, plan: &PlanV1) -> Result<(), PolicyError> {
    let distinct: BTreeSet<_> = policy.signers.iter().collect();
    if policy.threshold == 0 || usize::from(policy.threshold) > distinct.len() {
        return Err(PolicyError::Violation(format!(
            "approval policy {id} has impossible threshold"
        )));
    }
    for signer in distinct {
        match plan.identities.get(signer) {
            Some(identity) if matches!(identity.kind, IdentityKind::Signer) => {}
            _ => {
                return Err(PolicyError::Violation(format!(
                    "approval policy {id} references non-signer {signer}"
                )));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_generator_graph(plan: &PlanV1) -> Result<(), PolicyError> {
    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<&Id, Vec<&Id>> = BTreeMap::new();
    let mut generated_outputs = BTreeSet::new();
    let mut generated_public_output_ids = BTreeSet::new();
    let mut public_destinations = BTreeSet::new();
    let mut output_producers = BTreeMap::new();
    let mut generator_prompts = BTreeSet::new();
    let secret_sources: BTreeSet<_> = plan
        .secrets
        .values()
        .map(|secret| secret.source.as_str())
        .collect();
    for (generator_id, generator) in &plan.generators {
        if generator.dependencies.len() > 10_000
            || generator.secret_dependencies.len() > 10_000
            || generator.outputs.len() > 10_000
            || generator.public_outputs.len() > 10_000
        {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} exceeds dependency or output limits"
            )));
        }
        validate_generator_execution(generator_id, generator)?;
        validate_generator_prompts(generator_id, generator, &mut generator_prompts)?;
        if generator.outputs.is_empty() && generator.public_outputs.is_empty() {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} must declare at least one secret or public output"
            )));
        }
        validate_generator_outputs(
            plan,
            generator_id,
            generator,
            &mut generated_outputs,
            &mut generated_public_output_ids,
            &mut public_destinations,
            &mut output_producers,
            &secret_sources,
        )?;
        validate_generator_secret_dependencies(plan, generator_id, generator)?;
        if generator.parameters.len() > 128
            || generator.parameters.iter().any(|(key, value)| {
                !is_generator_parameter_name(key)
                    || value.len() > 4096
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
            || generator.validation.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 4096
                    || value.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} has invalid public parameters"
            )));
        }
        let dependencies: BTreeSet<_> = generator.dependencies.iter().collect();
        if dependencies.len() != generator.dependencies.len() {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} contains duplicate dependencies"
            )));
        }
        for dependency in &dependencies {
            if !plan.generators.contains_key(*dependency) {
                return Err(PolicyError::Violation(format!(
                    "generator {generator_id} references missing dependency {dependency}"
                )));
            }
            dependents.entry(dependency).or_default().push(generator_id);
        }
        indegree.insert(generator_id, dependencies.len());
    }
    let mut ready: VecDeque<_> = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect();
    let mut visited = 0_usize;
    while let Some(generator_id) = ready.pop_front() {
        visited = visited.checked_add(1).ok_or_else(|| {
            PolicyError::Violation("generator graph exceeds implementation limits".to_owned())
        })?;
        if let Some(entries) = dependents.get(generator_id) {
            for dependent in entries {
                let count = indegree.get_mut(dependent).ok_or_else(|| {
                    PolicyError::Violation("generator graph is internally inconsistent".to_owned())
                })?;
                *count = count.checked_sub(1).ok_or_else(|| {
                    PolicyError::Violation("generator graph is internally inconsistent".to_owned())
                })?;
                if *count == 0 {
                    ready.push_back(dependent);
                }
            }
        }
    }
    if visited != plan.generators.len() {
        return Err(PolicyError::Violation(
            "generator dependency graph contains a cycle".to_owned(),
        ));
    }
    validate_generated_secret_dependency_order(plan, &output_producers)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_generator_outputs<'a>(
    plan: &PlanV1,
    generator_id: &'a Id,
    generator: &'a nix_seal_core::Generator,
    generated_outputs: &mut BTreeSet<&'a Id>,
    generated_public_output_ids: &mut BTreeSet<Id>,
    public_destinations: &mut BTreeSet<String>,
    output_producers: &mut BTreeMap<&'a Id, &'a Id>,
    secret_sources: &BTreeSet<&str>,
) -> Result<(), PolicyError> {
    for output in &generator.outputs {
        if !plan.secrets.contains_key(output)
            || generated_public_output_ids.contains(output)
            || !generated_outputs.insert(output)
        {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} has a missing or duplicate secret output {output}"
            )));
        }
        output_producers.insert(output, generator_id);
    }
    for output in &generator.public_outputs {
        if !generated_public_output_ids.insert(output.id.clone())
            || generated_outputs.contains(&output.id)
            || !valid_repository_relative_path(&output.destination)
            || !public_destinations.insert(output.destination.clone())
            || secret_sources.contains(output.destination.as_str())
        {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} has a duplicate or unsafe public output {}",
                output.id
            )));
        }
    }
    Ok(())
}

fn validate_generated_secret_dependency_order(
    plan: &PlanV1,
    output_producers: &BTreeMap<&Id, &Id>,
) -> Result<(), PolicyError> {
    for (generator_id, generator) in &plan.generators {
        for secret_id in &generator.secret_dependencies {
            if let Some(producer) = output_producers.get(secret_id)
                && !generator.dependencies.contains(*producer)
            {
                return Err(PolicyError::Violation(format!(
                    "generator {generator_id} must directly depend on generator {producer}, which produces secret dependency {secret_id}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_generator_prompts<'a>(
    generator_id: &Id,
    generator: &'a Generator,
    known_prompts: &mut BTreeSet<&'a Id>,
) -> Result<(), PolicyError> {
    if generator.prompts.len() > 64
        || generator.prompts.iter().any(|prompt| {
            prompt.message.is_empty()
                || prompt.message.len() > 4096
                || prompt.message.bytes().any(|byte| byte == 0)
                || !known_prompts.insert(&prompt.id)
        })
    {
        return Err(PolicyError::Violation(format!(
            "generator {generator_id} has invalid or duplicate prompts"
        )));
    }
    Ok(())
}

fn validate_generator_secret_dependencies(
    plan: &PlanV1,
    generator_id: &Id,
    generator: &Generator,
) -> Result<(), PolicyError> {
    let secret_dependencies: BTreeSet<_> = generator.secret_dependencies.iter().collect();
    if secret_dependencies.len() != generator.secret_dependencies.len()
        || secret_dependencies
            .iter()
            .any(|secret| !plan.secrets.contains_key(*secret))
        || secret_dependencies
            .iter()
            .any(|secret| generator.outputs.contains(*secret))
    {
        return Err(PolicyError::Violation(format!(
            "generator {generator_id} has invalid, duplicate, missing, or self-referential secret dependencies"
        )));
    }
    Ok(())
}

fn validate_generator_execution(
    generator_id: &Id,
    generator: &nix_seal_core::Generator,
) -> Result<(), PolicyError> {
    if generator.executable.is_empty()
        || generator.executable.len() > 16 * 1024
        || generator
            .executable
            .bytes()
            .any(|byte| byte.is_ascii_control())
    {
        return Err(PolicyError::Violation(format!(
            "generator {generator_id} has an invalid executable declaration"
        )));
    }
    let is_builtin = matches!(
        generator.executable.as_str(),
        "builtin:random"
            | "builtin:hex"
            | "builtin:base64"
            | "builtin:token"
            | "builtin:passphrase"
            | "builtin:argon2id-password-hash"
            | "builtin:ssh-ed25519"
            | "builtin:wireguard-private-key"
            | "builtin:uuid"
    );
    if !is_builtin && !valid_store_executable(&generator.executable) {
        return Err(PolicyError::Violation(format!(
            "generator {generator_id} must use a built-in or direct executable below /nix/store"
        )));
    }
    if generator.arguments.len() > 256
        || generator.arguments.iter().any(|argument| {
            argument.len() > 16 * 1024 || argument.bytes().any(|byte| byte.is_ascii_control())
        })
        || generator.runtime_inputs.len() > 128
        || generator
            .runtime_inputs
            .iter()
            .any(|input| !valid_store_executable(input))
        || !(1..=300).contains(&generator.timeout_seconds)
        || generator.max_output_bytes == 0
        || generator.max_output_bytes > nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES
        || (is_builtin
            && (!generator.arguments.is_empty()
                || !generator.runtime_inputs.is_empty()
                || generator.timeout_seconds != nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS
                || generator.max_output_bytes != nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES))
    {
        return Err(PolicyError::Violation(format!(
            "generator {generator_id} has invalid constrained-execution settings"
        )));
    }
    if generator.executable == "builtin:argon2id-password-hash" {
        validate_argon2id_password_hash_generator(generator_id, generator)?;
    }
    if is_builtin && !generator.secret_dependencies.is_empty() {
        return Err(PolicyError::Violation(format!(
            "built-in generator {generator_id} cannot declare secret dependencies"
        )));
    }
    let ssh_public_output = generator.executable == "builtin:ssh-ed25519"
        && generator.outputs.len() == 1
        && generator.public_outputs.len() <= 1;
    if is_builtin && !generator.public_outputs.is_empty() && !ssh_public_output {
        return Err(PolicyError::Violation(format!(
            "built-in generator {generator_id} cannot declare public outputs"
        )));
    }
    if generator.executable == "builtin:ssh-ed25519"
        && (generator.outputs.len() != 1 || generator.public_outputs.len() > 1)
    {
        return Err(PolicyError::Violation(format!(
            "built-in generator {generator_id} requires exactly one secret output and at most one public output"
        )));
    }
    Ok(())
}

fn valid_repository_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.bytes().any(|byte| byte.is_ascii_control())
        })
}

fn validate_argon2id_password_hash_generator(
    generator_id: &Id,
    generator: &Generator,
) -> Result<(), PolicyError> {
    if generator.outputs.len() != 1
        || generator.prompts.len() != 1
        || !matches!(generator.prompts[0].mode, GeneratorPromptMode::Hidden)
        || generator.prompts[0].multiline
        || generator
            .parameters
            .keys()
            .any(|key| !matches!(key.as_str(), "memory-kib" | "iterations" | "output-length"))
    {
        return Err(PolicyError::Violation(format!(
            "Argon2id password-hash generator {generator_id} requires one single-line hidden prompt, one output, and bounded hash parameters"
        )));
    }
    let memory_kib = argon2id_parameter(generator, "memory-kib", 65_536)?;
    let iterations = argon2id_parameter(generator, "iterations", 3)?;
    let output_length = argon2id_parameter(generator, "output-length", 32)?;
    if !(19_456..=524_288).contains(&memory_kib)
        || !(2..=10).contains(&iterations)
        || !(16..=64).contains(&output_length)
    {
        return Err(PolicyError::Violation(format!(
            "Argon2id password-hash generator {generator_id} parameters are outside the supported security bounds"
        )));
    }
    Ok(())
}

fn argon2id_parameter(generator: &Generator, name: &str, default: u32) -> Result<u32, PolicyError> {
    generator.parameters.get(name).map_or(Ok(default), |value| {
        value.parse::<u32>().map_err(|_| {
            PolicyError::Violation(format!(
                "Argon2id password-hash generator parameter {name} must be an integer"
            ))
        })
    })
}

fn valid_store_executable(value: &str) -> bool {
    let path = Path::new(value);
    value.starts_with("/nix/store/")
        && !value.contains(':')
        && path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn is_generator_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// Returns `RFC 8785` canonical `JSON` bytes.
pub fn canonical_json(plan: &PlanV1) -> Result<Vec<u8>, PolicyError> {
    Ok(serde_jcs::to_vec(plan)?)
}

/// Returns the `BLAKE3` digest of the canonical plan.
pub fn plan_hash(plan: &PlanV1) -> Result<String, PolicyError> {
    Ok(domain_hash("nix-seal plan hash v1", &canonical_json(plan)?))
}

/// Derives the complete deterministic policy authorized for one target.
pub fn target_policy(plan: &PlanV1, target_id: &Id) -> Result<TargetPolicyV1, PolicyError> {
    validate(plan)?;
    let target = plan.targets.get(target_id).ok_or_else(|| {
        PolicyError::Violation(format!(
            "target policy references missing target {target_id}"
        ))
    })?;
    let recipient_identity = plan.identities.get(&target.identity).ok_or_else(|| {
        PolicyError::Violation(format!(
            "target {target_id} references missing identity {}",
            target.identity
        ))
    })?;
    let mut secrets = BTreeMap::new();
    for (secret_id, secret) in &plan.secrets {
        if target_is_consumer(plan, secret, target_id) {
            secrets.insert(
                secret_id.clone(),
                TargetSecretPolicyV1 {
                    source: secret.source.clone(),
                    delivery: secret.delivery.clone(),
                    phase: secret.phase,
                    runtime: secret.runtime.clone(),
                    approval: target_approval_policy(plan, secret.approval_policy.as_ref())?,
                },
            );
        }
    }
    let templates = plan
        .templates
        .iter()
        .filter(|(_, template)| {
            template
                .placeholders
                .values()
                .all(|placeholder| secrets.contains_key(&placeholder.secret))
        })
        .map(|(template_id, template)| {
            Ok((
                template_id.clone(),
                TargetTemplatePolicyV1 {
                    source: template.source.clone(),
                    phase: template_phase(plan, template_id, template)?,
                    placeholders: template.placeholders.clone(),
                    runtime: template.runtime.clone(),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, PolicyError>>()?;
    Ok(TargetPolicyV1 {
        schema: TARGET_POLICY_SCHEMA.to_owned(),
        plan_hash: plan_hash(plan)?,
        target_id: target_id.clone(),
        target_kind: target.kind.clone(),
        system: target.system.clone(),
        username: target.username.clone(),
        recipient_identity: target.identity.clone(),
        recipient: recipient_identity.public.clone(),
        secrets,
        templates,
    })
}

/// Returns RFC 8785 canonical bytes for a target-specific policy projection.
pub fn canonical_target_policy_json(policy: &TargetPolicyV1) -> Result<Vec<u8>, PolicyError> {
    Ok(serde_jcs::to_vec(policy)?)
}

/// Returns the BLAKE3 digest of one canonical target policy projection.
pub fn target_policy_hash(policy: &TargetPolicyV1) -> Result<String, PolicyError> {
    Ok(domain_hash(
        "nix-seal target policy hash v1",
        &canonical_target_policy_json(policy)?,
    ))
}

fn domain_hash(context: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

/// Returns the `JSON` Schema for plan.v1.
pub fn json_schema() -> Result<String, PolicyError> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        PlanV1
    ))?)
}

/// Returns the `JSON` Schema for the canonical target-policy projection.
pub fn target_policy_json_schema() -> Result<String, PolicyError> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        TargetPolicyV1
    ))?)
}

/// Returns the `JSON` Schema for canonical secret-recipient projections.
pub fn secret_recipients_json_schema() -> Result<String, PolicyError> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        SecretRecipientsV1
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_seal_core::{
        ActivationPhase, DeliveryMode, Group, Identity, Lifecycle, RuntimeSettings, Secret, Target,
        TargetKind, Template, TemplateEncoding, TemplatePlaceholder,
    };
    use std::collections::BTreeMap;
    const RECIPIENT: &str = "age1ml79lp4sk2gz59n3xux5xhasg7p5qa0pnm634rd8pnw80avag4js2etr0l";
    const SIGNER: &str = "nix-seal-ed25519-v1:EcFcZVkcYsuXdMDG2JyOsyuoCExdGk0yUwLVriY0Vyw=";
    const SSH_SIGNER: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti release@example.com";
    #[test]
    fn empty_plan_is_stable_and_valid() -> Result<(), PolicyError> {
        let plan = PlanV1::default();
        validate(&plan)?;
        assert_eq!(plan_hash(&plan)?, plan_hash(&plan)?);
        Ok(())
    }

    #[test]
    fn external_generator_paths_are_confined_to_the_nix_store() {
        assert!(valid_store_executable(
            "/nix/store/abc123-generator/bin/generate"
        ));
        assert!(!valid_store_executable("/bin/sh"));
        assert!(!valid_store_executable(
            "/nix/store/abc123-generator/../bin/generate"
        ));
        assert!(!valid_store_executable(
            "/nix/store/abc123:unsafe/bin/generate"
        ));
    }

    #[test]
    fn canonical_secret_sources_reject_dot_segments() -> Result<(), PolicyError> {
        assert!(!valid_repository_relative_path("secrets/./database.age"));
        assert!(!valid_repository_relative_path("secrets/\n-database.age"));

        let mut plan = PlanV1::default();
        plan.identities.insert(
            Id::parse("administrator")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            Id::parse("signer").map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.secrets.insert(
            Id::parse("database/password")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Secret {
                source: "secrets/./database.age".to_owned(),
                delivery: DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: ActivationPhase::Activation,
                runtime: RuntimeSettings::default(),
                lifecycle: Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        assert!(matches!(
            validate(&plan),
            Err(PolicyError::Violation(message)) if message.contains("normalized repository-relative")
        ));
        Ok(())
    }

    #[test]
    fn public_generator_outputs_are_validated_and_disjoint() -> Result<(), PolicyError> {
        let generator_id = Id::parse("application/public-output")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let output_id = Id::parse("application/public-key")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let mut plan = PlanV1::default();
        plan.generators.insert(
            generator_id.clone(),
            Generator {
                executable: "/nix/store/example-generator/bin/generate".to_owned(),
                arguments: Vec::new(),
                runtime_inputs: Vec::new(),
                timeout_seconds: 30,
                max_output_bytes: 1024,
                dependencies: Vec::new(),
                secret_dependencies: Vec::new(),
                outputs: Vec::new(),
                public_outputs: vec![nix_seal_core::GeneratorPublicOutput {
                    id: output_id.clone(),
                    destination: "public/application-key".to_owned(),
                }],
                prompts: Vec::new(),
                parameters: BTreeMap::new(),
                validation: None,
            },
        );
        validate(&plan)?;

        let invalid_destination = Generator {
            public_outputs: vec![nix_seal_core::GeneratorPublicOutput {
                id: output_id.clone(),
                destination: "../outside".to_owned(),
            }],
            ..plan.generators[&generator_id].clone()
        };
        plan.generators
            .insert(generator_id.clone(), invalid_destination);
        assert!(validate(&plan).is_err());

        let builtin_public = Generator {
            executable: "builtin:uuid".to_owned(),
            public_outputs: vec![nix_seal_core::GeneratorPublicOutput {
                id: output_id,
                destination: "public/uuid".to_owned(),
            }],
            ..plan.generators[&generator_id].clone()
        };
        plan.generators.insert(generator_id, builtin_public);
        assert!(validate(&plan).is_err());
        Ok(())
    }

    #[test]
    fn passphrase_ssh_and_argon2id_are_admitted_builtin_generators() -> Result<(), PolicyError> {
        let generator = nix_seal_core::Generator {
            executable: "builtin:passphrase".to_owned(),
            arguments: Vec::new(),
            runtime_inputs: Vec::new(),
            timeout_seconds: nix_seal_core::DEFAULT_GENERATOR_TIMEOUT_SECONDS,
            max_output_bytes: nix_seal_core::DEFAULT_GENERATOR_MAX_OUTPUT_BYTES,
            dependencies: Vec::new(),
            secret_dependencies: Vec::new(),
            outputs: Vec::new(),
            public_outputs: Vec::new(),
            prompts: Vec::new(),
            parameters: BTreeMap::from([("words".to_owned(), "16".to_owned())]),
            validation: None,
        };
        let id =
            Id::parse("passphrase").map_err(|error| PolicyError::Violation(error.to_string()))?;
        validate_generator_execution(&id, &generator)?;
        assert!(
            validate_generator_execution(
                &id,
                &nix_seal_core::Generator {
                    secret_dependencies: vec![
                        Id::parse("application/input")
                            .map_err(|error| PolicyError::Violation(error.to_string()))?
                    ],
                    ..generator.clone()
                }
            )
            .is_err()
        );
        let ssh = nix_seal_core::Generator {
            executable: "builtin:ssh-ed25519".to_owned(),
            outputs: vec![
                Id::parse("ssh-private")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
            ],
            public_outputs: vec![nix_seal_core::GeneratorPublicOutput {
                id: Id::parse("ssh-public")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
                destination: "public/ssh-key".to_owned(),
            }],
            parameters: BTreeMap::new(),
            ..generator
        };
        validate_generator_execution(
            &Id::parse("ssh").map_err(|error| PolicyError::Violation(error.to_string()))?,
            &ssh,
        )?;
        let argon2id = nix_seal_core::Generator {
            executable: "builtin:argon2id-password-hash".to_owned(),
            outputs: vec![
                Id::parse("password-hash")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
            ],
            prompts: vec![nix_seal_core::GeneratorPrompt {
                id: Id::parse("password")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
                mode: nix_seal_core::GeneratorPromptMode::Hidden,
                message: "Password".to_owned(),
                multiline: false,
                persistent: false,
            }],
            parameters: BTreeMap::from([
                ("memory-kib".to_owned(), "19456".to_owned()),
                ("iterations".to_owned(), "2".to_owned()),
            ]),
            public_outputs: Vec::new(),
            ..ssh
        };
        validate_generator_execution(
            &Id::parse("argon2id").map_err(|error| PolicyError::Violation(error.to_string()))?,
            &argon2id,
        )?;
        let invalid_argon2id = nix_seal_core::Generator {
            parameters: BTreeMap::from([("memory-kib".to_owned(), "19455".to_owned())]),
            ..argon2id
        };
        assert!(
            validate_generator_execution(
                &Id::parse("invalid-argon2id")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
                &invalid_argon2id,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn duplicate_ids_are_rejected() -> Result<(), PolicyError> {
        let (mut a, mut b) = (PlanV1::default(), PlanV1::default());
        let id = Id::parse("ops").map_err(|error| PolicyError::Violation(error.to_string()))?;
        a.groups.insert(id.clone(), nix_seal_core::Group::default());
        b.groups.insert(id, nix_seal_core::Group::default());
        assert!(matches!(merge(a, b), Err(PolicyError::Duplicate { .. })));
        Ok(())
    }

    #[test]
    fn property_canonical_hash_is_invariant_under_public_insertion_order() -> Result<(), PolicyError>
    {
        let mut forward = PlanV1::default();
        let mut reverse = PlanV1::default();
        for index in 0..32 {
            let id = Id::parse(format!("administrator/{index:02}"))
                .map_err(|error| PolicyError::Violation(error.to_string()))?;
            let identity = Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            };
            forward.identities.insert(id.clone(), identity.clone());
            reverse.identities.insert(id, identity);
        }
        // BTreeMap canonicalization is an explicit IR invariant, not an
        // implementation detail: callers may construct plans in any order.
        assert_eq!(canonical_json(&forward)?, canonical_json(&reverse)?);
        assert_eq!(plan_hash(&forward)?, plan_hash(&reverse)?);
        Ok(())
    }

    #[test]
    fn property_disjoint_merge_is_commutative_and_duplicate_merge_is_fatal()
    -> Result<(), PolicyError> {
        let mut left = PlanV1::default();
        let mut right = PlanV1::default();
        left.identities.insert(
            Id::parse("administrator/left")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        right.identities.insert(
            Id::parse("administrator/right")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        let first = merge(left.clone(), right.clone())?;
        let second = merge(right, left)?;
        assert_eq!(canonical_json(&first)?, canonical_json(&second)?);
        assert!(matches!(
            merge(first.clone(), first),
            Err(PolicyError::Duplicate { .. })
        ));
        Ok(())
    }

    #[test]
    fn property_selector_authorization_is_monotonic_for_explicit_consumers()
    -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let admin = Id::parse("administrator")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let signer =
            Id::parse("release").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            admin,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            signer.clone(),
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.approval_policies.insert(
            Id::parse("approval").map_err(|error| PolicyError::Violation(error.to_string()))?,
            ApprovalPolicy {
                threshold: 1,
                signers: vec![signer],
            },
        );
        let mut targets = Vec::new();
        for index in 0..4 {
            let target = Id::parse(format!("target/{index}"))
                .map_err(|error| PolicyError::Violation(error.to_string()))?;
            let identity = Id::parse(format!("target-identity-{index}"))
                .map_err(|error| PolicyError::Violation(error.to_string()))?;
            plan.identities.insert(
                identity.clone(),
                Identity {
                    kind: IdentityKind::Target,
                    public: RECIPIENT.to_owned(),
                },
            );
            plan.targets.insert(
                target.clone(),
                Target {
                    kind: TargetKind::NixOs,
                    system: "x86_64-linux".to_owned(),
                    identity,
                    username: None,
                    configuration: None,
                    environment: None,
                    tags: vec!["prod".to_owned()],
                },
            );
            targets.push(target);
        }
        let secret = Id::parse("application/token")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.secrets.insert(
            secret.clone(),
            Secret {
                source: "secrets/token.age".to_owned(),
                delivery: DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors {
                    tags: vec!["prod".to_owned()],
                    ..nix_seal_core::TargetSelectors::default()
                },
                phase: ActivationPhase::Activation,
                runtime: RuntimeSettings::default(),
                lifecycle: Lifecycle::default(),
                approval_policy: Some(
                    Id::parse("approval")
                        .map_err(|error| PolicyError::Violation(error.to_string()))?,
                ),
                repository_only: false,
            },
        );
        validate(&plan)?;
        let selected = target_policy(&plan, &targets[0])?.secrets.len();
        plan.secrets
            .get_mut(&secret)
            .ok_or_else(|| PolicyError::Violation("secret missing".to_owned()))?
            .consumers
            .push(targets[1].clone());
        validate(&plan)?;
        assert!(target_policy(&plan, &targets[0])?.secrets.len() >= selected);
        assert_eq!(target_policy(&plan, &targets[1])?.secrets.len(), 1);
        Ok(())
    }

    #[test]
    fn repository_only_secrets_cannot_be_target_delivered() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let admin = Id::parse("administrator")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let target_identity = Id::parse("target-identity")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let target =
            Id::parse("host").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let signer =
            Id::parse("signer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let secret_id = Id::parse("application/intermediary")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            admin,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            target_identity.clone(),
            Identity {
                kind: IdentityKind::Target,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            signer,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.targets.insert(
            target.clone(),
            Target {
                kind: TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: target_identity,
                username: None,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        plan.secrets.insert(
            secret_id,
            Secret {
                source: "secrets/intermediary.age".to_owned(),
                delivery: DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: vec![target],
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: ActivationPhase::Activation,
                runtime: RuntimeSettings::default(),
                lifecycle: Lifecycle::default(),
                repository_only: true,
                approval_policy: None,
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    fn duplicate_signer_keys_are_rejected_before_threshold_evaluation() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let first =
            Id::parse("signer-a").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let second =
            Id::parse("signer-b").map_err(|error| PolicyError::Violation(error.to_string()))?;
        for id in [first, second] {
            plan.identities.insert(
                id,
                nix_seal_core::Identity {
                    kind: IdentityKind::Signer,
                    public: SIGNER.to_owned(),
                },
            );
        }
        assert!(validate(&plan).is_err());
        Ok(())
    }

    #[test]
    fn generator_secret_dependencies_are_distinct_existing_and_not_outputs()
    -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let administrator = Id::parse("administrator")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let signer =
            Id::parse("signer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let input = Id::parse("application/input")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let output = Id::parse("application/output")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            administrator,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            signer,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        for (id, source) in [
            (&input, "secrets/input.age"),
            (&output, "secrets/output.age"),
        ] {
            plan.secrets.insert(
                id.clone(),
                Secret {
                    source: source.to_owned(),
                    delivery: DeliveryMode::Rekeyed,
                    administrators: Vec::new(),
                    consumers: Vec::new(),
                    selectors: nix_seal_core::TargetSelectors::default(),
                    phase: ActivationPhase::Activation,
                    runtime: RuntimeSettings::default(),
                    lifecycle: Lifecycle::default(),
                    approval_policy: None,
                    repository_only: false,
                },
            );
        }
        let generator_id = Id::parse("application/generator")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.generators.insert(
            generator_id,
            Generator {
                executable: "/nix/store/abc123-generator/bin/generate".to_owned(),
                arguments: Vec::new(),
                runtime_inputs: Vec::new(),
                timeout_seconds: 30,
                max_output_bytes: 1024,
                dependencies: Vec::new(),
                secret_dependencies: vec![input.clone(), output.clone()],
                outputs: vec![output.clone()],
                public_outputs: Vec::new(),
                prompts: Vec::new(),
                parameters: BTreeMap::new(),
                validation: None,
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        let invalid = plan
            .generators
            .remove(
                &Id::parse("application/generator")
                    .map_err(|error| PolicyError::Violation(error.to_string()))?,
            )
            .ok_or_else(|| PolicyError::Violation("test generator is missing".to_owned()))?;
        let producer_id = Id::parse("application/producer")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let consumer_id = Id::parse("application/consumer")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let mut producer = invalid.clone();
        producer.secret_dependencies = Vec::new();
        producer.outputs = vec![input.clone()];
        let mut consumer = invalid;
        consumer.secret_dependencies = vec![input];
        consumer.outputs = vec![output];
        consumer.dependencies = Vec::new();
        plan.generators.insert(producer_id.clone(), producer);
        plan.generators.insert(consumer_id.clone(), consumer);
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        plan.generators
            .get_mut(&consumer_id)
            .ok_or_else(|| PolicyError::Violation("test consumer is missing".to_owned()))?
            .dependencies = vec![producer_id];
        validate(&plan)?;
        Ok(())
    }

    #[test]
    fn duplicate_openssh_signer_keys_ignore_public_comments() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let first =
            Id::parse("signer-a").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let second =
            Id::parse("signer-b").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            first,
            nix_seal_core::Identity {
                kind: IdentityKind::Signer,
                public: SSH_SIGNER.to_owned(),
            },
        );
        plan.identities.insert(
            second,
            nix_seal_core::Identity {
                kind: IdentityKind::Signer,
                public: SSH_SIGNER.replace("release@example.com", "incident@example.com"),
            },
        );
        assert!(validate(&plan).is_err());
        Ok(())
    }

    #[test]
    fn encryption_identities_require_a_valid_age_recipient() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let id = Id::parse("administrator")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            id,
            Identity {
                kind: IdentityKind::Administrator,
                public: "not-an-age-recipient".to_owned(),
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    fn target_selectors_expand_deterministically() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let parse = |value: &str| {
            Id::parse(value).map_err(|error| PolicyError::Violation(error.to_string()))
        };
        let administrator = parse("administrator")?;
        let signer = parse("release-signer")?;
        let first_target = parse("desktop")?;
        let second_target = parse("server")?;
        plan.identities.insert(
            administrator,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            signer,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        for (target_id, identity_id, kind, system, tags) in [
            (
                first_target.clone(),
                parse("target-desktop")?,
                TargetKind::NixOs,
                "x86_64-linux",
                vec!["prod".to_owned(), "desktop".to_owned()],
            ),
            (
                second_target.clone(),
                parse("target-server")?,
                TargetKind::Darwin,
                "aarch64-darwin",
                vec!["prod".to_owned(), "server".to_owned()],
            ),
        ] {
            plan.identities.insert(
                identity_id.clone(),
                Identity {
                    kind: IdentityKind::Target,
                    public: RECIPIENT.to_owned(),
                },
            );
            plan.targets.insert(
                target_id,
                Target {
                    kind,
                    system: system.to_owned(),
                    identity: identity_id,
                    username: None,
                    configuration: Some("desktop".to_owned()),
                    environment: Some("prod".to_owned()),
                    tags,
                },
            );
        }
        let secret_id = parse("db/password")?;
        plan.secrets.insert(
            secret_id,
            Secret {
                source: "secrets/db-password.age".to_owned(),
                delivery: DeliveryMode::Rekeyed,
                administrators: Vec::new(),
                consumers: Vec::new(),
                selectors: nix_seal_core::TargetSelectors {
                    systems: vec!["x86_64-linux".to_owned()],
                    tags: vec!["desktop".to_owned()],
                    ..Default::default()
                },
                phase: ActivationPhase::Activation,
                runtime: RuntimeSettings::default(),
                lifecycle: Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        validate(&plan)?;
        let first_policy = target_policy(&plan, &first_target)?;
        let second_policy = target_policy(&plan, &second_target)?;
        assert_eq!(first_policy.secrets.len(), 1);
        assert!(second_policy.secrets.is_empty());
        Ok(())
    }

    #[test]
    fn signer_identities_require_a_valid_approval_key() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let id = Id::parse("signer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            id,
            Identity {
                kind: IdentityKind::Signer,
                public: "not-an-approval-key".to_owned(),
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    fn signer_identities_accept_openssh_ed25519_approval_keys() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let id =
            Id::parse("ssh-signer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            id,
            Identity {
                kind: IdentityKind::Signer,
                public: SSH_SIGNER.to_owned(),
            },
        );
        validate(&plan)
    }

    #[test]
    fn plugin_identities_require_standard_age_plugin_recipients() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let id = Id::parse("hardware-token")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            id,
            Identity {
                kind: IdentityKind::Plugin,
                public: "not-a-plugin-recipient".to_owned(),
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn templates_require_valid_secret_bindings_and_noncolliding_outputs() -> Result<(), PolicyError>
    {
        let mut plan = PlanV1::default();
        plan.identities.insert(
            Id::parse("release-signer")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.identities.insert(
            Id::parse("administrator")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        let secret_id =
            Id::parse("db/password").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let secret = Secret {
            source: "secrets/db-password.age".to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            selectors: nix_seal_core::TargetSelectors::default(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
            repository_only: false,
        };
        plan.secrets.insert(secret_id.clone(), secret.clone());
        let template_id = Id::parse("application/config")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.templates.insert(
            template_id,
            Template {
                source: "templates/application.conf".to_owned(),
                placeholders: BTreeMap::from([(
                    "password".to_owned(),
                    TemplatePlaceholder {
                        secret: secret_id.clone(),
                        encoding: TemplateEncoding::Utf8,
                    },
                )]),
                runtime: RuntimeSettings::default(),
            },
        );
        validate(&plan)?;

        let users_secret_id = Id::parse("db/users-password")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let mut users_secret = secret.clone();
        users_secret.source = "secrets/db-users-password.age".to_owned();
        users_secret.phase = ActivationPhase::Users;
        plan.secrets.insert(users_secret_id.clone(), users_secret);
        plan.templates
            .values_mut()
            .next()
            .ok_or_else(|| PolicyError::Violation("template missing".to_owned()))?
            .placeholders
            .insert(
                "users-password".to_owned(),
                TemplatePlaceholder {
                    secret: users_secret_id.clone(),
                    encoding: TemplateEncoding::Utf8,
                },
            );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        plan.secrets.remove(&users_secret_id);
        plan.templates
            .values_mut()
            .next()
            .ok_or_else(|| PolicyError::Violation("template missing".to_owned()))?
            .placeholders
            .remove("users-password");

        let missing_id = Id::parse("missing/secret")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.templates
            .values_mut()
            .next()
            .ok_or_else(|| PolicyError::Violation("template missing".to_owned()))?
            .placeholders
            .get_mut("password")
            .ok_or_else(|| PolicyError::Violation("placeholder missing".to_owned()))?
            .secret = missing_id;
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        let template = plan
            .templates
            .values_mut()
            .next()
            .ok_or_else(|| PolicyError::Violation("template missing".to_owned()))?;
        template
            .placeholders
            .get_mut("password")
            .ok_or_else(|| PolicyError::Violation("placeholder missing".to_owned()))?
            .secret = secret_id;
        let collision_id = Id::parse("templates/application/config")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.secrets.insert(collision_id, secret);
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn target_projection_resolves_nested_groups_approvals_and_templates() -> Result<(), PolicyError>
    {
        let mut plan = PlanV1::default();
        let signer_id =
            Id::parse("signer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let recipient_id = Id::parse("host-recipient")
            .map_err(|error| PolicyError::Violation(error.to_string()))?;
        let target_id =
            Id::parse("host.primary").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let other_target_id =
            Id::parse("host.other").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.identities.insert(
            signer_id.clone(),
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.identities.insert(
            Id::parse("administrator")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        plan.identities.insert(
            recipient_id.clone(),
            Identity {
                kind: IdentityKind::Target,
                public: RECIPIENT.to_owned(),
            },
        );
        for id in [&target_id, &other_target_id] {
            plan.targets.insert(
                id.clone(),
                Target {
                    kind: TargetKind::NixOs,
                    system: "x86_64-linux".to_owned(),
                    identity: recipient_id.clone(),
                    username: None,
                    configuration: None,
                    environment: None,
                    tags: Vec::new(),
                },
            );
        }
        let inner_group =
            Id::parse("hosts.inner").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let outer_group =
            Id::parse("hosts.outer").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.groups.insert(
            inner_group.clone(),
            Group {
                members: vec![target_id.clone()],
            },
        );
        plan.groups.insert(
            outer_group.clone(),
            Group {
                members: vec![inner_group],
            },
        );
        let authorized_id =
            Id::parse("db/password").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let inaccessible_id =
            Id::parse("other/token").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let secret = |source: &str, consumer: Id| Secret {
            source: source.to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: vec![consumer],
            selectors: nix_seal_core::TargetSelectors::default(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
            repository_only: false,
        };
        plan.secrets
            .insert(authorized_id.clone(), secret("secrets/db.age", outer_group));
        plan.secrets.insert(
            inaccessible_id.clone(),
            secret("secrets/other.age", other_target_id),
        );
        plan.templates.insert(
            Id::parse("application/config")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Template {
                source: "templates/application.conf".to_owned(),
                placeholders: BTreeMap::from([(
                    "password".to_owned(),
                    TemplatePlaceholder {
                        secret: authorized_id.clone(),
                        encoding: TemplateEncoding::Utf8,
                    },
                )]),
                runtime: RuntimeSettings::default(),
            },
        );
        plan.templates.insert(
            Id::parse("other/config").map_err(|error| PolicyError::Violation(error.to_string()))?,
            Template {
                source: "templates/other.conf".to_owned(),
                placeholders: BTreeMap::from([(
                    "token".to_owned(),
                    TemplatePlaceholder {
                        secret: inaccessible_id.clone(),
                        encoding: TemplateEncoding::Hex,
                    },
                )]),
                runtime: RuntimeSettings::default(),
            },
        );

        let projection = target_policy(&plan, &target_id)?;
        assert_eq!(projection.plan_hash, plan_hash(&plan)?);
        assert!(projection.secrets.contains_key(&authorized_id));
        assert!(!projection.secrets.contains_key(&inaccessible_id));
        assert_eq!(projection.templates.len(), 1);
        assert_eq!(
            projection
                .templates
                .values()
                .next()
                .ok_or_else(|| PolicyError::Violation("template missing".to_owned()))?
                .phase,
            ActivationPhase::Activation
        );
        let approval = &projection
            .secrets
            .get(&authorized_id)
            .ok_or_else(|| PolicyError::Violation("authorized secret missing".to_owned()))?
            .approval;
        assert_eq!(approval.threshold, 1);
        assert_eq!(approval.signers.get(&signer_id), Some(&SIGNER.to_owned()));
        assert_eq!(
            target_policy_hash(&projection)?,
            target_policy_hash(&projection)?
        );
        Ok(())
    }

    #[test]
    fn group_cycles_are_rejected_without_recursive_traversal() -> Result<(), PolicyError> {
        let mut plan = PlanV1::default();
        let first =
            Id::parse("first").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let second =
            Id::parse("second").map_err(|error| PolicyError::Violation(error.to_string()))?;
        plan.groups.insert(
            first.clone(),
            Group {
                members: vec![second.clone()],
            },
        );
        plan.groups.insert(
            second,
            Group {
                members: vec![first],
            },
        );
        assert!(matches!(validate(&plan), Err(PolicyError::Violation(_))));
        Ok(())
    }

    #[test]
    fn canonical_recipients_are_plan_derived_and_direct_mode_is_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = PlanV1::default();
        let admin = Id::parse("admin")?;
        let recovery = Id::parse("recovery")?;
        let signer = Id::parse("signer")?;
        let target_identity = Id::parse("target-recipient")?;
        let target = Id::parse("host.test")?;
        let group = Id::parse("hosts")?;
        let secret = Id::parse("db/password")?;
        for (id, kind, public) in [
            (&admin, IdentityKind::Administrator, RECIPIENT),
            (&recovery, IdentityKind::Recovery, RECIPIENT),
            (&signer, IdentityKind::Signer, SIGNER),
            (&target_identity, IdentityKind::Target, RECIPIENT),
        ] {
            plan.identities.insert(
                id.clone(),
                Identity {
                    kind,
                    public: public.to_owned(),
                },
            );
        }
        plan.targets.insert(
            target.clone(),
            Target {
                kind: TargetKind::NixOs,
                system: "x86_64-linux".to_owned(),
                identity: target_identity.clone(),
                username: None,
                configuration: None,
                environment: None,
                tags: Vec::new(),
            },
        );
        plan.groups.insert(
            group.clone(),
            Group {
                members: vec![target.clone()],
            },
        );
        plan.secrets.insert(
            secret.clone(),
            Secret {
                source: "secrets/db.age".to_owned(),
                delivery: DeliveryMode::Direct,
                administrators: vec![admin.clone()],
                consumers: vec![group],
                selectors: nix_seal_core::TargetSelectors::default(),
                phase: ActivationPhase::Activation,
                runtime: RuntimeSettings::default(),
                lifecycle: Lifecycle::default(),
                approval_policy: None,
                repository_only: false,
            },
        );
        let recipients = secret_recipients(&plan, &secret)?;
        assert_eq!(recipients.recipients.len(), 3);
        assert!(recipients.recipients.contains_key(&admin));
        assert!(recipients.recipients.contains_key(&recovery));
        assert!(recipients.recipients.contains_key(&target_identity));
        Ok(())
    }

    #[test]
    fn lifecycle_reporting_distinguishes_rotation_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut plan = PlanV1::default();
        let signer = Id::parse("signer")?;
        let admin = Id::parse("admin")?;
        plan.identities.insert(
            signer,
            Identity {
                kind: IdentityKind::Signer,
                public: SIGNER.to_owned(),
            },
        );
        plan.identities.insert(
            admin,
            Identity {
                kind: IdentityKind::Administrator,
                public: RECIPIENT.to_owned(),
            },
        );
        let rotating = Id::parse("rotating")?;
        let expired = Id::parse("expired")?;
        let base = |source: &str, lifecycle| Secret {
            source: source.to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            selectors: nix_seal_core::TargetSelectors::default(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle,
            approval_policy: None,
            repository_only: false,
        };
        plan.secrets.insert(
            rotating.clone(),
            base(
                "secrets/rotating.age",
                Lifecycle {
                    created_at: Some("2026-01-01T00:00:00Z".to_owned()),
                    rotate_after_days: Some(10),
                    ..Lifecycle::default()
                },
            ),
        );
        plan.secrets.insert(
            expired.clone(),
            base(
                "secrets/expired.age",
                Lifecycle {
                    created_at: Some("2026-01-01T00:00:00Z".to_owned()),
                    expires_at: Some("2026-01-02T00:00:00Z".to_owned()),
                    ..Lifecycle::default()
                },
            ),
        );
        let now: jiff::Timestamp = "2026-02-01T00:00:00Z".parse()?;
        let now: SystemTime = now.into();
        let report = lifecycle_report(&plan, now)?;
        assert_eq!(report[0].secret_id, expired);
        assert_eq!(report[0].state, LifecycleStateV1::Expired);
        assert_eq!(report[1].secret_id, rotating);
        assert_eq!(report[1].state, LifecycleStateV1::RotationDue);
        Ok(())
    }

    #[test]
    fn checked_in_plan_schema_matches_the_released_schema_generator()
    -> Result<(), Box<dyn std::error::Error>> {
        let generated: serde_json::Value = serde_json::from_str(&json_schema()?)?;
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/plan-v1.schema.json"))?;
        assert_eq!(generated, checked_in);
        Ok(())
    }
}

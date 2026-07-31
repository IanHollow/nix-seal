#![forbid(unsafe_code)]
//! Strict loading, merging, validation, and canonicalization of public plans.

use nix_seal_core::{
    ActivationPhase, ApprovalPolicy, DeliveryMode, Id, IdentityKind, PLAN_SCHEMA, PlanV1,
    RuntimeSettings, TargetKind, TemplatePlaceholder,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
    path::Path,
};
use thiserror::Error;

const MAX_PLAN_BYTES: u64 = 16 * 1024 * 1024;

/// Exact schema for one deterministic target-specific policy projection.
pub const TARGET_POLICY_SCHEMA: &str = "nix-seal.target-policy.v1";

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
    for (id, target) in &plan.targets {
        let identity = plan.identities.get(&target.identity).ok_or_else(|| {
            PolicyError::Violation(format!(
                "target {id} references missing identity {}",
                target.identity
            ))
        })?;
        if !matches!(identity.kind, IdentityKind::Target | IdentityKind::Plugin) {
            return Err(PolicyError::Violation(format!(
                "target {id} identity {} is not target/plugin kind",
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

fn validate_secrets(plan: &PlanV1) -> Result<(), PolicyError> {
    for (id, secret) in &plan.secrets {
        if secret.source.starts_with('/')
            || secret
                .source
                .split('/')
                .any(|part| part == ".." || part.is_empty())
        {
            return Err(PolicyError::Violation(format!(
                "secret {id} source must be a normalized repository-relative path"
            )));
        }
        for consumer in &secret.consumers {
            if !plan.targets.contains_key(consumer) && !plan.groups.contains_key(consumer) {
                return Err(PolicyError::Violation(format!(
                    "secret {id} references missing consumer {consumer}"
                )));
            }
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
    }
    Ok(())
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
        if !is_private_runtime_mode(&template.runtime.mode) {
            return Err(PolicyError::Violation(format!(
                "template {id} runtime mode must be a nonzero owner-only four-digit octal mode"
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

fn target_is_consumer(plan: &PlanV1, consumers: &[Id], target_id: &Id) -> bool {
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

fn validate_generator_graph(plan: &PlanV1) -> Result<(), PolicyError> {
    let mut indegree = BTreeMap::new();
    let mut dependents: BTreeMap<&Id, Vec<&Id>> = BTreeMap::new();
    for (generator_id, generator) in &plan.generators {
        if generator.dependencies.len() > 10_000 || generator.outputs.len() > 10_000 {
            return Err(PolicyError::Violation(format!(
                "generator {generator_id} exceeds dependency or output limits"
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
    Ok(())
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
        if target_is_consumer(plan, &secret.consumers, target_id) {
            secrets.insert(
                secret_id.clone(),
                TargetSecretPolicyV1 {
                    source: secret.source.clone(),
                    delivery: secret.delivery.clone(),
                    phase: secret.phase.clone(),
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
            (
                template_id.clone(),
                TargetTemplatePolicyV1 {
                    source: template.source.clone(),
                    placeholders: template.placeholders.clone(),
                    runtime: template.runtime.clone(),
                },
            )
        })
        .collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use nix_seal_core::{
        ActivationPhase, DeliveryMode, Group, Identity, Lifecycle, RuntimeSettings, Secret, Target,
        TargetKind, Template, TemplateEncoding, TemplatePlaceholder,
    };
    use std::collections::BTreeMap;
    #[test]
    fn empty_plan_is_stable_and_valid() -> Result<(), PolicyError> {
        let plan = PlanV1::default();
        validate(&plan)?;
        assert_eq!(plan_hash(&plan)?, plan_hash(&plan)?);
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
    fn templates_require_valid_secret_bindings_and_noncolliding_outputs() -> Result<(), PolicyError>
    {
        let mut plan = PlanV1::default();
        plan.identities.insert(
            Id::parse("release-signer")
                .map_err(|error| PolicyError::Violation(error.to_string()))?,
            Identity {
                kind: IdentityKind::Signer,
                public: "public-signer-fixture".to_owned(),
            },
        );
        let secret_id =
            Id::parse("db/password").map_err(|error| PolicyError::Violation(error.to_string()))?;
        let secret = Secret {
            source: "secrets/db-password.age".to_owned(),
            delivery: DeliveryMode::Rekeyed,
            administrators: Vec::new(),
            consumers: Vec::new(),
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
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
                public: "signer-public".to_owned(),
            },
        );
        plan.identities.insert(
            recipient_id.clone(),
            Identity {
                kind: IdentityKind::Target,
                public: "age1target-recipient".to_owned(),
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
            phase: ActivationPhase::Activation,
            runtime: RuntimeSettings::default(),
            lifecycle: Lifecycle::default(),
            approval_policy: None,
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
        let approval = &projection
            .secrets
            .get(&authorized_id)
            .ok_or_else(|| PolicyError::Violation("authorized secret missing".to_owned()))?
            .approval;
        assert_eq!(approval.threshold, 1);
        assert_eq!(
            approval.signers.get(&signer_id),
            Some(&"signer-public".to_owned())
        );
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
}

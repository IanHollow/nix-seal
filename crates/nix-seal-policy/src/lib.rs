#![forbid(unsafe_code)]
//! Strict loading, merging, validation, and canonicalization of public plans.

use nix_seal_core::{ApprovalPolicy, Id, IdentityKind, PLAN_SCHEMA, PlanV1};
use std::{collections::BTreeSet, path::Path};
use thiserror::Error;

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
    /// TOML decoding failed.
    #[error("invalid TOML plan: {0}")]
    Toml(#[from] toml::de::Error),
    /// JSON decoding failed.
    #[error("invalid JSON plan: {0}")]
    Json(#[from] serde_json::Error),
    /// Schema version is unsupported.
    #[error("unsupported plan schema {0:?}; expected {PLAN_SCHEMA:?}")]
    Schema(String),
    /// Two sources declare the same object ID.
    #[error("duplicate {kind} ID {id:?} across Nix and TOML plans")]
    Duplicate {
        /// Object collection.
        kind: &'static str,
        /// Conflicting ID.
        id: Id,
    },
    /// A policy invariant failed.
    #[error("policy violation: {0}")]
    Violation(String),
}

/// Loads a strict TOML plan.
pub fn load_toml(path: &Path) -> Result<PlanV1, PolicyError> {
    let value = std::fs::read_to_string(path).map_err(|source| PolicyError::Read {
        path: path.display().to_string(),
        source,
    })?;
    Ok(toml::from_str(&value)?)
}

/// Loads a strict JSON plan, including Nix-emitted plans.
pub fn load_json(path: &Path) -> Result<PlanV1, PolicyError> {
    let value = std::fs::read(path).map_err(|source| PolicyError::Read {
        path: path.display().to_string(),
        source,
    })?;
    Ok(serde_json::from_slice(&value)?)
}

/// Merges disjoint authoritative sources. Any overlapping ID is fatal.
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
        let mode =
            u32::from_str_radix(secret.runtime.mode.trim_start_matches('0'), 8).unwrap_or(u32::MAX);
        if mode & 0o077 != 0 {
            return Err(PolicyError::Violation(format!(
                "secret {id} runtime mode grants group/other access"
            )));
        }
    }
    for (id, policy) in &plan.approval_policies {
        validate_approval(id, policy, plan)?;
    }
    validate_generator_graph(plan)
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
    fn visit(
        node: &Id,
        plan: &PlanV1,
        visiting: &mut BTreeSet<Id>,
        visited: &mut BTreeSet<Id>,
    ) -> Result<(), PolicyError> {
        if visited.contains(node) {
            return Ok(());
        }
        if !visiting.insert(node.clone()) {
            return Err(PolicyError::Violation(format!(
                "generator dependency cycle contains {node}"
            )));
        }
        let generator = plan.generators.get(node).ok_or_else(|| {
            PolicyError::Violation(format!("missing generator dependency {node}"))
        })?;
        for dependency in &generator.dependencies {
            visit(dependency, plan, visiting, visited)?;
        }
        visiting.remove(node);
        visited.insert(node.clone());
        Ok(())
    }
    let (mut visiting, mut visited) = (BTreeSet::new(), BTreeSet::new());
    for id in plan.generators.keys() {
        visit(id, plan, &mut visiting, &mut visited)?;
    }
    Ok(())
}

/// Returns RFC 8785 canonical JSON bytes.
pub fn canonical_json(plan: &PlanV1) -> Result<Vec<u8>, PolicyError> {
    Ok(serde_jcs::to_vec(plan)?)
}

/// Returns the BLAKE3 digest of the canonical plan.
pub fn plan_hash(plan: &PlanV1) -> Result<String, PolicyError> {
    Ok(blake3::hash(&canonical_json(plan)?).to_hex().to_string())
}

/// Returns the JSON Schema for plan.v1.
pub fn json_schema() -> Result<String, PolicyError> {
    Ok(serde_json::to_string_pretty(&schemars::schema_for!(
        PlanV1
    ))?)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}

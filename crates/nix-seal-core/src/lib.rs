#![forbid(unsafe_code)]
//! Versioned public plan types. These values must never contain plaintext.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};
use thiserror::Error;

/// Current intermediate-representation schema identifier.
pub const PLAN_SCHEMA: &str = "nix-seal.plan.v1";
/// Default maximum execution time for a constrained external generator.
pub const DEFAULT_GENERATOR_TIMEOUT_SECONDS: u16 = 30;
/// Default per-output plaintext safety limit for a constrained external generator.
pub const DEFAULT_GENERATOR_MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;

/// A validated stable object identifier.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Id(String);

impl Id {
    /// Parses and validates an `ID`.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        if value.is_empty() || value.starts_with('/') || value.contains("..") {
            return Err(IdError::Invalid(value));
        }
        if value.split('/').any(str::is_empty)
            || !value.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '/' | '-' | '_')
            })
        {
            return Err(IdError::Invalid(value));
        }
        Ok(Self(value))
    }

    /// Returns the validated string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Id {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// `ID` validation failure.
#[derive(Debug, Error)]
pub enum IdError {
    /// The string is outside the public `ID` grammar.
    #[error(
        "invalid ID {0:?}; use lowercase ASCII slugs without absolute paths, '..', or empty segments"
    )]
    Invalid(String),
}

/// Fully compiled public plan.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanV1 {
    /// Must equal [`PLAN_SCHEMA`].
    pub schema: String,
    /// Public recipients and signers.
    #[serde(default)]
    pub identities: BTreeMap<Id, Identity>,
    /// Named sets of object `IDs`.
    #[serde(default)]
    pub groups: BTreeMap<Id, Group>,
    /// Platform consumers.
    #[serde(default)]
    pub targets: BTreeMap<Id, Target>,
    /// Secret policy and encrypted source metadata.
    #[serde(default)]
    pub secrets: BTreeMap<Id, Secret>,
    /// Generator definitions.
    #[serde(default)]
    pub generators: BTreeMap<Id, Generator>,
    /// Runtime template definitions.
    #[serde(default)]
    pub templates: BTreeMap<Id, Template>,
    /// Artifact signature policies.
    #[serde(default)]
    pub approval_policies: BTreeMap<Id, ApprovalPolicy>,
    /// Encryption/provider backends.
    #[serde(default)]
    pub backends: BTreeMap<Id, Backend>,
}

impl Default for PlanV1 {
    fn default() -> Self {
        Self {
            schema: PLAN_SCHEMA.to_owned(),
            identities: BTreeMap::new(),
            groups: BTreeMap::new(),
            targets: BTreeMap::new(),
            secrets: BTreeMap::new(),
            generators: BTreeMap::new(),
            templates: BTreeMap::new(),
            approval_policies: BTreeMap::new(),
            backends: BTreeMap::new(),
        }
    }
}

/// Public recipient or signer identity.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Identity {
    /// Identity role.
    pub kind: IdentityKind,
    /// Public recipient, key, or plugin reference.
    pub public: String,
}

/// Identity role.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityKind {
    /// Administrator encryption recipient.
    Administrator,
    /// Target encryption recipient.
    Target,
    /// Recovery encryption recipient.
    Recovery,
    /// Artifact approval verifier.
    Signer,
    /// Standard age plugin reference.
    Plugin,
}

/// Named group of `IDs`.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Group {
    /// Members of the group.
    #[serde(default)]
    pub members: Vec<Id>,
}

/// Target platform consumer.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Target {
    /// Integration type.
    pub kind: TargetKind,
    /// Nix system value.
    pub system: String,
    /// Recipient identity `ID`.
    pub identity: Id,
    /// Optional Home Manager user.
    pub username: Option<String>,
    /// Public selector tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Supported integration type.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetKind {
    /// `NixOS` system.
    NixOs,
    /// nix-darwin system.
    Darwin,
    /// Standalone or integrated Home Manager profile.
    HomeManager,
}

/// Secret policy. It contains paths and metadata, never plaintext.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Secret {
    /// Repository-relative canonical age ciphertext path.
    pub source: String,
    /// Artifact delivery model.
    #[serde(default)]
    pub delivery: DeliveryMode,
    /// Explicit administrator identity/group `IDs`.
    #[serde(default)]
    pub administrators: Vec<Id>,
    /// Explicit target/group `IDs`.
    #[serde(default)]
    pub consumers: Vec<Id>,
    /// Required activation phase.
    #[serde(default)]
    pub phase: ActivationPhase,
    /// Runtime delivery settings.
    #[serde(default)]
    pub runtime: RuntimeSettings,
    /// Lifecycle metadata.
    #[serde(default)]
    pub lifecycle: Lifecycle,
    /// Keep this secret in the repository/cache but never authorize a target consumer.
    #[serde(default)]
    pub repository_only: bool,
    /// Approval policy `ID`.
    pub approval_policy: Option<Id>,
}

/// Ciphertext delivery model.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DeliveryMode {
    /// Target-bound cache artifacts.
    #[default]
    Rekeyed,
    /// Canonical ciphertext includes target recipients.
    Direct,
}

/// Activation lifecycle phase.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ActivationPhase {
    /// Disk/installation phase.
    Partitioning,
    /// Before user creation.
    Users,
    /// General activation.
    #[default]
    Activation,
    /// Before service consumption.
    Services,
}

/// Runtime materialization controls.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeSettings {
    /// File owner.
    pub owner: String,
    /// File group.
    pub group: String,
    /// Octal mode represented as a string.
    pub mode: String,
    /// Units restarted after a successful switch.
    #[serde(default)]
    pub restart_units: Vec<String>,
    /// Units reloaded after a successful switch.
    #[serde(default)]
    pub reload_units: Vec<String>,
}
impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            owner: "root".into(),
            group: "root".into(),
            mode: "0400".into(),
            restart_units: vec![],
            reload_units: vec![],
        }
    }
}

/// Public lifecycle metadata.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Lifecycle {
    /// ISO-8601 creation time.
    pub created_at: Option<String>,
    /// ISO-8601 time of the most recent application-credential rotation.
    pub rotated_at: Option<String>,
    /// ISO-8601 expiry time.
    pub expires_at: Option<String>,
    /// Rotation interval in days.
    pub rotate_after_days: Option<u32>,
    /// Responsible contact.
    pub contact: Option<String>,
    /// Non-secret purpose.
    pub purpose: Option<String>,
    /// Public classification.
    pub classification: Option<String>,
    /// Public incident or ticket reference associated with this credential.
    pub incident_reference: Option<String>,
}

/// Generator declaration.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Generator {
    /// Built-in name or direct executable store path.
    pub executable: String,
    /// Literal public arguments passed directly to an external executable.
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Nix-store package roots whose `bin` directories form the generator `PATH`.
    #[serde(default)]
    pub runtime_inputs: Vec<String>,
    /// Maximum external-generator execution time in seconds.
    #[serde(default = "default_generator_timeout_seconds")]
    pub timeout_seconds: u16,
    /// Maximum plaintext bytes accepted from each external output file.
    #[serde(default = "default_generator_max_output_bytes")]
    pub max_output_bytes: u64,
    /// Generator dependencies.
    #[serde(default)]
    pub dependencies: Vec<Id>,
    /// Canonical secret inputs exposed only to a constrained external generator.
    #[serde(default)]
    pub secret_dependencies: Vec<Id>,
    /// Declared outputs.
    pub outputs: Vec<Id>,
    /// Explicit prompt declarations. Prompt values never enter the public plan.
    #[serde(default)]
    pub prompts: Vec<GeneratorPrompt>,
    /// Strict public generator parameters, such as a random-byte length.
    #[serde(default)]
    pub parameters: BTreeMap<String, String>,
    /// Public validation fingerprint.
    pub validation: Option<String>,
}

/// One declared external-generator prompt.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GeneratorPrompt {
    /// Stable prompt identifier, used to bind a private response file.
    pub id: Id,
    /// Whether interactive frontends should mask the response.
    pub mode: GeneratorPromptMode,
    /// Public operator-facing prompt text.
    pub message: String,
    /// Whether the response may contain multiple lines.
    #[serde(default)]
    pub multiline: bool,
    /// Whether a later persistent-prompt backend may retain the response.
    #[serde(default)]
    pub persistent: bool,
}

/// Display behavior for an external-generator prompt.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeneratorPromptMode {
    /// Input should not be echoed by an interactive frontend.
    Hidden,
    /// Input may be displayed by an interactive frontend.
    Visible,
}

fn default_generator_timeout_seconds() -> u16 {
    DEFAULT_GENERATOR_TIMEOUT_SECONDS
}

fn default_generator_max_output_bytes() -> u64 {
    DEFAULT_GENERATOR_MAX_OUTPUT_BYTES
}

/// Runtime template declaration.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Template {
    /// Non-secret source path.
    pub source: String,
    /// Strict placeholder declarations keyed by placeholder name.
    pub placeholders: BTreeMap<String, TemplatePlaceholder>,
    /// Rendered-file runtime settings.
    #[serde(default)]
    pub runtime: RuntimeSettings,
}

/// One explicit template placeholder binding.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemplatePlaceholder {
    /// Secret inserted at the placeholder.
    pub secret: Id,
    /// Explicit conversion from arbitrary secret bytes to template text.
    pub encoding: TemplateEncoding,
}

/// Supported plan-level secret-to-text transformations.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateEncoding {
    /// Require valid UTF-8 and copy without modification.
    Utf8,
    /// RFC 4648 base64 with padding.
    Base64,
    /// Lowercase hexadecimal.
    Hex,
}

/// N-of-M artifact signature policy.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovalPolicy {
    /// Required distinct signer count.
    pub threshold: u16,
    /// Trusted signer `IDs`.
    pub signers: Vec<Id>,
}

/// Backend declaration.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Backend {
    /// Backend kind.
    pub kind: BackendKind,
    /// Reserved public backend options. Native age uses an empty map.
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

/// Supported backend kinds.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendKind {
    /// Standard age.
    Age,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_follow_public_grammar() {
        for bad in ["", "/root", "a/../b", "a//b", "Upper", "a b"] {
            assert!(Id::parse(bad).is_err());
        }
        assert!(Id::parse("prod/db-password_v2").is_ok());
    }
}

{ lib }:
let
  validId =
    value:
    builtins.isString value
    && builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null
    && !(lib.hasInfix ".." value);

  validateCollection =
    kind: value:
    if !builtins.isAttrs value then
      throw "nix-seal.lib.mkPlan: ${kind} must be an attribute set keyed by IDs"
    else
      let
        invalid = lib.filter (id: !validId id) (builtins.attrNames value);
      in
      if invalid != [ ] then
        throw "nix-seal.lib.mkPlan: ${kind} contains invalid ID ${builtins.head invalid}"
      else
        value;
in
{
  schemaVersion = "nix-seal.plan.v1";
  schema = ../../schemas/plan-v1.schema.json;
  # Kept as a public helper for callers that validate IDs before constructing a
  # collection. `mkPlan` applies the same predicate to every collection key.
  inherit validId;

  # Nix values are public metadata only. This intentionally has no `...` in the
  # argument pattern: a typo in a top-level collection is a hard evaluation
  # error instead of being silently carried into the plan. Rust still performs
  # strict validation of every nested object and canonical hashing after this
  # deterministic JSON representation is emitted.
  mkPlan =
    {
      identities ? { },
      groups ? { },
      targets ? { },
      secrets ? { },
      generators ? { },
      templates ? { },
      approvalPolicies ? { },
      backends ? { },
    }:
    let
      checked = {
        identities = validateCollection "identities" identities;
        groups = validateCollection "groups" groups;
        targets = validateCollection "targets" targets;
        secrets = validateCollection "secrets" secrets;
        generators = validateCollection "generators" generators;
        templates = validateCollection "templates" templates;
        approvalPolicies = validateCollection "approvalPolicies" approvalPolicies;
        backends = validateCollection "backends" backends;
      };
    in
    builtins.toJSON (
      {
        schema = "nix-seal.plan.v1";
      }
      // {
        # The explicit projection is intentionally closed: arbitrary caller
        # attributes can never enter the versioned IR. Nix attrsets serialize
        # with deterministic key ordering; Rust validates nested objects.
        inherit (checked) identities;
        inherit (checked) groups;
        inherit (checked) targets;
        inherit (checked) secrets;
        inherit (checked) generators;
        inherit (checked) templates;
        inherit (checked) approvalPolicies;
        inherit (checked) backends;
      }
    );

  # Public, evaluated bridge for agenix-rekey migration. `rekeyFile` values must
  # be repository-relative strings (not Nix path values, which coerce to store
  # paths). Call `nix-seal migrate agenix-rekey --metadata` on the JSON output.
  agenixRekeyMigrationExport =
    {
      target,
      masterRecipients,
      secrets,
    }:
    builtins.toJSON {
      schema = "nix-seal.agenix-rekey-export.v1";
      inherit target masterRecipients secrets;
    };
}

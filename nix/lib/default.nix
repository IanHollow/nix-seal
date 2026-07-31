{ lib }: {
  schemaVersion = "nix-seal.plan.v1";
  schema = ../../schemas/plan-v1.schema.json;

  # Nix values are public metadata only. Rust performs strict validation and
  # canonical hashing after this deterministic JSON representation is emitted.
  mkPlan =
    objects:
    builtins.toJSON (
      {
        schema = "nix-seal.plan.v1";
        identities = { };
        groups = { };
        targets = { };
        secrets = { };
        generators = { };
        templates = { };
        approvalPolicies = { };
        backends = { };
      }
      // objects
    );

  validId =
    value: builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null && !(lib.hasInfix ".." value);
}

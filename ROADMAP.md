# Roadmap

- Phase 0: repository foundation, specification, governance, Rust workspace,
  flake/modules, schema, CI, and release scaffolding. No secret migration.
- Phase 1: complete Nix/TOML frontends and selectors; age/plugin adapter;
  Ed25519/SSH DSSE approvals; signed manifests; official/differential vectors;
  property and fuzz foundations.
- Phase 2: administrator-to-target rekey, deterministic Nix bridge,
  transactional cache, verified activation/switch/rollback, systemd credentials,
  and full platform modules.
- Phase 3: authoring and lifecycle commands, identity/value rotation,
  generators, prompts, templates, and provisioning phases.
- Phase 4: dry-run migration adapters and side-by-side dogfooding in nix-conf,
  starting with a synthetic low-risk secret.
- Phase 5: attack-path review, sustained fuzz/mutation/platform/performance
  work, release candidate, independent audit and remediation, then 1.0.

Post-1.0 candidates include remote provider SDK/daemon, Vault and cloud/password
manager providers, dynamic leases, SPIFFE, reviewed threshold decryption,
attested TPM-bound delivery, and organization-wide tamper-evident audit.

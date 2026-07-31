# ADR 0007: Deterministic target policy projection

Status: accepted; initial plan/rekey/activation enforcement implemented

`plan.v1` is the sole public policy authority. For each target, the policy crate
deterministically resolves nested target groups and emits a canonical
`nix-seal.target-policy.v1` projection containing the selected target recipient,
authorized secrets, delivery modes, phases, per-secret approval policies,
runtime permissions and service actions, and templates whose complete secret
dependency set is authorized. Both the full plan and projection use canonical
JSON and domain-separated BLAKE3 hashes.

Group traversal is iterative and bounded. Cycles, missing members, duplicate
signers, invalid thresholds, missing default signers, and unresolved identities
fail plan validation. Target template inclusion is fail-closed: a template is
available only when every placeholder secret is authorized for that target.

Rekey accepts the compiled plan, target ID, and secret ID. It derives the source
path, delivery mode, target recipient, plan hash, target-policy hash, and allowed
approval signers instead of accepting those values independently. Artifact v2
signatures bind both hashes. Activation likewise derives the recipient and
approval rules from the plan, requires the configured private identity to match,
and requires the complete artifact/template/runtime/service declaration to equal
the projection before creating any plaintext transaction.

This deliberately duplicates some public policy inside the activation document
only as materialization instructions; those fields have no authority and must
exactly match the projection. The plan and target ID remain public and may enter
the Nix store. Plaintext and private identities remain out of the store.

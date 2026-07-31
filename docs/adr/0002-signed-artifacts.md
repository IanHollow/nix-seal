# ADR 0002: Signed target artifacts

Status: accepted; Ed25519 envelope foundation implemented

Use a DSSE/in-toto-style canonical envelope and Ed25519/SSH signing. Bind plan
and source hashes, target/secret/recipient, generation, and versions. Signing
keys are separate from decryption keys. Default policy requires one trusted
signature and supports N-of-M distinct signers. This authenticates the artifact,
not repository or deployment authorization.

The artifact v1 payload uses RFC 8785 canonical JSON inside the DSSE pre-
authentication encoding. Verification is fail-closed: the caller supplies the
expected plan, source and artifact hashes, target, secret, recipient, generation,
tool version, and time. Unknown and duplicate signers, non-canonical payloads,
expired/future envelopes, threshold failures, and any binding mismatch are
rejected before decryption. Ed25519 is isolated in `nix-seal-manifest`; SSH
signing remains pending.

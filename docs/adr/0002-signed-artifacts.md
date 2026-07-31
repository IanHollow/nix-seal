# ADR 0002: Signed target artifacts

Status: accepted; implementation pending

Use a DSSE/in-toto-style canonical envelope and Ed25519/SSH signing. Bind plan
and source hashes, target/secret/recipient, generation, and versions. Signing
keys are separate from decryption keys. Default policy requires one trusted
signature and supports N-of-M distinct signers. This authenticates the artifact,
not repository or deployment authorization.

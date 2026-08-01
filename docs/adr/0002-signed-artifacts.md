# ADR 0002: Signed target artifacts

Status: accepted; native Ed25519 and OpenSSH Ed25519 signing implemented

Use a DSSE/in-toto-style canonical envelope and Ed25519/SSH signing. Bind plan
and source hashes, target/secret/recipient, generation, and versions. Signing
keys are separate from decryption keys. Default policy requires one trusted
signature and supports N-of-M distinct signers. This authenticates the artifact,
not repository or deployment authorization.

The artifact v2 payload uses RFC 8785 canonical JSON inside the DSSE pre-
authentication encoding. Verification is fail-closed: the caller supplies the
expected plan and target-policy hashes, source and artifact hashes, target,
secret, recipient, generation, tool version, and time. The target-policy hash
binds the artifact to the exact plan-derived recipient, authorized secret set,
per-secret approval policy, runtime permissions, templates, and service actions.
Unknown and duplicate signers, non-canonical payloads, expired/future envelopes,
threshold failures, and any binding mismatch are rejected before decryption. The
native `nix-seal-ed25519-v1` key format remains the default. The manifest crate
also accepts standard unencrypted OpenSSH `ssh-ed25519` private keys and public
keys. Those approvals are encoded as standard OpenSSH `sshsig` PEM under the
fixed `nix-seal-artifact-v2` namespace over the same DSSE pre-authenticated
bytes. The envelope records its signature format, so a native Ed25519 signature
can never be interpreted as an SSH signature (or vice versa). SSH public-key
comments do not affect the approval key ID or authorization comparison. Plan
validation rejects comment-only duplicates before approval thresholds are
calculated, so one OpenSSH key cannot inflate an N-of-M policy.

This is deliberately software-key compatibility only. The client does not invoke
`ssh-keygen`, `ssh-agent`, FIDO/U2F, PKCS#11, or an arbitrary helper; it accepts
neither SSH RSA nor ECDSA signing keys. Encrypted OpenSSH private keys are
rejected because background signing never prompts. Hardware and agent signing
require a separate protocol, descriptor, timeout, and user-presence ADR before
they can be enabled. `ssh-key 0.6.7` is pinned with only its `alloc` and
`ed25519` features, and is covered by the committed cargo-vet policy.

# ADR 0002: Signed target artifacts

Status: accepted; native Ed25519, OpenSSH Ed25519, and explicit SSH-agent
Ed25519 signing implemented

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

The client does not invoke `ssh-keygen` or an arbitrary helper. A signer may
explicitly delegate an Ed25519 operation to the local agent by placing
`NIX-SEAL-SSH-AGENT-ED25519-v1:<openssh-public-key>` in the selected signing-key
file. `SSH_AUTH_SOCK` is read only for that explicit format; the socket path
must be absolute, the request is the standard SSH-agent sign request with zero
flags, and reads/writes are bounded and capped at ten seconds. The response is
accepted only when it is an Ed25519 signature for the exact requested key and is
wrapped in the same `sshsig` namespace as file-backed SSH signing. The agent key
file contains public metadata only, and an agent failure never falls back to
another key or an interactive prompt. This supports compatible agents, including
agents fronting ordinary Ed25519 hardware keys, while FIDO/U2F security-key
algorithms, PKCS#11, SSH RSA/ECDSA, encrypted OpenSSH private keys, and agent
prompt flows remain rejected pending separate reviewed protocols.
`ssh-key 0.6.7` is pinned with only its `alloc` and `ed25519` features, and is
covered by the committed cargo-vet policy.

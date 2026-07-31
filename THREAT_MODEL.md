# Threat model

## Assets and trust boundaries

Assets are canonical plaintext, administrator and target identities, signing
keys, target artifacts, runtime generations, prompt input, and generator output.
Trust boundaries exist at Git review, administrator machines, age plugins and
agents, the ciphertext cache, Nix builders/binary caches, deployment transport,
target activation, generators/editors, and privileged service consumers.

Repository metadata and ciphertext are attacker-controlled input. Nix store and
binary caches are public. A target trusts only its configured plan root,
approval keys, and target identity. Repository authorization remains part of the
root of trust even when artifacts are signed.

## Adversaries

- Malicious repository contributors and substituted cache/transport objects.
- Compromised administrator workstations, decryption keys, or signing keys.
- Thieves possessing a target private key or historical Git checkout.
- Unprivileged local users racing or traversing runtime filesystem operations.
- Malicious plugins, agents, editors, generator executables, and migration
  tools.
- Supply-chain attackers affecting dependencies, CI, release identity, or Nix
  inputs.
- Attackers causing resource exhaustion, interrupted writes, concurrent races,
  malformed/oversized input, downgrade, replay, or partial activation.

## Required controls

Plans are strict, versioned, bounded, canonical, and signed by policy. Target
manifests bind all public security context. Crypto uses standard age behind an
adapter. Cache writes and activation use locks, private directories, same-device
atomic transactions, fsync, link/path checks, and fail-closed generation switch.
Plaintext is excluded from store, argv, ordinary environment, JSON, diagnostics,
logs, and CI. External processes receive a minimal environment, explicit file
descriptors, deadlines, output bounds, and the least required secret set.

Security tests cover traversal, symlink/hardlink/TOCTOU races, malformed crypto
and signatures, replay and target substitution, disk exhaustion, crashes,
concurrency, secret canaries, and denial-of-service bounds.

## Out of scope and unavoidable limits

- Root on a target can read that target's runtime plaintext.
- A compromised administrator identity exposes canonical ciphertext addressed to
  it; a compromised target identity exposes matching direct/historical objects.
- Re-encryption cannot make already-decrypted historical ciphertext secret
  again.
- Secure deletion is not guaranteed on SSDs or copy-on-write filesystems.
- Zeroization cannot prove every compiler/runtime copy disappeared.
- Static rotation cannot update an external service without a rotation provider.
- Availability under a fully compromised host/kernel is out of scope.

## Review cadence

Every cryptography, signing, manifest, activation, plugin, migration, or trust
root change updates this document and its ADR. Release candidates include an
attack-path review. The security team reviews the model at least once per minor
release and after every incident.

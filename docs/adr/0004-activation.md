# ADR 0004: Transactional activation

Status: accepted; authenticated generation foundation implemented

Verify all public bindings before decrypting. Materialize every secret/template
into a new private generation and atomically switch only on total success. Use
directory-relative no-follow exclusive operations, reject links and unsafe
parents/modes, and fsync state. Preserve the previous generation on failure and
reload/restart units only after switching. Prefer systemd credentials on NixOS.

The runtime implementation authenticates the complete artifact batch before it
creates a plaintext transaction. It holds no-follow regular ciphertext file
descriptors across hash/signature verification and bounded streaming age
decryption, rejects unsafe roots, sources, modes, and destination ancestry, and
serializes activation with a private no-follow lock. Each new generation is
fsynced and published under an immutable name before an atomic `current` symlink
switch. Authentication or decryption failure drops the transaction and leaves
the previous generation active.

Nix modules emit a strict `nix-seal.activation.v1` public document containing
only ciphertext paths, signed-envelope paths, hashes, target bindings, public
approval keys, and runtime policy. The target identity is configured as a string
runtime path and is never coerced to a Nix path or copied into the store. The
internal Rust `activate` command loads that identity with no-follow,
single-link, owner, and restrictive-mode checks. Runtime generation numbers are
allocated while the activation lock is held, avoiding collisions between
concurrent or repeated activations.

Runtime owner and group names are resolved before a plaintext transaction is
created. The runtime applies the resulting numeric IDs with descriptor-based
`fchown`, then reapplies the restrictive mode with descriptor-based `fchmod` so
ownership changes cannot clear the intended final permission bits or introduce a
path-resolution race.

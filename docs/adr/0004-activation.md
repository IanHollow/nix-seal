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

Each activation document carries one required phase. Its artifact and template
entries must match that phase, and a template can reference only secret outputs
within the same phase. This gives every phase a separate lock, generation
directory, and `current` symlink. The ordinary `activation` phase retains the
historical runtime root; other phases receive a child root such as
`/run/nix-seal/users`. This avoids overwriting a previously activated early
generation while preventing a later phase from implicitly consuming it.

On NixOS, `users` runs after `specialfs` and is an explicit dependency of the
standard user-creation activation script, so its output must be `root:root`. The
normal `activation` phase runs after `users`; `services` runs after it.
`partitioning` is never scheduled by the generic module because its correct
timing and transport depend on the installer. It remains an explicit public
activation spec to be invoked only by reviewed installation orchestration.
nix-darwin and Home Manager reject non-normal phases until they have
platform-specific safe ordering contracts.

Nix modules emit a strict `nix-seal.activation.v2` public document containing a
canonical plan path, target ID, ciphertext/envelope paths, source hashes, and
runtime materialization metadata. Plan hash, target-policy hash, recipient, and
per-secret approval keys and thresholds are not separately configurable: the
Rust bridge deterministically derives them from the validated plan and rejects
any artifact set, permissions, template declaration, or service action that
differs from that target projection. The target identity is configured as a
string runtime path and is never coerced to a Nix path or copied into the store.
The internal Rust `activate` command loads that identity with no-follow,
single-link, owner, and restrictive-mode checks. Runtime generation numbers are
allocated while the activation lock is held, avoiding collisions between
concurrent or repeated activations.

Runtime owner and group names are resolved before a plaintext transaction is
created. The runtime applies the resulting numeric IDs with descriptor-based
`fchown`, then reapplies the restrictive mode with descriptor-based `fchmod` so
ownership changes cannot clear the intended final permission bits or introduce a
path-resolution race.

Before publishing, activation compares the complete candidate generation with
the active generation using bounded in-memory hashes plus owner, group, and mode
metadata. An identical candidate is discarded without generation churn. Platform
service actions are declared as bounded unit names and a fixed manager kind, run
through an absolute executable with a sanitized environment and a hard timeout,
and are attempted only after a changed generation has switched.

Before switching a changed generation, activation durably records a restrictive
pending-action marker bound to the generation and plan hash. It clears that
marker only after every action succeeds. A failed action therefore does not roll
back the already-atomic secret switch, but the next activation retries the
actions even when the plaintext generation is unchanged. The activation lock
remains held through the switch, action execution, and marker update so
concurrent activations cannot lose or duplicate the pending state. Removing
actions from a later plan clears a matching or stale marker without executing
it.

On systemd platforms, a secret may map its runtime path to one or more explicit
`(service unit, credential name)` pairs. The modules emit only
`LoadCredential=name:runtime-path`; plaintext remains outside the unit and Nix
store. A credential mapping automatically adds its service to the post-switch
restart set because systemd credentials are immutable for the lifetime of one
service activation. Duplicate names within a service are rejected across the
entire nix-seal configuration. System-service mappings on NixOS default to
`PrivateMounts=true`, following systemd's recommendation that credential users
receive a private mount namespace. Linux Home Manager uses the corresponding
user-service setting. Darwin and macOS Home Manager reject credential mappings
because launchd has no equivalent contract.

Public runtime templates use the reserved placeholder grammar
`{{nix-seal:name}}`. Placeholder names and their source secret IDs are declared
separately in the activation document; missing, unused, malformed, or undeclared
reserved placeholders reject the complete transaction. A placeholder must select
an explicit `utf8`, padded RFC 4648 `base64`, or lowercase `hex` transform.
UTF-8 validation and all transforms stream from the already-decrypted private
candidate files through zeroizing bounded buffers. Template sources are public,
opened as no-follow single-link regular files, and bounded to 2 MiB; rendered
output is bounded to 128 MiB. Rendered files are created exclusively inside the
candidate generation with the same ownership, mode, fsync, equality comparison,
atomic switch, rollback preservation, and post-switch service semantics as
direct secret outputs.

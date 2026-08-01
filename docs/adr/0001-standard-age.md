# ADR 0001: Standard age ciphertext

Status: accepted

Use standard age files and recipient/plugin protocols. Isolate exactly pinned
Rust `age` behind `nix-seal-crypto`; never invent a container or primitive.
Upgrades require advisory/license review, official vector tests, and
differential compatibility with reference `age` and `rage`. PGP is
migration-only.

Native X25519 recipients are the default. OpenSSH Ed25519 and RSA recipients are
accepted only to migrate established deployments. Their parser is contained
inside the adapter, OpenSSH comments are excluded from policy comparison, and
encrypted private keys are rejected by non-interactive commands. New
configuration must prefer native age or reviewed hardware-backed age plugins.

The Nix package check requires bidirectional X25519 round trips with the
reference `age` executable and `rage`. These command-line tools are test-only
inputs and never shipped or invoked by the nix-seal runtime. This differential
check complements the pinned C2SP/CCTV vector suite. The test harness runs all
supported unarmored, uncompressed X25519 and parser cases, including expected
rejection and partial-payload behavior. It skips passphrase, armor, and hybrid
recipient vectors only until their corresponding native adapter capabilities are
implemented.

The adapter additionally performs a bounded structural preflight before passing
the ciphertext to `age`. This keeps malformed recipient-stanza cases rejected
even where the pinned pre-1.0 adapter defers validation until identity
resolution, while preserving standard SSH and GREASE stanza behavior.

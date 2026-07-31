# Contributing

Discuss substantial design changes before implementation and add an ADR for any
change to cryptography, signatures, manifests, cache/store trust, activation,
plugins, or migration. Changes must include tests, user-facing documentation,
and threat-model updates when trust boundaries move.

All commits require Developer Certificate of Origin sign-off:

```console
git commit -s
```

Run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `nix flake check`. Never put real secrets, private
identities, prompt answers, or plaintext test fixtures in commits or CI.

Security-critical code requires CODEOWNER review. Dependencies are reviewed one
at a time; lockfile updates must explain security and compatibility impact.

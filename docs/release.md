# Release controls

Version tags matching `v*.*.*` run the release workflow. The workflow builds the
Nix package natively on x86_64 Linux, aarch64 Linux, and aarch64 macOS, then
publishes the executable, CycloneDX SBOM, SHA-256 checksums, and build metadata
only after a protected `release` environment approval.

The publish job uses GitHub's OIDC-backed build-attestation action. It does not
use a long-lived signing key or package-registry credential. Repository
administrators must configure the `release` environment with the required
reviewers and keep tag creation protected. A 1.0 tag additionally requires the
independent security audit and all gates in [`SPEC.md`](../SPEC.md); those human
assurance gates are intentionally not replaced by CI automation.

The current Nix package set deliberately omits x86_64-darwin until a supported
nixpkgs/runners combination is available. The platform contract and release
matrix must be expanded when that limitation is removed.

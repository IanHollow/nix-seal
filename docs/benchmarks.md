# Benchmark protocol

`nix-seal-policy` contains a standalone scale benchmark at
`crates/nix-seal-policy/benches/scale.rs`. It exercises the public policy
validator, RFC 8785 plan canonicalization, one target-policy projection, and
streaming age encryption for 1, 100, 1,000, and 10,000 synthetic secrets and
targets. The benchmark is bounded by the same 10,000-object and 64 MiB limits
used by the product. It never prints or writes plaintext.

Run the complete suite with:

```console
cargo bench -p nix-seal-policy --bench scale --locked
```

To measure one case, pass `-- --size=1000`. Each output line is a versioned
`nix-seal.benchmark.v1` JSON object. It includes the object counts, canonical
public-plan sizes, operation timings, operating system, architecture, and
crate version. Times are wall-clock milliseconds and are not portable latency
claims. Compare runs only when recording the runner image, CPU model, memory,
Rust toolchain, and repository commit alongside the JSON output.

The CI benchmark job publishes the raw JSONL and runner metadata as an artifact
for every push and pull request. Release notes must link the artifact and state
the hardware and toolchain before making a performance claim. A statistically
significant regression threshold is a release-policy decision; no threshold is
silently encoded in this smoke benchmark.

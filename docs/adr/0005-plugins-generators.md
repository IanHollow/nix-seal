# ADR 0005: Plugins and generators

Status: accepted; plugin client pending, unsupported plugin identities rejected

Age identities use the standard plugin protocol. Generators are built-in Rust or
direct declared executables from Nix packages; no shell evaluation. Processes
receive a sanitized environment, explicit descriptors and secret dependencies,
private workspace, time/output bounds, and network isolation when enforceable.
Plugin errors are redacted and unrelated descriptors are closed.

Until the sandboxed client can enforce those invariants, any `plugin` identity
causes plan validation to fail. This avoids accepting a policy whose recipients
cannot be executed through the Rust adapter. Native age and OpenSSH migration
recipients remain available; enabling a plugin is a reviewed future capability,
not a silent fallback.

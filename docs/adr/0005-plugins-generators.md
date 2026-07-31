# ADR 0005: Plugins and generators

Status: accepted; implementation pending

Age identities use the standard plugin protocol. Generators are built-in Rust or
direct declared executables from Nix packages; no shell evaluation. Processes
receive a sanitized environment, explicit descriptors and secret dependencies,
private workspace, time/output bounds, and network isolation when enforceable.
Plugin errors are redacted and unrelated descriptors are closed.

# ADR 0005: Plugins and generators

Status: accepted; plugin client pending, unsupported plugin identities rejected

Age identities use the standard plugin protocol. Generators are built-in Rust or
direct declared executables from Nix packages; no shell evaluation. Processes
receive a sanitized environment, explicit descriptors and secret dependencies,
private workspace, time/output bounds, and network isolation when enforceable.
On Unix, nix-seal places generators and migration helpers in a dedicated process
group so timeout and failure cleanup terminates descendants that could otherwise
retain access to staged plaintext; other platforms retain direct child
termination as their portable fallback. External generators receive each
explicitly declared canonical secret dependency as one numbered `0600` file
beneath a private `NIX_SEAL_SECRET_DIR`; no dependency value is passed through
arguments, an ordinary environment value, or the Nix store. Built-ins reject
secret dependencies. The CLI checks canonical recipient authorization before
streaming any dependency into that workspace. Plugin errors are redacted and
unrelated descriptors are closed.

Until the sandboxed client can enforce those invariants, any `plugin` identity
causes plan validation to fail. This avoids accepting a policy whose recipients
cannot be executed through the Rust adapter. Native age and OpenSSH migration
recipients remain available; enabling a plugin is a reviewed future capability,
not a silent fallback.

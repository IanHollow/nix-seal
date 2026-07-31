# ADR 0004: Transactional activation

Status: accepted; partial implementation

Verify all public bindings before decrypting. Materialize every secret/template
into a new private generation and atomically switch only on total success. Use
directory-relative no-follow exclusive operations, reject links and unsafe
parents/modes, and fsync state. Preserve the previous generation on failure and
reload/restart units only after switching. Prefer systemd credentials on NixOS.

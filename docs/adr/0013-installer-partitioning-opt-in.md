# ADR 0013: Installer-only partitioning activation

Status: accepted; implemented

Partitioning secrets may be needed before a target filesystem, account database,
or normal service manager exists. A generic NixOS, nix-darwin, or Home Manager
activation hook cannot safely infer that lifecycle point, so partitioning must
not be scheduled by a normal system rebuild.

The NixOS module therefore rejects a configured `partitioning` phase by default.
An installer configuration may set `nixSeal.installerMode = true`; this is an
explicit review boundary, not a privilege escalation. The module then emits the
strict public `activationSpecs.partitioning` document and no activation script
for that phase. Installer orchestration is responsible for transporting the
public document and ciphertext-only artifacts over a protected channel and for
placing the target identity in an out-of-store protected path before invoking
the internal `nix-seal activate` entrypoint.

Installer mode emits a warning and remains opt-in on every configuration. The
runtime still performs the same plan, manifest, recipient, target-binding,
filesystem, and atomic-generation checks as ordinary activation. No plaintext
enters Nix evaluation, the Nix store, command arguments, or logs.

self:
{ config, lib, ... }:
let
  credentialId = value: builtins.head (lib.splitString ":" (toString value));
  groupCredentials = lib.foldl' (
    grouped: binding:
    let
      unit = lib.removeSuffix ".service" binding.unit;
    in
    grouped // { ${unit} = (grouped.${unit} or [ ]) ++ [ "${binding.name}:${binding.path}" ]; }
  ) { };
in
{
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "/run/nix-seal";
      serviceManager = "systemd-system";
      serviceExecutable = "/run/current-system/sw/bin/systemctl";
      supportsServiceCredentials = true;
      homeManagerRuntimeIdentity = false;
      serviceCredentialConfig =
        bindings:
        let
          grouped = groupCredentials bindings;
        in
        {
          systemd.services = lib.mapAttrs (_: credentials: {
            serviceConfig = {
              LoadCredential = lib.mkAfter credentials;
              PrivateMounts = lib.mkDefault true;
            };
          }) grouped;
          assertions = lib.mapAttrsToList (unit: credentials: {
            assertion =
              let
                expectedNames = map credentialId credentials;
                configuredNames = map credentialId (
                  lib.toList config.systemd.services.${unit}.serviceConfig.LoadCredential
                );
              in
              lib.all (name: lib.count (configured: configured == name) configuredNames == 1) expectedNames;
            message = "systemd service ${unit}.service has a LoadCredential name that conflicts with nixSeal";
          }) grouped;
        };
    })
  ];
  config = lib.mkIf config.nixSeal.enable {
    system.activationScripts.nixSeal = {
      deps = [ ];
      text = ''
        ${lib.getExe config.nixSeal.package} activate \
          --spec ${config.nixSeal.activationSpec} \
          --identity ${lib.escapeShellArg config.nixSeal.identityFile}
      '';
    };
  };
}

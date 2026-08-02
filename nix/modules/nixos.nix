self:
{ config, lib, ... }:
let
  cfg = config.nixSeal;
  credentialId = value: builtins.head (lib.splitString ":" (toString value));
  groupCredentials = lib.foldl' (
    grouped: binding:
    let
      unit = lib.removeSuffix ".service" binding.unit;
    in
    grouped // { ${unit} = (grouped.${unit} or [ ]) ++ [ "${binding.name}:${binding.path}" ]; }
  ) { };
  activate = spec: ''
    ${lib.getExe cfg.package} activate \
      --spec ${spec} \
      --identity ${lib.escapeShellArg cfg.identityFile}
  '';
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
  options.nixSeal.installerMode = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Explicitly enable installer-only partitioning activation-spec
      generation. This does not schedule an activation script; reviewed
      installer orchestration must transport the public spec and ciphertext
      artifacts over its protected channel and invoke `nix-seal activate`
      with an out-of-store target identity.
    '';
  };
  config = lib.mkIf cfg.enable {
    warnings = lib.optional cfg.installerMode ''
      nixSeal installer mode is active: partitioning is not scheduled by the
      normal NixOS activation graph. Invoke the generated activation spec only
      from reviewed installer orchestration over a protected channel.'';
    assertions = [
      {
        assertion = !(cfg.activationSpecs ? partitioning) || cfg.installerMode;
        message = "nixSeal partitioning-phase secrets require explicit nixSeal.installerMode=true; the module never schedules partitioning activation automatically";
      }
      {
        assertion =
          !(cfg.activationSpecs ? users)
          || lib.all (secret: secret.owner == "root" && secret.group == "root") (
            builtins.attrValues (lib.filterAttrs (_: secret: secret.phase == "users") cfg.secrets)
          );
        message = "nixSeal users-phase secrets must be owned by root:root until user accounts exist";
      }
      {
        assertion =
          !(cfg.activationSpecs ? users)
          || lib.all (template: template.owner == "root" && template.group == "root") (
            builtins.attrValues (lib.filterAttrs (_: template: template.phase == "users") cfg.templates)
          );
        message = "nixSeal users-phase templates must be owned by root:root until user accounts exist";
      }
    ];
    system.activationScripts = lib.mkMerge [
      (lib.mkIf (cfg.activationSpecs ? users) {
        users.deps = lib.mkAfter [ "nixSealUsers" ];
        nixSealUsers = {
          deps = [ "specialfs" ];
          text = activate cfg.activationSpecs.users;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? activation) {
        nixSeal = {
          deps = [ "users" ];
          text = activate cfg.activationSpecs.activation;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? services) {
        nixSealServices = {
          deps = if cfg.activationSpecs ? activation then [ "nixSeal" ] else [ "users" ];
          text = activate cfg.activationSpecs.services;
        };
      })
    ];
  };
}

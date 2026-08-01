self:
{ config, lib, ... }:
let
  cfg = config.nixSeal;
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
      runtimeDirectory = "/var/run/nix-seal";
      serviceManager = "launchd-system";
      serviceExecutable = "/bin/launchctl";
      supportsServiceCredentials = false;
      serviceCredentialConfig = _: { };
      homeManagerRuntimeIdentity = false;
    })
  ];
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.activationSpecs ? partitioning);
        message = "nixSeal partitioning-phase secrets require installer provisioning and cannot run in nix-darwin activation";
      }
      {
        assertion =
          !(cfg.activationSpecs ? users)
          || lib.all (secret: secret.owner == "root" && secret.group == "root") (
            builtins.attrValues (lib.filterAttrs (_: secret: secret.phase == "users") cfg.secrets)
          );
        message = "nixSeal users-phase secrets must be owned by root:root until macOS accounts exist";
      }
      {
        assertion =
          !(cfg.activationSpecs ? users)
          || lib.all (template: template.owner == "root" && template.group == "root") (
            builtins.attrValues (lib.filterAttrs (_: template: template.phase == "users") cfg.templates)
          );
        message = "nixSeal users-phase templates must be owned by root:root until macOS accounts exist";
      }
    ];
    system.activationScripts.extraActivation.text = lib.mkIf (cfg.activationSpecs ? users) (
      lib.mkAfter (activate cfg.activationSpecs.users)
    );
    system.activationScripts.postActivation.text = lib.mkAfter (
      lib.optionalString (cfg.activationSpecs ? activation) (activate cfg.activationSpecs.activation)
      + lib.optionalString (cfg.activationSpecs ? services) (activate cfg.activationSpecs.services)
    );
    warnings = [ "macOS runtime storage may not be memory-backed; inspect the selected volume" ];
  };
}

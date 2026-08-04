self:
{ config, lib, ... }:
let
  cfg = config.nixSeal;
  embeddedHomeManagerUsers =
    if builtins.hasAttr "home-manager" config then
      builtins.attrNames (config."home-manager".users or { })
    else
      [ ];
  bootPhases = [
    "users"
    "activation"
    "services"
  ];
  runtimeArguments =
    command:
    [
      (lib.getExe cfg.package)
      "__darwin-runtime"
      command
      "--root"
      cfg.darwin.volatileRuntime.root
      "--size"
      cfg.darwin.volatileRuntime.size
    ]
    ++ lib.concatMap (user: [
      "--user"
      user
    ]) embeddedHomeManagerUsers;
  prepareArguments = runtimeArguments "prepare";
  prepare = lib.escapeShellArgs prepareArguments;
  activateArguments =
    spec:
    if cfg.darwin.volatileRuntime.enable then
      runtimeArguments "activate"
      ++ [
        "--spec"
        (toString spec)
        "--identity"
        cfg.identityFile
      ]
    else
      [
        (lib.getExe cfg.package)
        "activate"
        "--spec"
        (toString spec)
        "--identity"
        cfg.identityFile
      ];
  activate = spec: lib.escapeShellArgs (activateArguments spec);
in
{
  imports = [
    ((import ./shared.nix) {
      inherit self;
      targetKind = "darwin";
      runtimeDirectory = "/var/run/nix-seal/system";
      serviceManager = "launchd-system";
      serviceExecutable = "/bin/launchctl";
      supportsServiceCredentials = false;
      serviceCredentialConfig = _: { };
      homeManagerRuntimeIdentity = false;
    })
  ];
  options.nixSeal.darwin.volatileRuntime = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Use a root-managed tmpfs for nix-seal plaintext runtime generations.";
    };
    root = lib.mkOption {
      type = lib.types.str;
      default = "/var/run/nix-seal";
      readOnly = true;
      description = "Fixed shared Darwin tmpfs mount root.";
    };
    size = lib.mkOption {
      type = lib.types.strMatching "[1-9][0-9]*[mMgG]";
      default = "256m";
      description = "Bounded total capacity of the Darwin nix-seal tmpfs.";
    };
  };
  config = lib.mkIf cfg.enable {
    nixSeal.runtimeStorage = lib.mkDefault (
      if cfg.darwin.volatileRuntime.enable then "volatile-tmpfs" else "persistent"
    );
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
    system.activationScripts = lib.mkMerge [
      (lib.mkIf cfg.darwin.volatileRuntime.enable {
        nixSealRuntime = {
          deps = [ "specialfs" ];
          text = prepare;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? users) {
        nixSealUsers = {
          deps = lib.optional cfg.darwin.volatileRuntime.enable "nixSealRuntime";
          text = activate cfg.activationSpecs.users;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? activation) {
        nixSeal = {
          deps = lib.optional cfg.darwin.volatileRuntime.enable "nixSealRuntime";
          text = activate cfg.activationSpecs.activation;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? services) {
        nixSealServices = {
          deps = lib.optional cfg.darwin.volatileRuntime.enable "nixSealRuntime";
          text = activate cfg.activationSpecs.services;
        };
      })
    ];
    launchd.daemons =
      lib.optionalAttrs cfg.darwin.volatileRuntime.enable {
        nix-seal-runtime.serviceConfig = {
          Label = "io.nix-seal.runtime";
          ProgramArguments = prepareArguments;
          RunAtLoad = true;
          ProcessType = "Background";
        };
      }
      // lib.listToAttrs (
        lib.concatMap (
          phase:
          lib.optional (builtins.hasAttr phase cfg.activationSpecs) {
            name = "nix-seal-${phase}";
            value.serviceConfig = {
              Label = "io.nix-seal.${phase}";
              ProgramArguments = activateArguments cfg.activationSpecs.${phase};
              RunAtLoad = true;
              ProcessType = "Background";
            };
          }
        ) bootPhases
      );
    warnings =
      lib.optional (!cfg.darwin.volatileRuntime.enable)
        "macOS nix-seal plaintext runtime is persistent; enable nixSeal.darwin.volatileRuntime for tmpfs storage";
  };
}

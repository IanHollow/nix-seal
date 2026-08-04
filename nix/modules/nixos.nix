self:
{ config, lib, ... }:
let
  cfg = config.nixSeal;
  embeddedHomeManagerUsers =
    if builtins.hasAttr "home-manager" config then
      builtins.attrNames (config."home-manager".users or { })
    else
      [ ];
  runtimeArguments =
    command:
    [
      (lib.getExe cfg.package)
      "__linux-runtime"
      command
      "--root"
      cfg.linux.volatileRuntime.root
    ]
    ++ lib.concatMap (user: [
      "--user"
      user
    ]) embeddedHomeManagerUsers;
  prepare = lib.escapeShellArgs (runtimeArguments "prepare");
  runtimeDeps = lib.optional cfg.linux.volatileRuntime.enable "nixSealRuntime";
  bootPhases = [
    "users"
    "activation"
    "services"
  ];
  bootActivationCommands = lib.concatMap (
    phase:
    lib.optional (builtins.hasAttr phase cfg.activationSpecs) "${lib.getExe cfg.package} activate --spec ${cfg.activationSpecs.${phase}} --identity ${lib.escapeShellArg cfg.identityFile}"
  ) bootPhases;
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
      targetKind = "nixOs";
      runtimeDirectory = "/run/nix-seal/system";
      runtimeStorage = "volatile-tmpfs-noswap";
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
            after = [ "nix-seal-activate.service" ];
            requires = [ "nix-seal-activate.service" ];
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
  options.nixSeal.linux.volatileRuntime = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Use a root-managed noswap tmpfs for nix-seal plaintext runtime generations.";
    };
    root = lib.mkOption {
      type = lib.types.str;
      default = "/run/nix-seal";
      readOnly = true;
      description = "Fixed shared Linux tmpfs mount root.";
    };
    size = lib.mkOption {
      type = lib.types.strMatching "[1-9][0-9]*[mMgG]";
      default = "256m";
      description = "Bounded total capacity of the Linux nix-seal tmpfs.";
    };
  };
  config = lib.mkIf cfg.enable {
    nixSeal.runtimeStorage = lib.mkDefault (
      if cfg.linux.volatileRuntime.enable then "volatile-tmpfs-noswap" else "persistent"
    );
    fileSystems.${cfg.linux.volatileRuntime.root} = lib.mkIf cfg.linux.volatileRuntime.enable {
      device = "tmpfs";
      fsType = "tmpfs";
      options = [
        # The mount root must be traversable by embedded Home Manager users;
        # its system and per-user children remain private 0700 directories.
        "mode=0711"
        "size=${cfg.linux.volatileRuntime.size}"
        "nosuid"
        "nodev"
        "noexec"
        "noswap"
      ];
    };
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
      (lib.mkIf cfg.linux.volatileRuntime.enable {
        nixSealRuntime = {
          deps = [ "specialfs" ];
          text = prepare;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? users) {
        users.deps = lib.mkAfter [ "nixSealUsers" ];
        nixSealUsers = {
          deps = [ "specialfs" ] ++ runtimeDeps;
          text = activate cfg.activationSpecs.users;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? activation) {
        nixSeal = {
          deps = [ "users" ] ++ runtimeDeps;
          text = activate cfg.activationSpecs.activation;
        };
      })
      (lib.mkIf (cfg.activationSpecs ? services) {
        nixSealServices = {
          deps = (if cfg.activationSpecs ? activation then [ "nixSeal" ] else [ "users" ]) ++ runtimeDeps;
          text = activate cfg.activationSpecs.services;
        };
      })
    ];
    systemd.services.nix-seal-runtime = lib.mkIf cfg.linux.volatileRuntime.enable {
      description = "Prepare nix-seal Linux volatile runtime";
      wantedBy = [ "multi-user.target" ];
      before = [ "nix-seal-activate.service" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        UMask = "0077";
        ExecStart = prepare;
      };
    };
    systemd.services.nix-seal-activate = {
      description = "Materialize nix-seal runtime generation";
      wantedBy = [ "multi-user.target" ];
      before = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      requires = lib.optional cfg.linux.volatileRuntime.enable "nix-seal-runtime.service";
      wants = lib.optional cfg.linux.volatileRuntime.enable "nix-seal-runtime.service";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        UMask = "0077";
        RequiresMountsFor = lib.optional cfg.linux.volatileRuntime.enable cfg.linux.volatileRuntime.root;
        ExecStart = bootActivationCommands;
      };
    };
  };
}

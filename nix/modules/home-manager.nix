self:
{
  config,
  lib,
  osConfig ? null,
  pkgs,
  ...
}:
let
  cfg = config.nixSeal;
  integratedLinuxVolatile =
    pkgs.stdenv.hostPlatform.isLinux
    && osConfig != null
    && (osConfig.nixSeal.enable or false)
    && (osConfig.nixSeal.linux.volatileRuntime.enable or false);
  integratedDarwinVolatile =
    pkgs.stdenv.hostPlatform.isDarwin
    && osConfig != null
    && (osConfig.nixSeal.enable or false)
    && (osConfig.nixSeal.darwin.volatileRuntime.enable or false);
  linuxRuntimeRoot = "/run/nix-seal/users/${config.home.username}";
  darwinRuntimeRoot = "/var/run/nix-seal/users/${config.home.username}";
  cleanupLegacyDarwinRuntime = lib.optionalString integratedDarwinVolatile ''
    ${lib.getExe cfg.package} __darwin-runtime cleanup-persistent \
      --root ${lib.escapeShellArg "${config.home.homeDirectory}/Library/Caches/nix-seal"}
  '';
  bootPhases = [
    "users"
    "activation"
    "services"
  ];
  credentialId = value: builtins.head (lib.splitString ":" (toString value));
  groupCredentials = lib.foldl' (
    grouped: binding:
    let
      unit = lib.removeSuffix ".service" binding.unit;
    in
    grouped // { ${unit} = (grouped.${unit} or [ ]) ++ [ "${binding.name}:${binding.path}" ]; }
  ) { };
  activate =
    phase: spec:
    let
      runtimeSuffix = if phase == "activation" then "" else "/${phase}";
      runtimeRoot =
        if integratedLinuxVolatile then
          lib.escapeShellArg "${linuxRuntimeRoot}${runtimeSuffix}"
        else if pkgs.stdenv.hostPlatform.isLinux then
          ''"$XDG_RUNTIME_DIR/nix-seal${runtimeSuffix}"''
        else if integratedDarwinVolatile then
          lib.escapeShellArg "${darwinRuntimeRoot}${runtimeSuffix}"
        else
          lib.escapeShellArg "${config.home.homeDirectory}/Library/Caches/nix-seal${runtimeSuffix}";
    in
    ''
      ${lib.optionalString (pkgs.stdenv.hostPlatform.isLinux && !integratedLinuxVolatile) ''
        if [ -z "''${XDG_RUNTIME_DIR:-}" ]; then
          echo "nix-seal: XDG_RUNTIME_DIR is required for Linux Home Manager activation" >&2
          exit 1
        fi
      ''}
      ${lib.getExe cfg.package} activate \
        --spec ${spec} \
        --identity ${lib.escapeShellArg cfg.identityFile} \
        --runtime-root ${runtimeRoot}
      ${cleanupLegacyDarwinRuntime}
    '';
  runtimeRootFor =
    phase:
    let
      runtimeSuffix = if phase == "activation" then "" else "/${phase}";
    in
    if integratedLinuxVolatile then
      "${linuxRuntimeRoot}${runtimeSuffix}"
    else if pkgs.stdenv.hostPlatform.isLinux then
      "%t/nix-seal${runtimeSuffix}"
    else if integratedDarwinVolatile then
      "${darwinRuntimeRoot}${runtimeSuffix}"
    else
      "${config.home.homeDirectory}/Library/Caches/nix-seal${runtimeSuffix}";
  persistentActivationArguments = phase: [
    (lib.getExe cfg.package)
    "activate"
    "--spec"
    (toString cfg.activationSpecs.${phase})
    "--identity"
    cfg.identityFile
    "--runtime-root"
    (runtimeRootFor phase)
  ];
in
{
  imports = [
    ((import ./shared.nix) {
      inherit self;
      targetKind = "homeManager";
      runtimeDirectory =
        if integratedLinuxVolatile then
          linuxRuntimeRoot
        else if pkgs.stdenv.hostPlatform.isLinux then
          "%t/nix-seal"
        else if integratedDarwinVolatile then
          darwinRuntimeRoot
        else
          "${config.home.homeDirectory}/Library/Caches/nix-seal";
      runtimeStorage =
        if integratedLinuxVolatile then
          "volatile-tmpfs-noswap"
        else if integratedDarwinVolatile then
          "volatile-tmpfs"
        else
          "persistent";
      serviceManager = if pkgs.stdenv.hostPlatform.isLinux then "systemd-user" else "launchd-user";
      serviceExecutable =
        if pkgs.stdenv.hostPlatform.isLinux then "${pkgs.systemd}/bin/systemctl" else "/bin/launchctl";
      supportsServiceCredentials = true;
      homeManagerRuntimeIdentity = true;
      serviceCredentialConfig = bindings: {
        systemd.user.services = lib.mapAttrs (_: credentials: {
          Service.LoadCredential = lib.mkAfter credentials;
        }) (groupCredentials bindings);
        assertions = lib.mapAttrsToList (unit: credentials: {
          assertion =
            let
              expectedNames = map credentialId credentials;
              configuredNames = map credentialId (
                lib.toList config.systemd.user.services.${unit}.Service.LoadCredential
              );
            in
            lib.all (name: lib.count (configured: configured == name) configuredNames == 1) expectedNames;
          message = "systemd user service ${unit}.service has a LoadCredential name that conflicts with nixSeal";
        }) (groupCredentials bindings);
      };
    })
  ];
  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          pkgs.stdenv.hostPlatform.isLinux
          || lib.all (secret: secret.serviceCredentials == [ ]) (builtins.attrValues config.nixSeal.secrets);
        message = "Home Manager nixSeal serviceCredentials require Linux systemd user services";
      }
      {
        assertion = !(cfg.activationSpecs ? partitioning);
        message = "nixSeal partitioning-phase secrets require installer provisioning and cannot run in Home Manager";
      }
    ];
    home.activation = lib.mkMerge [
      (lib.mkIf (cfg.activationSpecs ? users) {
        nixSealUsers = lib.hm.dag.entryAfter [ "writeBoundary" ] (
          activate "users" cfg.activationSpecs.users
        );
      })
      (lib.mkIf (cfg.activationSpecs ? activation) {
        nixSeal = lib.hm.dag.entryAfter (
          if cfg.activationSpecs ? users then [ "nixSealUsers" ] else [ "writeBoundary" ]
        ) (activate "activation" cfg.activationSpecs.activation);
      })
      (lib.mkIf (cfg.activationSpecs ? services) {
        nixSealServices = lib.hm.dag.entryAfter (
          if cfg.activationSpecs ? activation then
            [ "nixSeal" ]
          else if cfg.activationSpecs ? users then
            [ "nixSealUsers" ]
          else
            [ "writeBoundary" ]
        ) (activate "services" cfg.activationSpecs.services);
      })
    ];
    systemd.user.services = lib.mkIf pkgs.stdenv.hostPlatform.isLinux (
      lib.listToAttrs (
        lib.concatMap (
          phase:
          lib.optional (builtins.hasAttr phase cfg.activationSpecs) {
            name = "nix-seal-${phase}";
            value = {
              Unit = {
                Description = "Materialize nix-seal ${phase} generation";
                After = [ "default.target" ];
              };
              Service = {
                Type = "oneshot";
                RemainAfterExit = true;
                UMask = "0077";
                ExecStart = lib.concatStringsSep " " (persistentActivationArguments phase);
              };
              Install.WantedBy = [ "default.target" ];
            };
          }
        ) bootPhases
      )
    );
    launchd.agents = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin (
      lib.listToAttrs (
        lib.concatMap (
          phase:
          lib.optional (builtins.hasAttr phase cfg.activationSpecs) {
            name = "nix-seal-${phase}";
            value = {
              enable = true;
              domain = lib.mkDefault "user";
              config = {
                Label = "io.nix-seal.${phase}";
                ProgramArguments = persistentActivationArguments phase;
                RunAtLoad = true;
                ProcessType = "Background";
              };
            };
          }
        ) bootPhases
      )
    );
    warnings =
      lib.optional (pkgs.stdenv.hostPlatform.isDarwin && !integratedDarwinVolatile)
        "Home Manager stores runtime plaintext under ~/Library/Caches/nix-seal on macOS; this location is not guaranteed memory-backed";
  };
}

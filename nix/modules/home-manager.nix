self:
{
  config,
  lib,
  pkgs,
  ...
}:
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
  activate =
    phase: spec:
    let
      runtimeSuffix = if phase == "activation" then "" else "/${phase}";
      runtimeRoot =
        if pkgs.stdenv.hostPlatform.isLinux then
          ''"$XDG_RUNTIME_DIR/nix-seal${runtimeSuffix}"''
        else
          lib.escapeShellArg "${config.home.homeDirectory}/Library/Caches/nix-seal${runtimeSuffix}";
    in
    ''
      ${lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
        if [ -z "''${XDG_RUNTIME_DIR:-}" ]; then
          echo "nix-seal: XDG_RUNTIME_DIR is required for Linux Home Manager activation" >&2
          exit 1
        fi
      ''}
      ${lib.getExe cfg.package} activate \
        --spec ${spec} \
        --identity ${lib.escapeShellArg cfg.identityFile} \
        --runtime-root ${runtimeRoot}
    '';
in
{
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory =
        if pkgs.stdenv.hostPlatform.isLinux then
          "%t/nix-seal"
        else
          "${config.home.homeDirectory}/Library/Caches/nix-seal";
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
    warnings = [
      (
        if pkgs.stdenv.hostPlatform.isLinux then
          "Home Manager stores runtime plaintext under XDG_RUNTIME_DIR"
        else
          "Home Manager stores runtime plaintext under ~/Library/Caches/nix-seal on macOS; this location is not guaranteed memory-backed"
      )
    ];
  };
}

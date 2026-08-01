self: { config, lib, ... }: {
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
  config = lib.mkIf config.nixSeal.enable {
    assertions = [
      {
        assertion = lib.all (secret: secret.phase == "activation") (
          builtins.attrValues config.nixSeal.secrets
        );
        message = "nixSeal activation phases other than activation are not yet scheduled on nix-darwin";
      }
      {
        assertion = lib.all (template: template.phase == "activation") (
          builtins.attrValues config.nixSeal.templates
        );
        message = "nixSeal template activation phases other than activation are not yet scheduled on nix-darwin";
      }
    ];
    system.activationScripts.postActivation.text = lib.mkAfter ''
      ${lib.getExe config.nixSeal.package} activate \
        --spec ${config.nixSeal.activationSpec} \
        --identity ${lib.escapeShellArg config.nixSeal.identityFile}
    '';
    warnings = [ "macOS runtime storage may not be memory-backed; inspect the selected volume" ];
  };
}

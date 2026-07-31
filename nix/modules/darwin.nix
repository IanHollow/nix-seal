self: { config, lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "/var/run/nix-seal";
    })
  ];
  config = lib.mkIf config.nixSeal.enable {
    system.activationScripts.postActivation.text = lib.mkAfter ''
      ${lib.getExe config.nixSeal.package} activate \
        --spec ${config.nixSeal.activationSpec} \
        --identity ${lib.escapeShellArg config.nixSeal.identityFile}
    '';
    warnings = [ "macOS runtime storage may not be memory-backed; inspect the selected volume" ];
  };
}

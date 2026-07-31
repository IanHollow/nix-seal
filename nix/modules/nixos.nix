self: { config, lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "/run/nix-seal";
      serviceManager = "systemd-system";
      serviceExecutable = "/run/current-system/sw/bin/systemctl";
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

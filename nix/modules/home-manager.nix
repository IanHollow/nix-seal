self: { config, lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "%t/nix-seal";
    })
  ];
  config.warnings = lib.optional config.nixSeal.enable "Home Manager expands %t to its platform runtime directory during activation";
}

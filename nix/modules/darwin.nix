self: { config, lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "/var/run/nix-seal";
    })
  ];
  config.warnings = lib.optional config.nixSeal.enable "macOS runtime storage may not be memory-backed; inspect the selected volume";
}

self: { lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "/run/nix-seal";
    })
  ];
  config = lib.mkIf false { };
}

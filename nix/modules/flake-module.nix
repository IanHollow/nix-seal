{inputs, ...}: {
  perSystem = {system, ...}: {
    packages.nix-seal = inputs.nix-seal.packages.${system}.nix-seal;
  };
}

{
  description = "Security-first secret management for Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    flake-parts.url = "github:hercules-ci/flake-parts";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix-darwin = {
      url = "github:nix-darwin/nix-darwin";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      eachSystem = lib.genAttrs (import inputs.systems);
      packageFor =
        system:
        let
          pkgs = inputs.nixpkgs.legacyPackages.${system};
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "nix-seal";
          version = "0.1.0-alpha.1";
          src = lib.cleanSource ./.;
          cargoLock.lockFile = ./Cargo.lock;
          buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
          cargoBuildFlags = [
            "--package"
            "nix-seal"
          ];
          cargoTestFlags = [ "--workspace" ];
          meta = {
            description = "Security-first secret management for Nix";
            homepage = "https://github.com/IanHollow/nix-seal";
            license = with lib.licenses; [
              mit
              asl20
            ];
            mainProgram = "nix-seal";
            platforms = lib.platforms.linux ++ lib.platforms.darwin;
          };
        };
    in
    {
      packages = eachSystem (system: {
        default = packageFor system;
        nix-seal = packageFor system;
      });
      apps = eachSystem (system: {
        default = {
          type = "app";
          program = "${packageFor system}/bin/nix-seal";
        };
        nix-seal = {
          type = "app";
          program = "${packageFor system}/bin/nix-seal";
        };
      });
      devShells = eachSystem (
        system:
        let
          pkgs = inputs.nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages =
              with pkgs;
              [
                cargo
                rustc
                rustfmt
                clippy
                cargo-deny
                cargo-audit
                nixfmt-rfc-style
              ]
              ++ lib.optionals stdenv.hostPlatform.isDarwin [ libiconv ];
          };
        }
      );
      checks = eachSystem (
        system:
        let
          pkgs = inputs.nixpkgs.legacyPackages.${system};
        in
        {
          inherit (inputs.self.packages.${system}) nix-seal;
        }
        // import ./nix/tests/module-evaluation.nix {
          inherit inputs system pkgs;
          inherit (inputs) self;
        }
      );
      nixosModules.default = import ./nix/modules/nixos.nix inputs.self;
      darwinModules.default = import ./nix/modules/darwin.nix inputs.self;
      homeManagerModules.default = import ./nix/modules/home-manager.nix inputs.self;
      flakeModules.default = import ./nix/modules/flake-module.nix;
      lib = import ./nix/lib { inherit lib; };
    };
}

{
  description = "Security-first secret management for Nix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    flake-parts.url = "github:hercules-ci/flake-parts";
    cctv = {
      url = "github:C2SP/CCTV";
      flake = false;
    };
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
      # nixpkgs unstable dropped x86_64-darwin in 26.11. Keep the architecture
      # in the platform contract, but do not publish broken outputs until a
      # supported runner/package-set combination exists again.
      supportedSystems = lib.filter (system: system != "x86_64-darwin") (import inputs.systems);
      eachSystem = lib.genAttrs supportedSystems;
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
          nativeCheckInputs = [
            pkgs.age
            pkgs.openssh
            pkgs.rage
          ];
          preCheck = ''
            export NIX_SEAL_REQUIRE_INTEROP=1
            export NIX_SEAL_REQUIRE_SSHSIG_INTEROP=1
            export NIX_SEAL_REQUIRE_CCTV=1
            export NIX_SEAL_CCTV_AGE_TESTDATA=${inputs.cctv}/age/testdata
          '';
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
      documentationFor =
        system:
        let
          pkgs = inputs.nixpkgs.legacyPackages.${system};
          nixSeal = packageFor system;
        in
        pkgs.runCommand "nix-seal-documentation-0.1.0-alpha.1"
          {
            nativeBuildInputs = [
              nixSeal
              pkgs.mandoc
            ];
          }
          ''
            mandoc -Tlint ${./docs/nix-seal.1}
            install -D -m 0644 ${./docs/nix-seal.1} "$out/share/man/man1/nix-seal.1"
            install -d -m 0755 "$out/share/nix-seal/schemas" "$out/share/nix-seal/completions"
            nix-seal schema --kind plan > "$out/share/nix-seal/schemas/plan-v2.json"
            nix-seal schema --kind target-policy > "$out/share/nix-seal/schemas/target-policy-v1.json"
            nix-seal schema --kind secret-recipients > "$out/share/nix-seal/schemas/secret-recipients-v1.json"
            nix-seal schema --kind activation > "$out/share/nix-seal/schemas/activation-v2.json"
            nix-seal schema --kind collection > "$out/share/nix-seal/schemas/collection-v1.json"
            nix-seal completions bash > "$out/share/nix-seal/completions/nix-seal.bash"
            nix-seal completions zsh > "$out/share/nix-seal/completions/_nix-seal"
            nix-seal completions fish > "$out/share/nix-seal/completions/nix-seal.fish"
            nix-seal completions nushell > "$out/share/nix-seal/completions/nix-seal.nu"
          '';
    in
    {
      packages = eachSystem (system: {
        default = packageFor system;
        nix-seal = packageFor system;
        documentation = documentationFor system;
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
                cargo-fuzz
                rustc
                rustfmt
                clippy
                cargo-deny
                cargo-audit
                cargo-vet
                age
                rage
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
          documentation = inputs.self.packages.${system}.documentation;
        }
        // import ./nix/tests/module-evaluation.nix {
          inherit inputs system pkgs;
          inherit (inputs) self;
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.isLinux && system == "x86_64-linux") {
          runtime-vm = import ./nix/tests/runtime-vm.nix {
            inherit system pkgs;
            inherit (inputs) self;
          };
        }
      );
      nixosModules.default = import ./nix/modules/nixos.nix inputs.self;
      darwinModules.default = import ./nix/modules/darwin.nix inputs.self;
      homeManagerModules.default = import ./nix/modules/home-manager.nix inputs.self;
      flakeModules.default = import ./nix/modules/flake-module.nix;
      lib = import ./nix/lib { inherit lib; };
    };
}

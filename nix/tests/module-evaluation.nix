{
  inputs,
  self,
  system,
  pkgs,
}:
let
  inherit (inputs.nixpkgs) lib;
  digest = character: builtins.concatStringsSep "" (lib.replicate 64 character);
  ciphertext = pkgs.writeText "nix-seal-test-artifact.age" "public ciphertext fixture";
  envelope = pkgs.writeText "nix-seal-test-envelope.json" "public envelope fixture";
  common = {
    nixSeal = {
      enable = true;
      targetId = "host.test";
      identityFile = "/run/keys/nix-seal-target";
      planHash = digest "0";
      recipientFingerprint = digest "1";
      trustedKeys = [ "nix-seal-ed25519-public-v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
      secrets."db/password" = {
        inherit ciphertext envelope;
        sourceCiphertextHash = digest "2";
      };
    };
  };
  nixos = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      { system.stateVersion = "26.05"; }
    ];
  };
  home = inputs.home-manager.lib.homeManagerConfiguration {
    inherit pkgs;
    modules = [
      self.homeManagerModules.default
      common
      {
        home = {
          username = "test";
          homeDirectory = "/home/test";
          stateVersion = "26.05";
        };
      }
    ];
  };
  checkDocument =
    name: spec: activationText:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '
        .schema == "nix-seal.activation.v1" and
        .targetId == "host.test" and
        .approvalThreshold == 1 and
        (.artifacts | length) == 1 and
        .artifacts[0].secretId == "db/password"
      ' ${spec} >/dev/null
      grep -F -- "--identity /run/keys/nix-seal-target" ${activationText} >/dev/null
      touch "$out"
    '';
  nixosActivation = pkgs.writeText "nix-seal-nixos-activation" nixos.config.system.activationScripts.nixSeal.text;
  homeActivation = pkgs.writeText "nix-seal-home-activation" home.config.home.activation.nixSeal.data;
in
{
  module-nixos =
    checkDocument "nix-seal-module-nixos" nixos.config.nixSeal.activationSpec
      nixosActivation;
  module-home-manager =
    checkDocument "nix-seal-module-home-manager" home.config.nixSeal.activationSpec
      homeActivation;
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin (
  let
    darwin = inputs.nix-darwin.lib.darwinSystem {
      modules = [
        self.darwinModules.default
        common
        {
          nixpkgs.hostPlatform = system;
          system.stateVersion = 6;
        }
      ];
    };
    darwinActivation = pkgs.writeText "nix-seal-darwin-activation" darwin.config.system.activationScripts.postActivation.text;
  in
  {
    module-darwin =
      checkDocument "nix-seal-module-darwin" darwin.config.nixSeal.activationSpec
        darwinActivation;
  }
)

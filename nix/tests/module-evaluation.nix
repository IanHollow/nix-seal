{
  inputs,
  self,
  system,
  pkgs,
}:
let
  targetId = "host/test";
  secretId = "service/token";
  source = "nix-seal.example.toml";
  planObjects = {
    identities = {
      administrator = {
        kind = "administrator";
        public = "age1x2k2hx0rzltg56p4et3yn4a873m6jltk62vmlrs8leamel69kamqf8ycqx";
      };
      release = {
        kind = "signer";
        public = "nix-seal-ed25519-v1:bGfuLIxQvDrT8IMpu931WWcILSKDrDmaCJ8oPFyT3X4=";
      };
      target = {
        kind = "target";
        public = "age1x2k2hx0rzltg56p4et3yn4a873m6jltk62vmlrs8leamel69kamqf8ycqx";
      };
    };
    targets.${targetId} = {
      kind = "nixOs";
      inherit system;
      identity = "target";
    };
    secrets.${secretId} = {
      inherit source;
      consumers = [ targetId ];
      administrators = [ "administrator" ];
      approvalPolicy = "release";
      runtime = {
        owner = "root";
        group = "root";
        mode = "0400";
      };
    };
    approvalPolicies.release = {
      threshold = 1;
      signers = [ "release" ];
    };
  };
  configuration = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      {
        system.stateVersion = "26.05";
        nixSeal = {
          enable = true;
          inherit targetId planObjects;
          identityFile = "/run/keys/nix-seal-target";
          artifactCacheRoot = "/var/lib/nix-seal/cache/v1";
          repositoryRoot = ../../.;
          secrets.${secretId}.source = source;
        };
      }
    ];
  };
in
{
  plan-v2 =
    assert
      (builtins.fromJSON (self.lib.mkPlan (planObjects // { repositoryRoot = ../../.; }))).schema
      == "nix-seal.plan.v2";
    pkgs.runCommand "nix-seal-plan-v2" { } "touch $out";
  module-cache-discovery =
    pkgs.runCommand "nix-seal-module-cache-discovery" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        jq -e '
          .schema == "nix-seal.activation.v2" and
          .artifactCacheRoot == "/var/lib/nix-seal/cache/v1" and
          (.artifacts | length) == 1 and
          (.artifacts[0] | has("ciphertext") | not) and
          (.artifacts[0] | has("envelope") | not)
        ' ${configuration.config.nixSeal.activationSpec} >/dev/null
        touch "$out"
      '';
}

{self, runtimeDirectory}: {lib, config, pkgs, ...}: let
  inherit (lib) mkIf mkOption types;
  cfg = config.nixSeal;
in {
  options.nixSeal = {
    enable = lib.mkEnableOption "nix-seal pre-release integration";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.system}.nix-seal;
      defaultText = lib.literalExpression "nix-seal.packages.\${pkgs.system}.nix-seal";
      description = "nix-seal package used by activation tooling.";
    };
    targetId = mkOption {
      type = types.str;
      description = "Stable lowercase target ID bound into signed artifacts.";
    };
    runtimeDirectory = mkOption {
      type = types.str;
      readOnly = true;
      default = runtimeDirectory;
      description = "Platform runtime directory for plaintext generations.";
    };
    secrets = mkOption {
      default = {};
      type = types.attrsOf (types.submodule ({name, ...}: {
        options = {
          path = mkOption {
            type = types.str;
            readOnly = true;
            default = "${runtimeDirectory}/current/${name}";
            description = "Runtime path of the activated secret.";
          };
          owner = mkOption {type = types.str; default = "root";};
          group = mkOption {type = types.str; default = "root";};
          mode = mkOption {type = types.strMatching "0[0-7]{3}"; default = "0400";};
          restartUnits = mkOption {type = types.listOf types.str; default = [];};
          reloadUnits = mkOption {type = types.listOf types.str; default = [];};
        };
      }));
      description = "Public runtime secret declarations; values never enter Nix evaluation.";
    };
    templates = mkOption {
      default = {};
      type = types.attrsOf (types.submodule ({name, ...}: {
        options.path = mkOption {
          type = types.str;
          readOnly = true;
          default = "${runtimeDirectory}/current/templates/${name}";
        };
      }));
      description = "Runtime-rendered non-store template outputs.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" cfg.targetId != null;
      message = "nixSeal.targetId must be a lowercase stable ID";
    }];
    warnings = ["nix-seal is pre-1.0 and has not passed its required external security audit"];
  };
}

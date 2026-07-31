{ self, runtimeDirectory }:
{
  lib,
  config,
  pkgs,
  ...
}:
let
  inherit (lib) mkIf mkOption types;
  cfg = config.nixSeal;
  digestType = types.strMatching "[0-9a-f]{64}";
  configuredSecrets = lib.filterAttrs (_: secret: secret.ciphertext != null) cfg.secrets;
  activationDocument = {
    schema = "nix-seal.activation.v1";
    runtimeRoot = cfg.runtimeDirectory;
    inherit (cfg) planHash;
    inherit (cfg) targetId;
    inherit (cfg) recipientFingerprint;
    inherit (cfg) allowedClockSkew;
    inherit (cfg) approvalThreshold;
    inherit (cfg) trustedKeys;
    artifacts = lib.mapAttrsToList (name: secret: {
      ciphertext = toString secret.ciphertext;
      envelope = toString secret.envelope;
      secretId = name;
      inherit (secret) sourceCiphertextHash;
      inherit (secret) artifactGeneration;
      inherit (secret) mode;
    }) configuredSecrets;
  };
in
{
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
    identityFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Runtime path to the target age identity. This path is not copied to the Nix store.";
    };
    planHash = mkOption {
      type = types.nullOr digestType;
      default = null;
      description = "Canonical plan hash bound into every accepted artifact.";
    };
    recipientFingerprint = mkOption {
      type = types.nullOr digestType;
      default = null;
      description = "Fingerprint of the configured target recipient.";
    };
    trustedKeys = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Encoded public artifact-approval keys.";
    };
    approvalThreshold = mkOption {
      type = types.ints.positive;
      default = 1;
      description = "Required number of distinct trusted artifact approvals.";
    };
    allowedClockSkew = mkOption {
      type = types.ints.between 0 86400;
      default = 300;
      description = "Maximum accepted artifact issue-time lead in seconds, capped at one day.";
    };
    runtimeDirectory = mkOption {
      type = types.str;
      readOnly = true;
      default = runtimeDirectory;
      description = "Platform runtime directory for plaintext generations.";
    };
    secrets = mkOption {
      default = { };
      type = types.attrsOf (
        types.submodule (
          { name, ... }: {
            options = {
              path = mkOption {
                type = types.str;
                readOnly = true;
                default = "${runtimeDirectory}/current/${name}";
                description = "Runtime path of the activated secret.";
              };
              owner = mkOption {
                type = types.str;
                default = "root";
              };
              group = mkOption {
                type = types.str;
                default = "root";
              };
              mode = mkOption {
                type = types.strMatching "0[0-7]{3}";
                default = "0400";
              };
              ciphertext = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Target-encrypted artifact path. Ciphertext may enter the Nix store.";
              };
              envelope = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Signed public artifact manifest path.";
              };
              sourceCiphertextHash = mkOption {
                type = types.nullOr digestType;
                default = null;
                description = "Canonical administrator ciphertext hash bound by the manifest.";
              };
              artifactGeneration = mkOption {
                type = types.ints.positive;
                default = 1;
                description = "Exact signed artifact generation.";
              };
              restartUnits = mkOption {
                type = types.listOf types.str;
                default = [ ];
              };
              reloadUnits = mkOption {
                type = types.listOf types.str;
                default = [ ];
              };
            };
          }
        )
      );
      description = "Public runtime secret declarations; values never enter Nix evaluation.";
    };
    templates = mkOption {
      default = { };
      type = types.attrsOf (
        types.submodule (
          { name, ... }: {
            options.path = mkOption {
              type = types.str;
              readOnly = true;
              default = "${runtimeDirectory}/current/templates/${name}";
            };
          }
        )
      );
      description = "Runtime-rendered non-store template outputs.";
    };
    activationSpec = mkOption {
      type = types.path;
      readOnly = true;
      default = pkgs.writeText "nix-seal-activation-v1.json" (builtins.toJSON activationDocument);
      description = "Strict public activation document consumed by the Rust runtime.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" cfg.targetId != null;
        message = "nixSeal.targetId must be a lowercase stable ID";
      }
      {
        assertion = cfg.identityFile != null;
        message = "nixSeal.identityFile must name an out-of-store target identity when nix-seal is enabled";
      }
      {
        assertion = cfg.planHash != null && cfg.recipientFingerprint != null;
        message = "nixSeal.planHash and recipientFingerprint must be explicitly configured";
      }
      {
        assertion = cfg.trustedKeys != [ ] && cfg.approvalThreshold <= builtins.length cfg.trustedKeys;
        message = "nixSeal approvalThreshold must be satisfied by configured trustedKeys";
      }
      {
        assertion = configuredSecrets != { };
        message = "nixSeal requires at least one configured target ciphertext artifact";
      }
      {
        assertion = lib.all (secret: secret.envelope != null && secret.sourceCiphertextHash != null) (
          builtins.attrValues configuredSecrets
        );
        message = "every nixSeal ciphertext requires an envelope and sourceCiphertextHash";
      }
      {
        assertion =
          builtins.length (builtins.attrNames configuredSecrets)
          == builtins.length (builtins.attrNames cfg.secrets);
        message = "every declared nixSeal secret requires a target ciphertext";
      }
    ];
    warnings = [ "nix-seal is pre-1.0 and has not passed its required external security audit" ];
  };
}

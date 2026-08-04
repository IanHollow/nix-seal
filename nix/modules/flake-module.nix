{ inputs, lib, ... }:
let
  idIsValid =
    value:
    builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null
    && !lib.hasInfix ".." value
    && lib.all (segment: segment != ".") (lib.splitString "/" value);
  idType = lib.types.addCheck lib.types.str idIsValid;
  identityType = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum [
          "administrator"
          "target"
          "recovery"
          "signer"
          "plugin"
        ];
        description = "Role of this public identity in plan.v2.";
      };
      public = lib.mkOption {
        type = lib.types.str;
        description = "Public age recipient, signer, or plugin reference.";
      };
    };
  };
  groupType = lib.types.submodule {
    options.members = lib.mkOption {
      type = lib.types.listOf idType;
      default = [ ];
      description = "Identity or group IDs in this administrator-scoped group.";
    };
  };
  approvalPolicyType = lib.types.submodule {
    options = {
      threshold = lib.mkOption {
        type = lib.types.ints.between 0 65535;
        description = "Required number of distinct signer approvals.";
      };
      signers = lib.mkOption {
        type = lib.types.listOf idType;
        description = "Signer IDs in this administrator-scoped policy.";
      };
    };
  };
  administratorType = lib.types.submodule {
    options = {
      identities = lib.mkOption {
        type = lib.types.attrsOf identityType;
        default = { };
        description = "Public administrator, recovery, signer, and plugin identities.";
      };
      groups = lib.mkOption {
        type = lib.types.attrsOf groupType;
        default = { };
        description = "Public groups whose references are scoped to this administrator.";
      };
      approvalPolicies = lib.mkOption {
        type = lib.types.attrsOf approvalPolicyType;
        default = { };
        description = "Public artifact approval policies for this administrator.";
      };
      defaultApprovalPolicy = lib.mkOption {
        type = lib.types.nullOr idType;
        default = null;
        description = "Optional local approval policy applied to secrets that omit one.";
      };
    };
  };
in
{
  options.flake.nixSeal = lib.mkOption {
    type = lib.types.submodule {
      options.administrators = lib.mkOption {
        type = lib.types.attrsOf administratorType;
        default = { };
        description = "Public administrator catalogs used by nix-seal target modules.";
      };
    };
    default = { };
    description = "Public nix-seal policy metadata. Private identities and plaintext never belong here.";
  };

  config.perSystem = { system, ... }: {
    packages.nix-seal = inputs.nix-seal.packages.${system}.nix-seal;
  };
}

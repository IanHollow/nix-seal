{
  self,
  runtimeDirectory,
  serviceManager,
  serviceExecutable,
  supportsServiceCredentials,
  serviceCredentialConfig,
  homeManagerRuntimeIdentity,
}:
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
  privateModeType = types.strMatching "0[1-7]00";
  idIsValid =
    value: builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null && !lib.hasInfix ".." value;
  idType = types.addCheck types.str idIsValid;
  privateIdentityPathIsSafe =
    value: lib.hasPrefix "/" value && !(lib.hasPrefix "/nix/store/" value);
  unitType = types.strMatching "[A-Za-z0-9_.@:-]{1,256}";
  serviceUnitType = types.strMatching "[A-Za-z0-9_.@:-]{1,247}\\.service";
  credentialNameType = types.addCheck (types.strMatching "[A-Za-z0-9_.@-]{1,255}") (
    name: name != "." && name != ".."
  );
  configuredSecrets = lib.filterAttrs (_: secret: secret.ciphertext != null) cfg.secrets;
  configuredTemplates = lib.filterAttrs (_: template: template.source != null) cfg.templates;
  explicitReloadUnits = lib.unique (
    lib.concatMap (item: item.reloadUnits) (
      builtins.attrValues configuredSecrets ++ builtins.attrValues configuredTemplates
    )
  );
  explicitRestartUnits = lib.unique (
    lib.concatMap (item: item.restartUnits) (
      builtins.attrValues configuredSecrets ++ builtins.attrValues configuredTemplates
    )
  );
  serviceCredentialBindings = lib.concatMap (
    secretId:
    map (credential: {
      inherit secretId;
      inherit (credential) unit name;
      path = cfg.secrets.${secretId}.path;
    }) cfg.secrets.${secretId}.serviceCredentials
  ) (builtins.attrNames configuredSecrets);
  serviceCredentialKeys = map (binding: "${binding.unit}:${binding.name}") serviceCredentialBindings;
  reloadUnits = explicitReloadUnits;
  restartUnits = lib.unique (
    explicitRestartUnits ++ map (binding: binding.unit) serviceCredentialBindings
  );
  activationDocument = {
    schema = "nix-seal.activation.v2";
    runtimeRoot = cfg.runtimeDirectory;
    plan = toString cfg.planFile;
    inherit (cfg) targetId;
    inherit (cfg) allowedClockSkew;
    artifacts = lib.mapAttrsToList (name: secret: {
      ciphertext = toString secret.ciphertext;
      envelope = toString secret.envelope;
      secretId = name;
      inherit (secret) sourceCiphertextHash;
      inherit (secret) artifactGeneration;
      inherit (secret) mode;
      inherit (secret) owner;
      inherit (secret) group;
    }) configuredSecrets;
    templates = lib.mapAttrsToList (name: template: {
      source = toString template.source;
      templateId = name;
      placeholders = lib.mapAttrs (_: placeholder: {
        secretId = placeholder.secret;
        inherit (placeholder) encoding;
      }) template.placeholders;
      inherit (template) mode owner group;
    }) configuredTemplates;
    postSwitch =
      if reloadUnits == [ ] && restartUnits == [ ] then
        null
      else
        {
          executable = serviceExecutable;
          manager = serviceManager;
          inherit reloadUnits restartUnits;
          timeoutSeconds = cfg.serviceActionTimeout;
        };
  };
in
{
  options.nixSeal = {
    enable = lib.mkEnableOption "nix-seal pre-release integration";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.nix-seal;
      defaultText = lib.literalExpression "nix-seal.packages.\${pkgs.stdenv.hostPlatform.system}.nix-seal";
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
    planFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Canonical compiled plan.v1 JSON used to derive and verify target policy.";
    };
    allowedClockSkew = mkOption {
      type = types.ints.between 0 86400;
      default = 300;
      description = "Maximum accepted artifact issue-time lead in seconds, capped at one day.";
    };
    serviceActionTimeout = mkOption {
      type = types.ints.between 1 60;
      default = 30;
      description = "Per-unit post-switch service action timeout in seconds.";
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
                default = if homeManagerRuntimeIdentity then config.home.username else "root";
                description = "Existing runtime account that owns the activated file.";
              };
              group = mkOption {
                type = types.str;
                default =
                  if homeManagerRuntimeIdentity then
                    (if pkgs.stdenv.hostPlatform.isDarwin then "staff" else config.home.username)
                  else
                    "root";
                description = "Existing runtime group that owns the activated file.";
              };
              mode = mkOption {
                type = privateModeType;
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
                type = types.listOf unitType;
                default = [ ];
              };
              reloadUnits = mkOption {
                type = types.listOf unitType;
                default = [ ];
              };
              serviceCredentials = mkOption {
                type = types.listOf (
                  types.submodule {
                    options = {
                      unit = mkOption {
                        type = serviceUnitType;
                        description = "Systemd service that receives this secret as a credential.";
                      };
                      name = mkOption {
                        type = credentialNameType;
                        description = "Filename exposed below the service's CREDENTIALS_DIRECTORY.";
                      };
                    };
                  }
                );
                default = [ ];
                description = ''
                  Per-service systemd credential mappings. Each mapping loads the
                  activated runtime file and automatically schedules a service
                  restart when the secret generation changes.
                '';
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
            options = {
              path = mkOption {
                type = types.str;
                readOnly = true;
                default = "${runtimeDirectory}/current/templates/${name}";
                description = "Runtime path of the atomically rendered template.";
              };
              source = mkOption {
                type = types.nullOr types.path;
                default = null;
                description = "Public template source. This file may enter the Nix store.";
              };
              placeholders = mkOption {
                default = { };
                type = types.attrsOf (
                  types.submodule {
                    options = {
                      secret = mkOption {
                        type = idType;
                        description = "ID of the secret inserted at this placeholder.";
                      };
                      encoding = mkOption {
                        type = types.enum [
                          "utf8"
                          "base64"
                          "hex"
                        ];
                        default = "utf8";
                        description = "Explicit transformation applied while streaming the secret.";
                      };
                    };
                  }
                );
                description = "Strict {{nix-seal:name}} placeholder declarations.";
              };
              owner = mkOption {
                type = types.str;
                default = if homeManagerRuntimeIdentity then config.home.username else "root";
                description = "Existing runtime account that owns the rendered file.";
              };
              group = mkOption {
                type = types.str;
                default =
                  if homeManagerRuntimeIdentity then
                    (if pkgs.stdenv.hostPlatform.isDarwin then "staff" else config.home.username)
                  else
                    "root";
                description = "Existing runtime group that owns the rendered file.";
              };
              mode = mkOption {
                type = privateModeType;
                default = "0400";
              };
              restartUnits = mkOption {
                type = types.listOf unitType;
                default = [ ];
              };
              reloadUnits = mkOption {
                type = types.listOf unitType;
                default = [ ];
              };
            };
          }
        )
      );
      description = "Runtime-rendered non-store template outputs.";
    };
    activationSpec = mkOption {
      type = types.path;
      readOnly = true;
      default = pkgs.writeText "nix-seal-activation-v2.json" (builtins.toJSON activationDocument);
      description = "Strict public activation document consumed by the Rust runtime.";
    };
  };

  config = mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = idIsValid cfg.targetId;
            message = "nixSeal.targetId must be a lowercase stable ID";
          }
          {
            assertion = lib.all idIsValid (builtins.attrNames cfg.secrets ++ builtins.attrNames cfg.templates);
            message = "nixSeal secret and template names must be lowercase stable IDs";
          }
          {
            assertion = cfg.identityFile != null;
            message = "nixSeal.identityFile must name an out-of-store target identity when nix-seal is enabled";
          }
          {
            assertion = cfg.identityFile == null || privateIdentityPathIsSafe cfg.identityFile;
            message = "nixSeal.identityFile must be an absolute path outside /nix/store";
          }
          {
            assertion = cfg.planFile != null;
            message = "nixSeal.planFile must provide canonical compiled plan.v1 JSON";
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
          {
            assertion =
              builtins.length (builtins.attrNames configuredTemplates)
              == builtins.length (builtins.attrNames cfg.templates);
            message = "every declared nixSeal template requires a public source";
          }
          {
            assertion = lib.all (
              template:
              template.placeholders != { } && builtins.length (builtins.attrNames template.placeholders) <= 256
            ) (builtins.attrValues configuredTemplates);
            message = "every nixSeal template requires between 1 and 256 declared placeholders";
          }
          {
            assertion = lib.all (
              template:
              lib.all (name: builtins.match "[a-z0-9][a-z0-9_.-]{0,127}" name != null) (
                builtins.attrNames template.placeholders
              )
            ) (builtins.attrValues configuredTemplates);
            message = "nixSeal template placeholder names must be lowercase stable names";
          }
          {
            assertion = lib.all (
              template:
              lib.all (placeholder: builtins.hasAttr placeholder.secret configuredSecrets) (
                builtins.attrValues template.placeholders
              )
            ) (builtins.attrValues configuredTemplates);
            message = "every nixSeal template placeholder must reference a configured secret";
          }
          {
            assertion =
              lib.intersectLists (builtins.attrNames configuredSecrets) (
                map (name: "templates/${name}") (builtins.attrNames configuredTemplates)
              ) == [ ];
            message = "a nixSeal template output cannot collide with a secret runtime path";
          }
          {
            assertion =
              serviceManager != "launchd-system" && serviceManager != "launchd-user" || reloadUnits == [ ];
            message = "nixSeal reloadUnits are unsupported by launchd; use restartUnits";
          }
          {
            assertion = lib.intersectLists reloadUnits restartUnits == [ ];
            message = "a nixSeal unit cannot appear in both reloadUnits and restartUnits";
          }
          {
            assertion = supportsServiceCredentials || serviceCredentialBindings == [ ];
            message = "nixSeal serviceCredentials require a systemd platform";
          }
          {
            assertion =
              builtins.length serviceCredentialKeys == builtins.length (lib.unique serviceCredentialKeys);
            message = "a systemd service credential name may be mapped by only one nixSeal secret";
          }
        ];
        warnings = [ "nix-seal is pre-1.0 and has not passed its required external security audit" ];
      }
      (serviceCredentialConfig serviceCredentialBindings)
    ]
  );
}

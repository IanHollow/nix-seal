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
  privateModeType = types.strMatching "0[1-7]00";
  idIsValid =
    value:
    builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null
    && !lib.hasInfix ".." value
    && lib.all (segment: segment != ".") (lib.splitString "/" value);
  idType = types.addCheck types.str idIsValid;
  activationPhaseType = types.enum [
    "partitioning"
    "users"
    "activation"
    "services"
  ];
  activationPhases = [
    "partitioning"
    "users"
    "activation"
    "services"
  ];
  privateIdentityPathIsSafe = value: lib.hasPrefix "/" value && !(lib.hasPrefix "/nix/store/" value);
  artifactCacheRootIsSafe =
    value:
    lib.hasPrefix "/" value
    && value != "/"
    && !(lib.hasPrefix "/nix/store/" value)
    && !lib.hasSuffix "/" value
    && !lib.hasInfix "/../" value
    && !lib.hasInfix "/./" value
    && !lib.hasSuffix "/.." value
    && !lib.hasSuffix "/." value
    && !(builtins.any (character: character < " " || character == "\u007f") (
      lib.stringToCharacters value
    ));
  unitType = types.strMatching "[A-Za-z0-9_.@:-]{1,256}";
  serviceUnitType = types.strMatching "[A-Za-z0-9_.@:-]{1,247}\\.service";
  credentialNameType = types.addCheck (types.strMatching "[A-Za-z0-9_.@-]{1,255}") (
    name: name != "." && name != ".."
  );
  compatibilitySymlinkType = types.nullOr (
    types.addCheck types.str (
      path:
      lib.hasPrefix "/" path
      && path != "/"
      && !lib.hasPrefix "/nix/store/" path
      && !lib.hasSuffix "/" path
      && !lib.hasInfix "/../" path
      && !lib.hasInfix "/./" path
      && !lib.hasSuffix "/.." path
      && !lib.hasSuffix "/." path
      && !(builtins.any (character: character < " " || character == "\u007f") (
        lib.stringToCharacters path
      ))
    )
  );
  configuredSecrets = lib.filterAttrs (_: secret: secret.source != null) cfg.secrets;
  missingSecretSources = lib.filterAttrs (_: secret: secret.source == null) cfg.secrets;
  configuredTemplates = lib.filterAttrs (_: template: template.source != null) cfg.templates;
  compiledPlanObjects = {
    inherit (cfg) identities approvalPolicies;
    targets.${cfg.targetId} = cfg.target;
    secrets = lib.mapAttrs (_: secret: {
      inherit (secret)
        source
        delivery
        administrators
        phase
        lifecycle
        ;
      consumers = [ cfg.targetId ];
      inherit (secret) approvalPolicy;
      runtime = {
        inherit (secret)
          owner
          group
          mode
          compatibilitySymlink
          restartUnits
          reloadUnits
          ;
      };
    }) configuredSecrets;
    templates = lib.mapAttrs (_: template: {
      inherit (template) source placeholders;
      runtime = {
        inherit (template)
          owner
          group
          mode
          restartUnits
          reloadUnits
          ;
      };
    }) configuredTemplates;
  };
  effectivePlanObjects = if cfg.identities != { } then compiledPlanObjects else cfg.planObjects;
  phaseRuntimeDirectory =
    phase: if phase == "activation" then cfg.runtimeDirectory else "${cfg.runtimeDirectory}/${phase}";
  configuredSecretsForPhase =
    phase: lib.filterAttrs (_: secret: secret.phase == phase) configuredSecrets;
  configuredTemplatesForPhase =
    phase: lib.filterAttrs (_: template: template.phase == phase) configuredTemplates;
  explicitReloadUnitsForPhase =
    phase:
    lib.unique (
      lib.concatMap (item: item.reloadUnits) (
        builtins.attrValues (configuredSecretsForPhase phase)
        ++ builtins.attrValues (configuredTemplatesForPhase phase)
      )
    );
  explicitRestartUnitsForPhase =
    phase:
    lib.unique (
      lib.concatMap (item: item.restartUnits) (
        builtins.attrValues (configuredSecretsForPhase phase)
        ++ builtins.attrValues (configuredTemplatesForPhase phase)
      )
    );
  serviceCredentialBindingsForPhase =
    phase:
    lib.concatMap (
      secretId:
      map (credential: {
        inherit secretId;
        inherit (credential) unit name;
        path = cfg.secrets.${secretId}.path;
      }) cfg.secrets.${secretId}.serviceCredentials
    ) (builtins.attrNames (configuredSecretsForPhase phase));
  serviceCredentialBindings = lib.concatMap serviceCredentialBindingsForPhase activationPhases;
  serviceCredentialKeys = map (binding: "${binding.unit}:${binding.name}") serviceCredentialBindings;
  reloadUnitsForPhase = explicitReloadUnitsForPhase;
  restartUnitsForPhase =
    phase:
    lib.unique (
      explicitRestartUnitsForPhase phase
      ++ map (binding: binding.unit) (serviceCredentialBindingsForPhase phase)
    );
  reloadUnits = lib.concatMap reloadUnitsForPhase activationPhases;
  activationDocumentFor =
    phase:
    let
      secrets = configuredSecretsForPhase phase;
      templates = configuredTemplatesForPhase phase;
      reloadUnits = reloadUnitsForPhase phase;
      restartUnits = restartUnitsForPhase phase;
    in
    {
      schema = "nix-seal.activation.v2";
      runtimeRoot = phaseRuntimeDirectory phase;
      plan = toString cfg.planFile;
      inherit (cfg) artifactCacheRoot;
      inherit (cfg) targetId;
      inherit phase;
      inherit (cfg) allowedClockSkew;
      artifacts = lib.mapAttrsToList (name: secret: {
        secretId = name;
        inherit (secret) phase;
        inherit (secret) mode;
        inherit (secret) owner;
        inherit (secret) group;
        inherit (secret) compatibilitySymlink;
      }) secrets;
      templates = lib.mapAttrsToList (name: template: {
        source = toString template.source;
        templateId = name;
        placeholders = lib.mapAttrs (_: placeholder: {
          secretId = placeholder.secret;
          inherit (placeholder) encoding;
        }) template.placeholders;
        inherit (template) phase;
        inherit (template) mode owner group;
      }) templates;
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
  activationDocument = activationDocumentFor "activation";
  activationSpecFor =
    phase:
    pkgs.writeText "nix-seal-activation-v2-${phase}.json" (
      builtins.toJSON (activationDocumentFor phase)
    );
  configuredPhases = lib.filter (phase: configuredSecretsForPhase phase != { }) activationPhases;
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
      default = pkgs.writeText "nix-seal-plan-v2.json" (
        self.lib.mkPlan (effectivePlanObjects // { inherit (cfg) repositoryRoot; })
      );
      description = "Canonical compiled plan.v2 JSON used to derive and verify target policy.";
    };
    repositoryRoot = mkOption {
      type = types.path;
      description = "Repository root used only to hash canonical ciphertext sources while compiling plan.v2.";
    };
    identities = mkOption {
      type = types.attrs;
      default = { };
      description = "Public administrator, recovery, signer, and target identity declarations used to compile plan.v2.";
    };
    target = mkOption {
      type = types.attrs;
      description = "Public target declaration for this configuration, including its plan identity ID.";
    };
    approvalPolicies = mkOption {
      type = types.attrs;
      default = { };
      description = "Public artifact approval policies used to compile plan.v2.";
    };
    # Temporary pre-release input accepted only so existing Nix declarations can
    # be evaluated while being simplified. New configurations use the typed
    # options above; a nonempty typed identity set always wins.
    planObjects = mkOption {
      type = types.attrs;
      default = { };
      description = "Deprecated pre-release plan input; use nixSeal identities, target, approvalPolicies, and secrets instead.";
    };
    allowedClockSkew = mkOption {
      type = types.ints.between 0 86400;
      default = 300;
      description = "Maximum accepted artifact issue-time lead in seconds, capped at one day.";
    };
    artifactCacheRoot = mkOption {
      type = types.addCheck types.str artifactCacheRootIsSafe;
      description = "Absolute target-local ciphertext cache root. Activation discovers only cryptographically verified matching bundles here.";
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
                default = "${phaseRuntimeDirectory config.nixSeal.secrets.${name}.phase}/current/${name}";
                description = "Runtime path of the activated secret.";
              };
              phase = mkOption {
                type = activationPhaseType;
                default = "activation";
                description = "Activation generation that materializes this secret.";
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
              compatibilitySymlink = mkOption {
                type = compatibilitySymlinkType;
                default = null;
                description = ''
                  Optional absolute compatibility symlink for legacy consumers.
                  Activation binds it to the stable current-generation path and
                  refuses to replace a mismatched existing filesystem entry.
                '';
              };
              source = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = "Repository-relative canonical .age ciphertext source. Its hash is pinned by plan.v2, never copied to the runtime activation metadata.";
              };
              delivery = mkOption {
                type = types.enum [
                  "rekeyed"
                  "direct"
                ];
                default = "rekeyed";
                description = "Ciphertext delivery model.";
              };
              administrators = mkOption {
                type = types.listOf idType;
                default = [ ];
                description = "Administrator or recovery identity IDs authorized for canonical encryption.";
              };
              approvalPolicy = mkOption {
                type = types.nullOr idType;
                default = null;
                description = "Approval policy ID required for this secret's artifacts.";
              };
              lifecycle = mkOption {
                type = types.attrs;
                default = { };
                description = "Public lifecycle metadata included in plan.v2.";
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
                default = "${
                  phaseRuntimeDirectory config.nixSeal.templates.${name}.phase
                }/current/templates/${name}";
                description = "Runtime path of the atomically rendered template.";
              };
              phase = mkOption {
                type = activationPhaseType;
                default = "activation";
                description = "Activation generation that renders this template.";
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
    activationSpecs = mkOption {
      type = types.attrsOf types.path;
      readOnly = true;
      default = lib.genAttrs configuredPhases activationSpecFor;
      description = "Strict phase-isolated activation documents consumed by the Rust runtime.";
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
            message = "nixSeal.planFile must provide canonical compiled plan.v2 JSON";
          }
          {
            assertion = configuredSecrets != { };
            message = "nixSeal requires at least one configured canonical secret source";
          }
          {
            assertion = missingSecretSources == { };
            message =
              let
                secret = builtins.head (builtins.attrNames missingSecretSources);
              in
              "nixSeal secret ${secret} is missing its canonical repository source";
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
            assertion = lib.all (
              template:
              lib.all (
                placeholder:
                builtins.hasAttr placeholder.secret configuredSecrets
                && cfg.secrets.${placeholder.secret}.phase == template.phase
              ) (builtins.attrValues template.placeholders)
            ) (builtins.attrValues configuredTemplates);
            message = "every nixSeal template may reference secrets from exactly its own activation phase";
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
            assertion = lib.all (
              phase: lib.intersectLists (reloadUnitsForPhase phase) (restartUnitsForPhase phase) == [ ]
            ) configuredPhases;
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

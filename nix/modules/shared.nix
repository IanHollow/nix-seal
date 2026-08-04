{
  self,
  runtimeDirectory,
  runtimeStorage ? "persistent",
  serviceManager,
  serviceExecutable,
  supportsServiceCredentials,
  serviceCredentialConfig,
  homeManagerRuntimeIdentity,
  targetKind,
}:
{
  lib,
  config,
  pkgs,
  nixSealCatalog ? { },
  ...
}:
let
  inherit (lib) mkIf mkOption types;
  cfg = config.nixSeal;
  # Module arguments are resolved by the Nix module system before the module
  # function's defaults are applied. Read this optional framework argument
  # from _module.args so standalone consumers can evaluate the module without
  # having to define targetName.
  targetName = config._module.args.targetName or null;
  privateModeType = types.strMatching "0[1-7]00";
  idIsValid =
    value:
    builtins.match "[a-z0-9._-]+(/[a-z0-9._-]+)*" value != null
    && !lib.hasInfix ".." value
    && lib.all (segment: segment != ".") (lib.splitString "/" value);
  idType = types.addCheck types.str idIsValid;
  localIdIsValid =
    value:
    idIsValid value
    && (
      cfg.administrator == null
      || (
        !(lib.any (administrator: lib.hasPrefix "${administrator}/" value) (
          builtins.attrNames administratorCatalog
        ))
        && !(lib.hasPrefix "host/" value)
        && !(lib.hasPrefix "home/" value)
        && !(lib.hasPrefix "hosts/" value)
        && !(lib.hasPrefix "users/" value)
      )
    );
  localIdType = types.addCheck types.str localIdIsValid;
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
  administratorCatalog = nixSealCatalog.administrators or { };
  selectedAdministrator =
    if cfg.administrator != null && builtins.hasAttr cfg.administrator administratorCatalog then
      administratorCatalog.${cfg.administrator}
    else
      { };
  targetScopeFromId =
    targetId:
    let
      parts = lib.splitString "/" targetId;
    in
    if lib.hasPrefix "home/" targetId && builtins.length parts >= 2 then
      "users/${builtins.elemAt parts 1}"
    else if lib.hasPrefix "host/" targetId then
      "hosts/${lib.removePrefix "host/" targetId}"
    else
      null;
  derivedTargetName = targetName;
  derivedTargetId =
    if derivedTargetName == null then
      null
    else if targetKind == "homeManager" then
      "home/${config.home.username}/${derivedTargetName}"
    else
      "host/${if targetKind == "nixOs" then "nixos" else "darwin"}/${derivedTargetName}";
  derivedSecretScope =
    if targetKind == "homeManager" then
      "users/${config.home.username}"
    else if derivedTargetName != null then
      "hosts/${if targetKind == "nixOs" then "nixos" else "darwin"}/${derivedTargetName}"
    else if cfg.targetId != null then
      targetScopeFromId cfg.targetId
    else
      null;
  canonicalSecretId =
    name: if cfg.administrator == null then name else "${cfg.administrator}/${cfg.secretScope}/${name}";
  canonicalTemplateId =
    name: if cfg.administrator == null then name else "${cfg.administrator}/${cfg.secretScope}/${name}";
  qualifyReference =
    kind: value:
    if cfg.administrator == null then
      value
    else
      let
        first = builtins.head (lib.splitString "/" value);
        selectedPrefix = "${cfg.administrator}/";
      in
      if lib.hasPrefix selectedPrefix value then
        value
      else if builtins.hasAttr first administratorCatalog && first != cfg.administrator then
        throw "nixSeal ${kind} '${value}' references administrator '${first}', but target follows '${cfg.administrator}'"
      else
        "${selectedPrefix}${value}";
  projectAdminGroups =
    if cfg.administrator == null then
      { }
    else
      lib.mapAttrs' (
        name: group:
        lib.nameValuePair "${cfg.administrator}/${name}" (
          group // { members = map (qualifyReference "administrator group member") (group.members or [ ]); }
        )
      ) (selectedAdministrator.groups or { });
  projectAdminApprovalPolicies =
    if cfg.administrator == null then
      { }
    else
      lib.mapAttrs' (
        name: policy:
        lib.nameValuePair "${cfg.administrator}/${name}" (
          policy // { signers = map (qualifyReference "approval signer") (policy.signers or [ ]); }
        )
      ) (selectedAdministrator.approvalPolicies or { });
  projectAdminIdentities =
    if cfg.administrator == null then
      { }
    else
      lib.mapAttrs' (name: identity: lib.nameValuePair "${cfg.administrator}/${name}" identity) (
        selectedAdministrator.identities or { }
      );
  projectLocalGroups =
    if cfg.administrator == null then
      cfg.groups
    else
      lib.mapAttrs' (
        name: group:
        lib.nameValuePair "${cfg.administrator}/${name}" (
          group // { members = map (qualifyReference "group member") (group.members or [ ]); }
        )
      ) cfg.groups;
  projectLocalApprovalPolicies =
    if cfg.administrator == null then
      cfg.approvalPolicies
    else
      lib.mapAttrs' (
        name: policy:
        lib.nameValuePair "${cfg.administrator}/${name}" (
          policy // { signers = map (qualifyReference "approval signer") (policy.signers or [ ]); }
        )
      ) cfg.approvalPolicies;
  defaultApprovalPolicy = selectedAdministrator.defaultApprovalPolicy or null;
  defaultAdministratorReferences =
    if cfg.administrator == null then
      [ ]
    else
      lib.filter (
        name:
        lib.elem
          (
            if builtins.hasAttr name (selectedAdministrator.identities or { }) then
              selectedAdministrator.identities.${name}.kind
            else
              null
          )
          [
            "administrator"
            "recovery"
          ]
      ) (builtins.attrNames (selectedAdministrator.identities or { }));
  configuredSecrets = lib.filterAttrs (_: secret: secret.source != null) cfg.secrets;
  missingSecretSources = lib.filterAttrs (_: secret: secret.source == null) cfg.secrets;
  configuredTemplates = lib.filterAttrs (_: template: template.source != null) cfg.templates;
  compiledPlanObjects = {
    identities = projectAdminIdentities // cfg.identities;
    groups = projectAdminGroups // projectLocalGroups;
    approvalPolicies = projectAdminApprovalPolicies // projectLocalApprovalPolicies;
    targets = lib.optionalAttrs (cfg.targetId != null) { ${cfg.targetId} = cfg.target; };
    secrets = lib.mapAttrs' (
      name: secret:
      lib.nameValuePair (canonicalSecretId name) {
        inherit (secret)
          source
          delivery
          phase
          lifecycle
          ;
        administrators = map (qualifyReference "administrator") secret.administrators;
        consumers = lib.optional (cfg.targetId != null) cfg.targetId;
        approvalPolicy =
          if secret.approvalPolicy != null then
            qualifyReference "approval policy" secret.approvalPolicy
          else if defaultApprovalPolicy != null then
            qualifyReference "default approval policy" defaultApprovalPolicy
          else
            null;
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
      }
    ) configuredSecrets;
    templates = lib.mapAttrs' (
      name: template:
      lib.nameValuePair (canonicalTemplateId name) {
        inherit (template) source;
        placeholders = lib.mapAttrs (_: placeholderDef: {
          secret = canonicalSecretId placeholderDef.secret;
          inherit (placeholderDef) encoding;
        }) template.placeholders;
        runtime = {
          inherit (template)
            owner
            group
            mode
            restartUnits
            reloadUnits
            ;
        };
      }
    ) configuredTemplates;
  };
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
      inherit (cfg) runtimeStorage;
      plan = toString cfg.planFile;
      inherit (cfg) artifactCacheRoot;
      inherit (cfg) targetId;
      inherit phase;
      inherit (cfg) allowedClockSkew;
      artifacts = lib.mapAttrsToList (_name: secret: {
        secretId = secret.id;
        inherit (secret) phase;
        inherit (secret) mode;
        inherit (secret) owner;
        inherit (secret) group;
        inherit (secret) compatibilitySymlink;
      }) secrets;
      templates = lib.mapAttrsToList (_: template: {
        source = toString template.source;
        templateId = template.id;
        placeholders = lib.mapAttrs (_: placeholderDef: {
          secretId = cfg.secrets.${placeholderDef.secret}.id;
          inherit (placeholderDef) encoding;
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
    administrator = mkOption {
      type = types.nullOr idType;
      default = null;
      description = "Flake-level administrator catalog entry followed by this target.";
    };
    targetId = mkOption {
      type = types.nullOr idType;
      default = null;
      description = "Stable target ID bound into signed artifacts; derived from framework metadata when available.";
    };
    secretScope = mkOption {
      type = types.nullOr idType;
      default = null;
      description = "Administrator-relative secret namespace; derived from the target when available.";
    };
    identityFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Runtime path to the target age identity. This path is not copied to the Nix store.";
    };
    planFile = mkOption {
      type = types.nullOr types.path;
      default = pkgs.writeText "nix-seal-plan-v2.json" (
        self.lib.mkPlan (compiledPlanObjects // { inherit (cfg) repositoryRoot; })
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
    groups = mkOption {
      type = types.attrs;
      default = { };
      description = "Public plan groups declared by this target or administrator projection.";
    };
    target = mkOption {
      type = types.attrs;
      default = { };
      description = "Public target declaration for this configuration, including its plan identity ID.";
    };
    approvalPolicies = mkOption {
      type = types.attrs;
      default = { };
      description = "Public artifact approval policies used to compile plan.v2.";
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
    runtimeStorage = mkOption {
      type = types.enum [
        "persistent"
        "volatile-tmpfs"
        "volatile-tmpfs-noswap"
      ];
      default = runtimeStorage;
      internal = true;
      description = "Internal activation storage requirement selected by the platform module.";
    };
    secrets = mkOption {
      default = { };
      type = types.attrsOf (
        types.submodule (
          { name, ... }: {
            options = {
              id = mkOption {
                type = idType;
                readOnly = true;
                default = canonicalSecretId name;
                description = "Canonical plan ID derived from the selected administrator and target scope.";
              };
              path = mkOption {
                type = types.str;
                readOnly = true;
                default = "${phaseRuntimeDirectory config.nixSeal.secrets.${name}.phase}/current/${
                  config.nixSeal.secrets.${name}.id
                }";
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
                default =
                  if cfg.administrator != null && cfg.secretScope != null then
                    "secrets/${canonicalSecretId name}.age"
                  else
                    null;
                description = "Repository-relative canonical .age ciphertext source; scoped targets derive this from the canonical ID.";
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
                default = defaultAdministratorReferences;
                description = "Administrator or recovery identity IDs; scoped targets qualify local references under the selected administrator.";
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
              id = mkOption {
                type = idType;
                readOnly = true;
                default = canonicalTemplateId name;
                description = "Canonical plan ID derived from the selected administrator and target scope.";
              };
              path = mkOption {
                type = types.str;
                readOnly = true;
                default = "${phaseRuntimeDirectory config.nixSeal.templates.${name}.phase}/current/templates/${
                  config.nixSeal.templates.${name}.id
                }";
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
                        type = localIdType;
                        description = "Local ID of the secret inserted at this placeholder.";
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
        nixSeal.target = lib.mkDefault (
          {
            kind = targetKind;
            system = pkgs.stdenv.hostPlatform.system;
            identity = "target";
          }
          // lib.optionalAttrs (targetName != null) { configuration = targetName; }
          // lib.optionalAttrs (targetKind == "homeManager") { username = config.home.username; }
        );
        nixSeal.targetId = lib.mkDefault derivedTargetId;
        nixSeal.secretScope = lib.mkDefault derivedSecretScope;
        assertions = [
          {
            assertion = cfg.targetId != null && idIsValid cfg.targetId;
            message = "nixSeal.targetId must be a lowercase stable ID or be derivable from framework metadata";
          }
          {
            assertion = cfg.target != { } && cfg.target ? identity;
            message = "nixSeal.target must declare a target identity";
          }
          {
            assertion = lib.all localIdIsValid (
              builtins.attrNames cfg.secrets ++ builtins.attrNames cfg.templates
            );
            message = "nixSeal scoped secret and template names must be local lowercase stable IDs";
          }
          {
            assertion = cfg.administrator == null || builtins.hasAttr cfg.administrator administratorCatalog;
            message = "nixSeal.administrator must reference an administrator in the flake nixSeal catalog";
          }
          {
            assertion = cfg.administrator == null || cfg.secretScope != null;
            message = "nixSeal.secretScope must be derivable or explicitly set when nixSeal.administrator is selected";
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
              lib.all (placeholderDef: builtins.hasAttr placeholderDef.secret configuredSecrets) (
                builtins.attrValues template.placeholders
              )
            ) (builtins.attrValues configuredTemplates);
            message = "every nixSeal template placeholder must reference a configured secret";
          }
          {
            assertion = lib.all (
              template:
              lib.all (
                placeholderDef:
                builtins.hasAttr placeholderDef.secret configuredSecrets
                && cfg.secrets.${placeholderDef.secret}.phase == template.phase
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

{
  inputs,
  self,
  system,
  pkgs,
}:
let
  inherit (inputs.nixpkgs) lib;
  nixSealLib = self.lib;
  digest = character: builtins.concatStringsSep "" (lib.replicate 64 character);
  ciphertext = pkgs.writeText "nix-seal-test-artifact.age" "public ciphertext fixture";
  envelope = pkgs.writeText "nix-seal-test-envelope.json" "public envelope fixture";
  exportedArtifact = pkgs.runCommand "nix-seal-test-exported-artifact" { } ''
    mkdir -p "$out"
    printf '%s' 'public ciphertext fixture' > "$out/ciphertext.age"
    printf '%s' 'public envelope fixture' > "$out/manifest.dsse.json"
  '';
  importedArtifact = nixSealLib.artifactBundle {
    path = exportedArtifact;
    target = "host.test";
    secret = "db/password";
  };
  templateSource = pkgs.writeText "nix-seal-test-template" ''
    password={{nix-seal:password}}
  '';
  planFile = pkgs.writeText "nix-seal-test-plan-v1.json" ''
    {"schema":"nix-seal.plan.v1"}
  '';
  common = {
    nixSeal = {
      enable = true;
      targetId = "host.test";
      identityFile = "/run/keys/nix-seal-target";
      inherit planFile;
      secrets."db/password" = {
        inherit ciphertext envelope;
        sourceCiphertextHash = digest "2";
        compatibilitySymlink = "/run/nix-seal-legacy/db-password";
      };
      templates."application/config" = {
        source = templateSource;
        placeholders.password.secret = "db/password";
        restartUnits = [ "example.service" ];
      };
    };
  };
  commonNoPlan = common // {
    nixSeal = builtins.removeAttrs common.nixSeal [ "planFile" ];
  };
  credentialMapping = {
    nixSeal.secrets."db/password".serviceCredentials = [
      {
        unit = "example.service";
        name = "database-password";
      }
    ];
  };
  explicitRestart = {
    nixSeal.secrets."db/password".restartUnits = [ "example.service" ];
  };
  nixos = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      credentialMapping
      { system.stateVersion = "26.05"; }
    ];
  };
  nixosCompiledPlan = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      commonNoPlan
      {
        system.stateVersion = "26.05";
        nixSeal.planObjects = { };
      }
    ];
  };
  nixosArtifactBundle = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      {
        system.stateVersion = "26.05";
        nixSeal = {
          enable = true;
          targetId = "host.test";
          identityFile = "/run/keys/nix-seal-target";
          inherit planFile;
          secrets."db/password" = {
            artifact = importedArtifact;
            sourceCiphertextHash = digest "2";
          };
        };
      }
    ];
  };
  credentialCollision = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      credentialMapping
      {
        system.stateVersion = "26.05";
        systemd.services.example.serviceConfig.LoadCredential = [
          "database-password:/run/conflicting-source"
        ];
        nixSeal.secrets."api/token" = {
          inherit ciphertext envelope;
          sourceCiphertextHash = digest "3";
          serviceCredentials = [
            {
              unit = "example.service";
              name = "database-password";
            }
          ];
        };
      }
    ];
  };
  templatePolicyViolation = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal = {
          secrets."templates/application/config" = {
            inherit ciphertext envelope;
            sourceCiphertextHash = digest "4";
          };
          secrets."invalid../id" = {
            inherit ciphertext envelope;
            sourceCiphertextHash = digest "5";
          };
          templates."unknown/config" = {
            source = templateSource;
            placeholders.value.secret = "missing/secret";
          };
          templates."missing/source".placeholders.value.secret = "db/password";
        };
      }
    ];
  };
  unsafeIdentityPath = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal.identityFile = lib.mkForce "/nix/store/public-target.identity";
      }
    ];
  };
  nixosPhased = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal.secrets."bootstrap/token" = {
          inherit ciphertext envelope;
          sourceCiphertextHash = digest "6";
          phase = "users";
        };
      }
    ];
  };
  partitioningPhase = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal.secrets."disk/token" = {
          inherit ciphertext envelope;
          sourceCiphertextHash = digest "7";
          phase = "partitioning";
        };
      }
    ];
  };
  partitioningInstaller = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal.installerMode = true;
        nixSeal.secrets."disk/token" = {
          inherit ciphertext envelope;
          sourceCiphertextHash = digest "7";
          phase = "partitioning";
        };
      }
    ];
  };
  phaseTemplateViolation = inputs.nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      self.nixosModules.default
      common
      {
        system.stateVersion = "26.05";
        nixSeal.secrets."bootstrap/token" = {
          inherit ciphertext envelope;
          sourceCiphertextHash = digest "8";
          phase = "users";
        };
        nixSeal.templates."bootstrap/config" = {
          source = templateSource;
          placeholders.password.secret = "bootstrap/token";
        };
      }
    ];
  };
  home = inputs.home-manager.lib.homeManagerConfiguration {
    inherit pkgs;
    modules = [
      self.homeManagerModules.default
      common
      (if pkgs.stdenv.hostPlatform.isLinux then credentialMapping else explicitRestart)
      {
        home = {
          username = "test";
          homeDirectory = "/home/test";
          stateVersion = "26.05";
        };
      }
    ];
  };
  homePhased = inputs.home-manager.lib.homeManagerConfiguration {
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
        nixSeal = {
          secrets."bootstrap/token" = {
            inherit ciphertext envelope;
            sourceCiphertextHash = digest "9";
            phase = "users";
          };
          secrets."service/token" = {
            inherit ciphertext envelope;
            sourceCiphertextHash = digest "a";
            phase = "services";
          };
        };
      }
    ];
  };
  homeRuntimeDirectory =
    if pkgs.stdenv.hostPlatform.isLinux then "%t/nix-seal" else "/home/test/Library/Caches/nix-seal";
  homeActivationRuntimeDirectory =
    if pkgs.stdenv.hostPlatform.isLinux then
      ''"$XDG_RUNTIME_DIR/nix-seal"''
    else
      "/home/test/Library/Caches/nix-seal";
  checkDocument =
    name: manager: owner: group: spec: activationText: credentialSpec:
    pkgs.runCommand name { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e \
        --arg manager ${lib.escapeShellArg manager} \
        --arg owner ${lib.escapeShellArg owner} \
        --arg group ${lib.escapeShellArg group} \
        --arg planFile ${lib.escapeShellArg (toString planFile)} \
        --arg templateSource ${lib.escapeShellArg (toString templateSource)} '
        .schema == "nix-seal.activation.v2" and
        .targetId == "host.test" and
        .plan == $planFile and
        (has("planHash") | not) and
        (has("targetPolicyHash") | not) and
        (has("recipientFingerprint") | not) and
        (has("trustedKeys") | not) and
        (has("approvalThreshold") | not) and
        (.artifacts | length) == 1 and
        (.templates | length) == 1 and
        .artifacts[0].secretId == "db/password" and
        .artifacts[0].compatibilitySymlink == "/run/nix-seal-legacy/db-password" and
        .artifacts[0].owner == $owner and
        .artifacts[0].group == $group and
        .templates[0].templateId == "application/config" and
        .templates[0].source == $templateSource and
        .templates[0].placeholders.password.secretId == "db/password" and
        .templates[0].placeholders.password.encoding == "utf8" and
        .templates[0].owner == $owner and
        .templates[0].group == $group and
        .postSwitch.restartUnits == ["example.service"] and
        .postSwitch.manager == $manager
      ' ${spec} >/dev/null
      ${lib.optionalString (credentialSpec != null) ''
        jq -e '
          .loadCredential == ["database-password:" + .expectedPath] and
          (.privateMounts == null or .privateMounts == true)
        ' ${credentialSpec} >/dev/null
      ''}
      grep -F -- "--identity /run/keys/nix-seal-target" ${activationText} >/dev/null
      touch "$out"
    '';
  nixosActivation = pkgs.writeText "nix-seal-nixos-activation" nixos.config.system.activationScripts.nixSeal.text;
  nixosUsersActivation = pkgs.writeText "nix-seal-nixos-users-activation" nixosPhased.config.system.activationScripts.nixSealUsers.text;
  homeActivation = pkgs.writeText "nix-seal-home-activation" home.config.home.activation.nixSeal.data;
  homeUsersActivation = pkgs.writeText "nix-seal-home-users-activation" homePhased.config.home.activation.nixSealUsers.data;
  homeServicesActivation = pkgs.writeText "nix-seal-home-services-activation" homePhased.config.home.activation.nixSealServices.data;
  nixosCredentialSpec = pkgs.writeText "nix-seal-nixos-credential.json" (
    builtins.toJSON {
      loadCredential = nixos.config.systemd.services.example.serviceConfig.LoadCredential;
      privateMounts = nixos.config.systemd.services.example.serviceConfig.PrivateMounts;
      expectedPath = "/run/nix-seal/current/db/password";
    }
  );
  homeCredentialSpec = pkgs.writeText "nix-seal-home-credential.json" (
    builtins.toJSON {
      loadCredential = home.config.systemd.user.services.example.Service.LoadCredential;
      privateMounts = null;
      expectedPath = "%t/nix-seal/current/db/password";
    }
  );
  hasFailedAssertion =
    message: evaluated:
    lib.any (
      assertion: !assertion.assertion && assertion.message == message
    ) evaluated.config.assertions;
  strictPlan = nixSealLib.mkPlan {
    identities.admin = { };
    secrets."db/password" = { };
  };
  strictPlanFile = pkgs.writeText "nix-seal-test-strict-plan-v1.json" strictPlan;
  invalidCollectionId = builtins.tryEval (
    builtins.deepSeq (nixSealLib.mkPlan { secrets."bad//id" = { }; }) true
  );
  invalidDotSegmentId = builtins.tryEval (
    builtins.deepSeq (nixSealLib.mkPlan { secrets."bad/./id" = { }; }) true
  );
  invalidArtifactEntries = builtins.tryEval (
    nixSealLib.artifactBundle {
      path = pkgs.runCommand "nix-seal-invalid-artifact" { } ''
        mkdir -p "$out"
        touch "$out/ciphertext.age" "$out/manifest.dsse.json" "$out/unexpected"
      '';
      target = "host.test";
      secret = "db/password";
    }
  );
  missingArtifact = builtins.tryEval (
    nixSealLib.artifactBundle {
      target = "host.test";
      secret = "db/password";
      rekeyCommand = "nix-seal rekey --plan plan.v1.json --target host.test --secret db/password";
    }
  );
in
{
  module-plan-objects =
    pkgs.runCommand "nix-seal-module-plan-objects" { nativeBuildInputs = [ pkgs.jq ]; }
      ''
        jq -e '.schema == "nix-seal.plan.v1" and (.secrets | length) == 0' \
          ${nixosCompiledPlan.config.nixSeal.planFile} >/dev/null
        touch "$out"
      '';
  lib-plan-builder =
    assert !invalidCollectionId.success;
    assert !invalidDotSegmentId.success;
    pkgs.runCommand "nix-seal-lib-plan-builder" { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '
        .schema == "nix-seal.plan.v1" and
        (.identities | keys) == ["admin"] and
        (.secrets | keys) == ["db/password"] and
        ((keys | sort) == [
          "approvalPolicies", "backends", "generators", "groups",
          "identities", "schema", "secrets", "targets", "templates"
        ])
      ' ${strictPlanFile} >/dev/null
      touch "$out"
    '';
  lib-artifact-bundle =
    assert invalidArtifactEntries.success == false;
    assert missingArtifact.success == false;
    assert builtins.pathExists "${importedArtifact}/ciphertext.age";
    assert builtins.pathExists "${importedArtifact}/manifest.dsse.json";
    pkgs.runCommand "nix-seal-lib-artifact-bundle" { } ''
      test -f ${importedArtifact}/ciphertext.age
      test -f ${importedArtifact}/manifest.dsse.json
      test "$(find ${importedArtifact} -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2
      touch "$out"
    '';
  module-artifact-bundle =
    assert
      nixosArtifactBundle.config.nixSeal.secrets."db/password".ciphertext
      == "${importedArtifact}/ciphertext.age";
    assert
      nixosArtifactBundle.config.nixSeal.secrets."db/password".envelope
      == "${importedArtifact}/manifest.dsse.json";
    pkgs.runCommand "nix-seal-module-artifact-bundle" { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '.artifacts[0].ciphertext == "${importedArtifact}/ciphertext.age" and .artifacts[0].envelope == "${importedArtifact}/manifest.dsse.json"' \
        ${nixosArtifactBundle.config.nixSeal.activationSpec} >/dev/null
      touch "$out"
    '';
  module-nixos =
    checkDocument "nix-seal-module-nixos" "systemd-system" "root" "root"
      nixos.config.nixSeal.activationSpec
      nixosActivation
      nixosCredentialSpec;
  module-home-manager =
    checkDocument "nix-seal-module-home-manager"
      (if pkgs.stdenv.hostPlatform.isLinux then "systemd-user" else "launchd-user")
      "test"
      (if pkgs.stdenv.hostPlatform.isLinux then "test" else "staff")
      home.config.nixSeal.activationSpec
      homeActivation
      (if pkgs.stdenv.hostPlatform.isLinux then homeCredentialSpec else null);
  module-credential-policy =
    assert hasFailedAssertion
      "a systemd service credential name may be mapped by only one nixSeal secret"
      credentialCollision;
    assert hasFailedAssertion
      "systemd service example.service has a LoadCredential name that conflicts with nixSeal"
      credentialCollision;
    pkgs.runCommand "nix-seal-module-credential-policy" { } ''
      touch "$out"
    '';
  module-template-policy =
    assert hasFailedAssertion "nixSeal secret and template names must be lowercase stable IDs"
      templatePolicyViolation;
    assert hasFailedAssertion "every declared nixSeal template requires a public source"
      templatePolicyViolation;
    assert hasFailedAssertion "every nixSeal template placeholder must reference a configured secret"
      templatePolicyViolation;
    assert hasFailedAssertion "a nixSeal template output cannot collide with a secret runtime path"
      templatePolicyViolation;
    pkgs.runCommand "nix-seal-module-template-policy" { } ''
      touch "$out"
    '';
  module-identity-policy =
    assert hasFailedAssertion "nixSeal.identityFile must be an absolute path outside /nix/store"
      unsafeIdentityPath;
    pkgs.runCommand "nix-seal-module-identity-policy" { } ''
      touch "$out"
    '';
  module-phase-scheduling =
    assert
      nixosPhased.config.nixSeal.secrets."bootstrap/token".path
      == "/run/nix-seal/users/current/bootstrap/token";
    assert lib.elem "nixSealUsers" nixosPhased.config.system.activationScripts.users.deps;
    assert hasFailedAssertion
      "nixSeal partitioning-phase secrets require explicit nixSeal.installerMode=true; the module never schedules partitioning activation automatically"
      partitioningPhase;
    assert partitioningInstaller.config.nixSeal.activationSpecs ? partitioning;
    assert !(partitioningInstaller.config.system.activationScripts ? nixSealPartitioning);
    assert hasFailedAssertion
      "every nixSeal template may reference secrets from exactly its own activation phase"
      phaseTemplateViolation;
    pkgs.runCommand "nix-seal-module-phase-scheduling" { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '
        .phase == "users" and
        .runtimeRoot == "/run/nix-seal/users" and
        (.artifacts | length) == 1 and
        .artifacts[0].secretId == "bootstrap/token" and
        .artifacts[0].phase == "users" and
        (.templates | length) == 0
      ' ${nixosPhased.config.nixSeal.activationSpecs.users} >/dev/null
      jq -e '
        .phase == "partitioning" and
        .runtimeRoot == "/run/nix-seal/partitioning" and
        (.artifacts | length) == 1 and
        .artifacts[0].secretId == "disk/token"
      ' ${partitioningInstaller.config.nixSeal.activationSpecs.partitioning} >/dev/null
      grep -F -- "--identity /run/keys/nix-seal-target" ${nixosUsersActivation} >/dev/null
      touch "$out"
    '';
  module-home-phase-scheduling =
    assert
      homePhased.config.nixSeal.secrets."bootstrap/token".path
      == "${homeRuntimeDirectory}/users/current/bootstrap/token";
    assert
      homePhased.config.nixSeal.secrets."service/token".path
      == "${homeRuntimeDirectory}/services/current/service/token";
    assert lib.elem "nixSealUsers" homePhased.config.home.activation.nixSeal.after;
    assert lib.elem "nixSeal" homePhased.config.home.activation.nixSealServices.after;
    pkgs.runCommand "nix-seal-module-home-phase-scheduling" { nativeBuildInputs = [ pkgs.jq ]; } ''
      jq -e '
        .phase == "users" and
        .runtimeRoot == $runtimeRoot and
        (.artifacts | length) == 1 and
        .artifacts[0].secretId == "bootstrap/token"
      ' --arg runtimeRoot "${homeRuntimeDirectory}/users" ${homePhased.config.nixSeal.activationSpecs.users} >/dev/null
      jq -e '
        .phase == "services" and
        .runtimeRoot == $runtimeRoot and
        (.artifacts | length) == 1 and
        .artifacts[0].secretId == "service/token"
      ' --arg runtimeRoot "${homeRuntimeDirectory}/services" ${homePhased.config.nixSeal.activationSpecs.services} >/dev/null
      grep -F -- ${lib.escapeShellArg "${homeActivationRuntimeDirectory}/users"} ${homeUsersActivation} >/dev/null
      grep -F -- ${lib.escapeShellArg "${homeActivationRuntimeDirectory}/services"} ${homeServicesActivation} >/dev/null
      touch "$out"
    '';
}
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
  let
    homeExternalCollision = inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules.default
        common
        credentialMapping
        {
          home = {
            username = "test";
            homeDirectory = "/home/test";
            stateVersion = "26.05";
          };
          systemd.user.services.example.Service.LoadCredential = [
            "database-password:/run/conflicting-source"
          ];
        }
      ];
    };
  in
  {
    module-home-credential-policy =
      assert !(builtins.tryEval homeExternalCollision.activationPackage).success;
      pkgs.runCommand "nix-seal-module-home-credential-policy" { } ''
        touch "$out"
      '';
  }
)
// lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin (
  let
    darwin = inputs.nix-darwin.lib.darwinSystem {
      modules = [
        self.darwinModules.default
        common
        explicitRestart
        {
          nixpkgs.hostPlatform = system;
          system.stateVersion = 6;
        }
      ];
    };
    darwinActivation = pkgs.writeText "nix-seal-darwin-activation" darwin.config.system.activationScripts.postActivation.text;
    darwinPhased = inputs.nix-darwin.lib.darwinSystem {
      modules = [
        self.darwinModules.default
        common
        {
          nixpkgs.hostPlatform = system;
          system.stateVersion = 6;
          nixSeal = {
            secrets."bootstrap/token" = {
              inherit ciphertext envelope;
              sourceCiphertextHash = digest "b";
              phase = "users";
            };
            secrets."service/token" = {
              inherit ciphertext envelope;
              sourceCiphertextHash = digest "c";
              phase = "services";
            };
          };
        }
      ];
    };
    darwinUsersActivation = pkgs.writeText "nix-seal-darwin-users-activation" darwinPhased.config.system.activationScripts.extraActivation.text;
    darwinServicesActivation = pkgs.writeText "nix-seal-darwin-services-activation" darwinPhased.config.system.activationScripts.postActivation.text;
    darwinUnsupported = inputs.nix-darwin.lib.darwinSystem {
      modules = [
        self.darwinModules.default
        common
        credentialMapping
        {
          nixpkgs.hostPlatform = system;
          system.stateVersion = 6;
        }
      ];
    };
    homeUnsupported = inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeManagerModules.default
        common
        credentialMapping
        {
          home = {
            username = "test";
            homeDirectory = "/Users/test";
            stateVersion = "26.05";
          };
        }
      ];
    };
  in
  {
    module-darwin =
      checkDocument "nix-seal-module-darwin" "launchd-system" "root" "root"
        darwin.config.nixSeal.activationSpec
        darwinActivation
        null;
    module-darwin-credential-policy =
      assert hasFailedAssertion "nixSeal serviceCredentials require a systemd platform" darwinUnsupported;
      assert !(builtins.tryEval homeUnsupported.activationPackage).success;
      pkgs.runCommand "nix-seal-module-darwin-credential-policy" { } ''
        touch "$out"
      '';
    module-darwin-phase-scheduling =
      assert
        darwinPhased.config.nixSeal.secrets."bootstrap/token".path
        == "/var/run/nix-seal/users/current/bootstrap/token";
      assert
        darwinPhased.config.nixSeal.secrets."service/token".path
        == "/var/run/nix-seal/services/current/service/token";
      pkgs.runCommand "nix-seal-module-darwin-phase-scheduling" { nativeBuildInputs = [ pkgs.jq ]; } ''
        jq -e '
          .phase == "users" and
          .runtimeRoot == "/var/run/nix-seal/users" and
          (.artifacts | length) == 1 and
          .artifacts[0].secretId == "bootstrap/token"
        ' ${darwinPhased.config.nixSeal.activationSpecs.users} >/dev/null
        jq -e '
          .phase == "services" and
          .runtimeRoot == "/var/run/nix-seal/services" and
          (.artifacts | length) == 1 and
          .artifacts[0].secretId == "service/token"
        ' ${darwinPhased.config.nixSeal.activationSpecs.services} >/dev/null
        grep -F -- "--spec ${darwinPhased.config.nixSeal.activationSpecs.users}" ${darwinUsersActivation} >/dev/null
        grep -F -- "--spec ${darwinPhased.config.nixSeal.activationSpecs.activation}" ${darwinServicesActivation} >/dev/null
        grep -F -- "--spec ${darwinPhased.config.nixSeal.activationSpecs.services}" ${darwinServicesActivation} >/dev/null
        touch "$out"
      '';
  }
)

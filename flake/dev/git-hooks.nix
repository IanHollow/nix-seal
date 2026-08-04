{ inputs, lib, ... }: {
  imports = [ inputs.git-hooks-nix.flakeModule ];

  perSystem = { config, pkgs, ... }: {
    pre-commit = {
      check.enable = pkgs.stdenv.hostPlatform.isDarwin;
      settings = {
        package = pkgs.prek;
        hooks = {
          treefmt = {
            enable = true;
            name = "treefmt";
            entry = "${lib.getExe config.treefmt.build.wrapper} --no-cache";
            pass_filenames = true;
          };
          pinact = {
            enable = true;
            name = "pinact";
            entry = "${lib.getExe pkgs.pinact} run --fix=false --no-api";
            language = "system";
            files = "^\\.github/workflows/.*\\.ya?ml$";
            after = [ "treefmt" ];
          };
          cargo-fmt = {
            enable = true;
            entry = "cargo fmt --all -- --check";
            language = "system";
            always_run = true;
            pass_filenames = false;
            after = [ "treefmt" ];
          };
          cargo-check = {
            enable = true;
            entry = "cargo check --workspace --all-targets";
            language = "system";
            always_run = true;
            pass_filenames = false;
            stages = [ "pre-push" ];
            after = [ "cargo-fmt" ];
          };

          end-of-file-fixer = {
            enable = true;
            excludes = [ ".*\\.age$" ];
          };
          trim-trailing-whitespace = {
            enable = true;
            excludes = [ ".*\\.age$" ];
          };
          mixed-line-endings = {
            enable = true;
            args = [ "--fix=lf" ];
            excludes = [ ".*\\.age$" ];
          };
          check-merge-conflicts.enable = true;
          check-symlinks.enable = true;
          detect-private-keys.enable = true;
          check-case-conflicts.enable = true;
          check-added-large-files.enable = true;
          check-executables-have-shebangs.enable = true;
          check-shebang-scripts-are-executable = {
            enable = true;
            excludes = [ ".*\\.rs$" ];
          };
          fix-byte-order-marker.enable = true;
          check-json.enable = true;
          check-toml.enable = true;
          check-yaml.enable = true;
          editorconfig-checker = {
            enable = true;
            excludes = [
              "^LICENSE-.*$"
              "^docs/runbooks\\.md$"
              "^crates/nix-seal-cli/tests/authoring\\.rs$"
            ];
          };
          typos = {
            enable = true;
            settings.configPath = ".typos.toml";
          };
          zizmor = {
            enable = true;
            args = [
              "--persona=pedantic"
              "--min-severity=medium"
            ];
          };
          gitleaks = {
            enable = true;
            name = "Gitleaks";
            entry = "${lib.getExe pkgs.gitleaks} git --pre-commit --staged --redact --no-banner";
            language = "system";
            always_run = true;
            pass_filenames = false;
          };
          flake-checker.enable = true;

          nix-flake-check = {
            enable = true;
            entry = "${lib.getExe pkgs.nix} flake check --no-build";
            language = "system";
            always_run = true;
            pass_filenames = false;
            stages = [ "pre-push" ];
          };
        };
      };
    };
  };
}

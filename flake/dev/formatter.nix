{ inputs, ... }: {
  imports = [ inputs.treefmt-nix.flakeModule ];

  perSystem.treefmt.programs = {
    actionlint.enable = true;
    yamlfmt.enable = true;
    yamllint = {
      enable = true;
      settings = {
        extends = "default";
        rules = {
          document-start = "disable";
          line-length = {
            max = 160;
            level = "warning";
          };
        };
      };
    };

    deadnix.enable = true;
    statix.enable = true;
    nixfmt = {
      enable = true;
      width = 100;
      strict = true;
    };
    nixf-diagnose = {
      enable = true;
      autoFix = false;
    };

    shfmt.enable = true;
    shellcheck.enable = true;
    taplo.enable = true;
    rumdl-check.enable = true;
    typos = {
      enable = true;
      configFile = ".typos.toml";
    };
    prettier = {
      enable = true;
      excludes = [
        "*.md"
        "*.yaml"
        "*.yml"
      ];
      settings.proseWrap = "always";
    };
    keep-sorted.enable = true;
    just.enable = true;
  };
}

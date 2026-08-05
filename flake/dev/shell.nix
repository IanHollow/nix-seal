_: {
  perSystem =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      inherit (config.pre-commit.settings) enabledPackages package shellHook;
    in
    {
      devShells.default = pkgs.mkShellNoCC {
        inherit shellHook;
        LIBRARY_PATH = lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "${pkgs.libiconv}/lib";
        NIX_LDFLAGS = lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "-L${pkgs.libiconv}/lib";
        packages =
          enabledPackages
          ++ [ package ]
          ++ (with pkgs; [
            age
            actionlint
            cargo-audit
            cargo-deny
            cargo-fuzz
            cargo-nextest
            cargo-vet
            deadnix
            direnv
            editorconfig-checker
            gitleaks
            keep-sorted
            just
            nixd
            nixf-diagnose
            nixfmt
            nixfmt-rfc-style
            osv-scanner
            pinact
            prettier
            prek
            rumdl
            rage
            rustc
            clippy
            rust-analyzer
            rustfmt
            shellcheck
            shfmt
            statix
            taplo
            treefmt
            typos
            yamlfmt
            yamllint
            zizmor
          ])
          ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];
      };
    };
}

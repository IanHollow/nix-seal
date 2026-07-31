self: { config, lib, ... }: {
  imports = [
    ((import ./shared.nix) {
      inherit self;
      runtimeDirectory = "%t/nix-seal";
    })
  ];
  config = lib.mkIf config.nixSeal.enable {
    home.activation.nixSeal = lib.hm.dag.entryAfter [ "writeBoundary" ] ''
      if [ -z "''${XDG_RUNTIME_DIR:-}" ]; then
        echo "nix-seal: XDG_RUNTIME_DIR is required for Home Manager activation" >&2
        exit 1
      fi
      ${lib.getExe config.nixSeal.package} activate \
        --spec ${config.nixSeal.activationSpec} \
        --identity ${lib.escapeShellArg config.nixSeal.identityFile} \
        --runtime-root "$XDG_RUNTIME_DIR/nix-seal"
    '';
    warnings = [
      "Home Manager stores runtime plaintext under XDG_RUNTIME_DIR; macOS may not provide memory-backed storage"
    ];
  };
}

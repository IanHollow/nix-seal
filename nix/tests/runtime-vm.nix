{
  self,
  system,
  pkgs,
}:
let
  # A real VM test complements module evaluation and the Rust runtime tests.
  # Every private identity and secret value is generated inside the guest, so
  # the Nix evaluation graph, store, test derivation, and host never contain a
  # plaintext fixture or a private key.
  nixSeal = self.packages.${system}.nix-seal;
in
pkgs.testers.nixosTest {
  name = "nix-seal-runtime-activation";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [
      nixSeal
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
      pkgs.jq
    ];
    systemd.services.nix-seal-test = {
      description = "nix-seal VM credential consumer";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        LoadCredential = "database-password:/run/nix-seal/current/app/token";
      };
      script = ''
        umask 077
        ${pkgs.coreutils}/bin/cat "$CREDENTIALS_DIRECTORY/database-password" > /run/nix-seal-service-observed
      '';
    };
    virtualisation.memorySize = 1024;
    system.stateVersion = "26.05";
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")

    machine.succeed("""
      set -euo pipefail
      umask 077
      root=/var/lib/nix-seal-runtime-test
      install -d -m 0700 "$root" "$root/secrets"

      admin_recipient=$(nix-seal key generate --identity-out "$root/admin.age")
      target_recipient=$(nix-seal key generate --identity-out "$root/target.age")
      signer_public=$(nix-seal key generate-signing --key-out "$root/signer.key")

      # printf avoids a whitespace-sensitive here-document terminator inside
      # the Python test driver's indented command string.
      printf '%s\\n' \
        'schema = "nix-seal.plan.v2"' \
        "" \
        '[identities.admin]' \
        'kind = "administrator"' \
        "public = \\\"$admin_recipient\\\"" \
        "" \
        '[identities.target]' \
        'kind = "target"' \
        "public = \\\"$target_recipient\\\"" \
        "" \
        '[identities.signer]' \
        'kind = "signer"' \
        "public = \\\"$signer_public\\\"" \
        "" \
        '[targets.vm]' \
        'kind = "nixOs"' \
        'system = "x86_64-linux"' \
        'identity = "target"' \
        "" \
        '[approvalPolicies.release]' \
        'threshold = 1' \
        'signers = ["signer"]' \
        "" \
        '[secrets."app/token"]' \
        'source = "secrets/app-token.age"' \
        'sourceCiphertextHash = "0000000000000000000000000000000000000000000000000000000000000000"' \
        'administrators = ["admin"]' \
        'consumers = ["vm"]' \
        'approvalPolicy = "release"' \
        "" \
        '[secrets."app/token".runtime]' \
        'owner = "root"' \
        'group = "root"' \
        'mode = "0400"' \
        'restartUnits = ["nix-seal-test.service"]' \
        "" \
        '[templates."app/config"]' \
        'source = "template.txt"' \
        "" \
        '[templates."app/config".placeholders.token]' \
        'secret = "app/token"' \
        'encoding = "base64"' > "$root/nix-seal.toml"

      printf 'token={{nix-seal:token}}\\n' > "$root/template.txt"
      nix-seal plan --toml "$root/nix-seal.toml" --output "$root/plan.v2.json"

      # Keep the random canary entirely in a pipe. The activated file is a
      # printable base64 token so grep can scan the Nix store using -f without
      # putting the value in process arguments.
      head -c 32 /dev/urandom | base64 -w0 | nix-seal secret create \
        --plan "$root/plan.v2.json" \
        --secret app/token \
        --repository-root "$root" \
        --identity "$root/admin.age"

      # Canonical authoring creates the ciphertext; compile the plan again so
      # its required public source hash is bound to the committed bytes.
      source_hash=$(sha256sum "$root/secrets/app-token.age" | cut -d' ' -f1)
      sed -i "s/^sourceCiphertextHash = \"[0-9a-f]*\"$/sourceCiphertextHash = \"$source_hash\"/" "$root/nix-seal.toml"
      nix-seal plan --toml "$root/nix-seal.toml" --output "$root/plan.v2.json"

      result=$(nix-seal --json rekey \
        --plan "$root/plan.v2.json" \
        --repository-root "$root" \
        --identity "$root/admin.age" \
        --target vm \
        --secret app/token \
        --generation 1 \
        --signing-key "$root/signer.key" \
        --cache-root "$root/cache")
      jq -n \
        --arg root /run/nix-seal \
        --arg plan "$root/plan.v2.json" \
        --arg cache "$root/cache" \
        --arg template "$root/template.txt" \
        '{
          schema: "nix-seal.activation.v2",
          runtimeRoot: $root,
          plan: $plan,
          artifactCacheRoot: $cache,
          targetId: "vm",
          phase: "activation",
          allowedClockSkew: 0,
          artifacts: [{
            secretId: "app/token",
            phase: "activation",
            mode: "0400",
            owner: "root",
            group: "root"
          }],
          templates: [{
            source: $template,
            templateId: "app/config",
            phase: "activation",
            placeholders: {token: {secretId: "app/token", encoding: "base64"}},
            mode: "0400",
            owner: "root",
            group: "root"
          }],
          postSwitch: {
            executable: "/run/current-system/sw/bin/systemctl",
            manager: "systemd-system",
            reloadUnits: [],
            restartUnits: ["nix-seal-test.service"],
            timeoutSeconds: 30
          }
        }' > "$root/activation.json"

      systemctl daemon-reload
      nix-seal activate --spec "$root/activation.json" --identity "$root/target.age"
      systemctl start nix-seal-test.service
      cmp /run/nix-seal-service-observed /run/nix-seal/current/app/token

      nix-seal activate --spec "$root/activation.json" --identity "$root/target.age"

      test "$(stat -c %a /run/nix-seal/current/app/token)" = 400
      test "$(stat -c %U:%G /run/nix-seal/current/app/token)" = root:root
      test "$(stat -c %a /run/nix-seal/current/templates/app/config)" = 400
      cut -d= -f2 /run/nix-seal/current/templates/app/config | base64 -d | cmp - /run/nix-seal/current/app/token
      systemctl is-active --quiet nix-seal-test.service
      cmp /run/nix-seal-service-observed /run/nix-seal/current/app/token

      # The random plaintext must not have escaped into the host-visible Nix
      # store. -f reads the candidate from the activated private file rather
      # than exposing it through argv or an environment variable.
      # Nix store paths may contain dangling symlinks after GC. Restrict the
      # scan to regular files rather than treating an unreadable dangling target
      # as a plaintext-leak failure. `find` batches its regular-file arguments
      # for grep, which emits only matching public paths; the canary itself
      # stays in the private `-f` file rather than argv.
      if find /nix/store -type f \
        -exec grep -l --binary-files=without-match -F -f /run/nix-seal/current/app/token {} + \
        2>/dev/null | grep -q .; then
        exit 1
      fi

      # A tampered artifact must fail before a generation switch and preserve
      # the working secret/template pair from the prior generation.
      artifact_dir="$root/cache/artifacts/$(jq -r '.key' "$root/cache/index.json" | head -n1)"
      printf x >> "$artifact_dir/ciphertext.age"
      ! nix-seal activate --spec "$root/activation.json" --identity "$root/target.age"
      cut -d= -f2 /run/nix-seal/current/templates/app/config | base64 -d | cmp - /run/nix-seal/current/app/token
      cmp /run/nix-seal-service-observed /run/nix-seal/current/app/token
    """)
  '';
}

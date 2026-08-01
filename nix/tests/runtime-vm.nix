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
      pkgs.gnugrep
      pkgs.jq
    ];
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
        'schema = "nix-seal.plan.v1"' \
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
        'administrators = ["admin"]' \
        'consumers = ["vm"]' \
        'approvalPolicy = "release"' \
        "" \
        '[secrets."app/token".runtime]' \
        'owner = "root"' \
        'group = "root"' \
        'mode = "0400"' \
        "" \
        '[templates."app/config"]' \
        'source = "template.txt"' \
        "" \
        '[templates."app/config".placeholders.token]' \
        'secret = "app/token"' \
        'encoding = "base64"' > "$root/nix-seal.toml"

      printf 'token={{nix-seal:token}}\\n' > "$root/template.txt"
      nix-seal plan --toml "$root/nix-seal.toml" --output "$root/plan.v1.json"

      # Keep the random canary entirely in a pipe. The activated file is a
      # printable base64 token so grep can scan the Nix store using -f without
      # putting the value in process arguments.
      head -c 32 /dev/urandom | base64 -w0 | nix-seal secret create \
        --plan "$root/plan.v1.json" \
        --secret app/token \
        --repository-root "$root" \
        --identity "$root/admin.age"

      result=$(nix-seal --json rekey \
        --plan "$root/plan.v1.json" \
        --repository-root "$root" \
        --identity "$root/admin.age" \
        --target vm \
        --secret app/token \
        --generation 1 \
        --signing-key "$root/signer.key" \
        --cache-root "$root/cache")
      cache_key=$(printf '%s' "$result" | jq -er '.cacheKey')
      source_hash=$(printf '%s' "$result" | jq -er '.sourceCiphertextHash')
      artifact_dir="$root/cache/artifacts/$cache_key"

      jq -n \
        --arg root /run/nix-seal \
        --arg plan "$root/plan.v1.json" \
        --arg ciphertext "$artifact_dir/ciphertext.age" \
        --arg envelope "$artifact_dir/manifest.dsse.json" \
        --arg template "$root/template.txt" \
        --arg source_hash "$source_hash" \
        '{
          schema: "nix-seal.activation.v2",
          runtimeRoot: $root,
          plan: $plan,
          targetId: "vm",
          phase: "activation",
          allowedClockSkew: 0,
          artifacts: [{
            ciphertext: $ciphertext,
            envelope: $envelope,
            secretId: "app/token",
            phase: "activation",
            sourceCiphertextHash: $source_hash,
            artifactGeneration: 1,
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
          }]
        }' > "$root/activation.json"

      nix-seal activate --spec "$root/activation.json" --identity "$root/target.age"

      test "$(stat -c %a /run/nix-seal/current/app/token)" = 400
      test "$(stat -c %U:%G /run/nix-seal/current/app/token)" = root:root
      test "$(stat -c %a /run/nix-seal/current/templates/app/config)" = 400
      cut -d= -f2 /run/nix-seal/current/templates/app/config | base64 -d | cmp - /run/nix-seal/current/app/token

      # The random plaintext must not have escaped into the host-visible Nix
      # store. -f reads the candidate from the activated private file rather
      # than exposing it through argv or an environment variable.
      if grep -R --binary-files=without-match -F -f /run/nix-seal/current/app/token /nix/store; then
        exit 1
      else
        test "$?" -eq 1
      fi

      # A tampered artifact must fail before a generation switch and preserve
      # the working secret/template pair from the prior generation.
      printf x >> "$artifact_dir/ciphertext.age"
      ! nix-seal activate --spec "$root/activation.json" --identity "$root/target.age"
      cut -d= -f2 /run/nix-seal/current/templates/app/config | base64 -d | cmp - /run/nix-seal/current/app/token
    """)
  '';
}

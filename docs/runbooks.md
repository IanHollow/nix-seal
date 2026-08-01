# Security and recovery runbooks

These procedures assume a reviewed `plan.v1.json`, a protected administrator
workstation, and private identities stored outside the Nix store. Commands that
can mutate state are shown first in their dry-run form. Never put a secret
value, private identity, passphrase, or decrypted fragment in an argument,
ordinary environment variable, issue, chat, or log.

## Incident rules

1. Stop deployments and freeze plan, cache, and Git changes. Record the public
   plan hash, target IDs, affected identity fingerprints, artifact generations,
   and UTC timestamps. Do not copy plaintext as incident evidence.
2. Preserve the affected Git commits, cache manifests, and activation logs as
   public evidence. Restrict access to any private identity or runtime host
   involved in the incident.
3. Work from a clean, patched administrator machine. Assume a compromised
   administrator or target key can decrypt every historical ciphertext that it
   was addressed to; changing a recipient does not erase Git history.
4. After containment, compile the reviewed TOML/Nix sources and run
   `nix-seal check --toml nix-seal.toml --nix-plan plan-from-nix.json --deep`
   when both sources exist. Run `nix-seal doctor --plan plan.v1.json` against
   the compiled plan before provisioning any target. Review the JSON reports as
   public metadata only.

## Administrator or recovery-key compromise

This procedure has two separate actions: recipient rekeying and application
credential rotation. Recipient rekeying changes who can decrypt a ciphertext; it
does not change the credential used by the service.

1. Disable and quarantine the compromised identity. Do not use it again to
   decrypt or rekey values. Identify every administrator/recovery identity and
   secret policy that references it.
2. Generate or provision a replacement administrator/recovery recipient using an
   offline or hardware-backed process. Add the new public identity and remove or
   rotate the old public identity in the reviewed TOML/Nix plan. Keep the old
   identity only long enough to complete an explicitly approved historical
   recovery, never in the new default policy.
3. Compile and inspect the replacement plan:

   ```console
   nix-seal plan --toml nix-seal.toml --nix-plan plan-from-nix.json --output plan.v1.json
   nix-seal check --toml nix-seal.toml --nix-plan plan-from-nix.json \
     --deep --repository-root .
   nix-seal doctor --plan plan.v1.json --repository-root .
   ```

4. For each canonical ciphertext whose recipients changed, keep at least one
   uncompromised administrator/recovery identity authorized long enough to
   perform the conversion. Review the recipient-only canonical rekey first;
   it changes encryption recipients without changing the application value:

   ```console
   nix-seal secret rekey --plan plan.v1.json --secret <id> \
     --repository-root . --identity /private/uncompromised-recovery.age --json
   ```

   After reviewing the public report, repeat the command with `--yes`. The
   operation stages a fresh standard age ciphertext, verifies it by round-trip
   decryption, and atomically replaces the same canonical source. If no
   authorized old identity remains, or if a path change is required for
   side-by-side rollback, use the migration adapter instead with an
   uncompromised identity used only for this approved conversion:

   ```console
   nix-seal migrate ciphertext --repository-root . \
     --source secrets/old/service.age --destination secrets/new/service.age \
     --identity /private/old-recovery.age --recipient age1new... --json
   ```

   Review the mapping and then add `--execute`. Update the plan's `source` field
   in the same reviewed change; never delete the old source until the new
   ciphertext has passed an independent round-trip check. Repeat for every
   affected source or use an explicitly reviewed bulk adapter.

5. Rebuild target artifacts from the new plan. `provision` is dry-run-first;
   only add `--execute` after reviewing every target and generation. Export the
   ciphertext-only cache to the deployment host and activate normally.
6. Rotate application credentials for any service whose value may have been
   decrypted. Use `nix-seal rotate --plan plan.v1.json --secret <id>` with the
   replacement value supplied through a protected stream, then reprovision and
   restart/reload only after the complete generation switches.
7. Treat all old Git ciphertext and old cache artifacts as exposed. Retain them
   only when required for incident evidence; otherwise use repository retention
   controls and cache GC, understanding that secure deletion cannot be
   guaranteed on copy-on-write or SSD storage.

## Target-key compromise or target loss

1. Remove the target from deployment automation and isolate or wipe the target
   according to its platform procedure. A direct-delivery target key requires
   treating matching current and historical Git ciphertext as exposed; a rekeyed
   target key requires treating its target artifacts as exposed.
2. Rotate the target identity in the plan, or remove the target and create a
   replacement target ID. Compile and deep-check the plan, review the target
   projection, and provision a new generation with the replacement recipient.
3. Rotate every application credential delivered to the compromised target if
   the target could read it. Do not rely on artifact generation numbers as a
   credential rotation mechanism.
4. If the target is merely unavailable and not compromised, restore it from
   trusted installation media, recover its identity through the approved
   hardware/offline path, import the ciphertext-only cache, and activate the
   last approved generation. Never copy plaintext through the Nix store or a
   deployment command line.

## Approval-signer compromise and signer rotation

1. Stop artifact publication and record the affected signer fingerprint. A
   signing key authenticates policy approval; it is separate from decryption
   identities and does not itself decrypt ciphertext.
2. Generate a replacement signing key on a clean machine. Add its public key to
   the relevant `approvalPolicies`, remove the compromised key, and choose an
   explicit threshold that remains satisfiable by the remaining trusted signers.
3. Compile and validate the plan, then reprovision every target artifact with
   the replacement signer set. Verify each artifact before deployment:

   ```console
   nix-seal provision --plan plan.v1.json --target <target> --generation <n> \
     --signing-key /private/new-signing-key --identity /private/admin.age
   nix-seal check --toml nix-seal.toml --nix-plan plan-from-nix.json \
     --deep --repository-root .
   ```

   Add `--execute` only after the complete dry-run report has been reviewed.

4. Remove stale artifacts with `nix-seal cache gc` after confirming the active
   plan and signer threshold. Activation must reject old envelopes because the
   current plan no longer trusts the compromised signer.

## Cache loss, corruption, or binary-cache substitution

1. Treat the cache as disposable ciphertext-only build output. Verify the
   canonical plan and source ciphertext from Git, not from the cache.
2. Run `nix-seal doctor --plan plan.v1.json --repository-root .` and inspect any
   stale, malformed, or unauthenticated object counts. Do not manually copy
   files into the cache.
3. Recreate artifacts with `nix-seal provision` in dry-run mode, then use
   `--execute` from a trusted administrator machine. Export with
   `nix-seal cache export` and import with `nix-seal cache import`; import
   revalidates hashes, signatures, names, permissions, and exact bundle layout.
4. If a binary cache or transport supplied an artifact, activation remains the
   final authority: it verifies the plan hash, source hash, target binding,
   recipient fingerprint, generation, expiry, and approval threshold before
   decrypting.

## Failed activation and rollback

1. A failed batch must leave the previous `current` generation active. Confirm
   that the service still references the previous generation and capture only
   public error metadata.
2. Fix the plan, artifact, ownership, or runtime cause on the administrator
   machine. Do not edit files inside an active generation and do not delete an
   old generation before confirming the replacement is healthy.
3. Use the platform's normal Nix rollback or redeploy the previously approved
   artifact generation. Re-run activation and service health checks, then
   inspect unit reload/restart results.
4. Remember that old generations contain old plaintext until removed or the host
   reboots. If the failed deployment involved a suspected credential exposure,
   rotate the application value before making the rollback durable.

## Recovery from Git and offline backups

1. Restore the exact reviewed plan and canonical age sources from a trusted Git
   commit or backup. Verify the commit and repository ownership before opening
   any identity.
2. Recover at least one authorized administrator/recovery identity and one
   currently trusted signing key from separate protected backups. Check private
   file ownership and permissions; never place either in `/nix/store`.
3. Run the compiled-plan `check --deep` procedure, `doctor`, and a dry-run
   `provision` for one low-risk target. Export/import the resulting
   ciphertext-only cache and verify the artifact envelope before activating.
4. Exercise one rollback path and record the plan hash, artifact generation, and
   recovery outcome. Update the incident record without recording values.

These runbooks are operational guidance, not a guarantee of secure deletion or
host integrity. A compromised kernel, root account, administrator workstation,
or external service still requires the corresponding platform incident process.

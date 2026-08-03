#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Ok(plan) = serde_json::from_slice::<nix_seal_core::PlanV2>(input) else {
        return;
    };
    if nix_seal_policy::validate(&plan).is_err() {
        return;
    }

    let canonical = nix_seal_policy::canonical_json(&plan)
        .expect("a validated plan must have canonical public JSON");
    let reparsed = serde_json::from_slice::<nix_seal_core::PlanV2>(&canonical)
        .expect("canonical public JSON must deserialize");
    nix_seal_policy::validate(&reparsed).expect("canonical public JSON must validate");

    for target_id in reparsed.targets.keys() {
        let projection = nix_seal_policy::target_policy(&reparsed, target_id)
            .expect("a validated target must produce a projection");
        nix_seal_policy::target_policy_hash(&projection)
            .expect("a target projection must have a canonical hash");
    }
});

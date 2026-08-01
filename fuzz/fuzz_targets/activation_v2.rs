#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Ok(spec) = serde_json::from_slice::<nix_seal_runtime::ActivationSpecV2>(input) else {
        return;
    };
    if spec.validate().is_err() {
        return;
    }

    let canonical = serde_json::to_vec(&spec)
        .expect("a validated activation document must serialize to public JSON");
    let reparsed = serde_json::from_slice::<nix_seal_runtime::ActivationSpecV2>(&canonical)
        .expect("serialized public activation JSON must deserialize");
    reparsed
        .validate()
        .expect("serialized public activation JSON must validate");
});

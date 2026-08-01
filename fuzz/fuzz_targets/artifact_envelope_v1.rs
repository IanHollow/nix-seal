#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Ok(envelope) = serde_json::from_slice::<nix_seal_manifest::SignedEnvelopeV1>(input) else {
        return;
    };
    if nix_seal_manifest::inspect_unverified(&envelope).is_err() {
        return;
    }

    let canonical = serde_json::to_vec(&envelope)
        .expect("a structurally valid envelope must serialize to public JSON");
    let reparsed = serde_json::from_slice::<nix_seal_manifest::SignedEnvelopeV1>(&canonical)
        .expect("serialized public envelope JSON must deserialize");
    nix_seal_manifest::inspect_unverified(&reparsed)
        .expect("serialized public envelope JSON must retain its canonical manifest payload");
});

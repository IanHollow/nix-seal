#![no_main]

use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

fuzz_target!(|input: &[u8]| {
    let Ok(value) = std::str::from_utf8(input) else {
        return;
    };

    if let Ok(normalized) = nix_seal_crypto::normalize_recipient(value) {
        let renormalized = nix_seal_crypto::normalize_recipient(&normalized)
            .expect("a normalized recipient must be accepted again");
        assert_eq!(normalized, renormalized);
        let fingerprint = nix_seal_crypto::recipient_fingerprint(&normalized)
            .expect("a normalized recipient must have a fingerprint");
        assert_eq!(fingerprint.len(), 64);
    }

    let identity = SecretString::from(value.to_owned());
    let _ = nix_seal_crypto::recipient_from_identity(&identity);
});

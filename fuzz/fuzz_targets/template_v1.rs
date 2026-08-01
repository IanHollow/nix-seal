#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use nix_seal_runtime::{RuntimeError, TemplateEncodingV1, TemplatePlaceholderSpecV1};

fn placeholders() -> BTreeMap<String, TemplatePlaceholderSpecV1> {
    BTreeMap::from([(
        "value".to_owned(),
        TemplatePlaceholderSpecV1 {
            secret_id: nix_seal_core::Id::parse("fuzz/value").expect("static ID must be valid"),
            encoding: TemplateEncodingV1::Utf8,
        },
    )])
}

fuzz_target!(|input: &[u8]| {
    let placeholders = placeholders();
    if nix_seal_runtime::validate_template_source(input, &placeholders).is_err() {
        return;
    }

    let mut rendered = Vec::new();
    nix_seal_runtime::render_template_into(input, &placeholders, &mut rendered, |_placeholder, writer| {
        writer.write_all(b"value").map_err(RuntimeError::Io)
    })
    .expect("a validated template must render with every declared placeholder");
});

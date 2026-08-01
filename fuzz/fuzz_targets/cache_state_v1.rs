#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let temporary = tempfile::tempdir().expect("temporary cache root must be creatable");
    let cache = nix_seal_cache::Cache::open(temporary.path().join("cache"))
        .expect("private cache root must be creatable");
    let digest = cache.put(input).expect("bounded cache put must succeed");
    assert_eq!(cache.get(&digest).expect("stored object must verify"), input);
    assert_eq!(cache.put(input).expect("idempotent cache put must succeed"), digest);
    let inventory = cache.inventory().expect("cache inventory must verify");
    assert_eq!(inventory.object_count, 1);

    let exported = temporary.path().join("exported");
    cache.export_to(&exported).expect("verified cache export must succeed");
    let imported = nix_seal_cache::Cache::open(temporary.path().join("imported"))
        .expect("second private cache root must be creatable");
    imported
        .import_from(&exported)
        .expect("verified cache import must succeed");
    assert_eq!(imported.get(&digest).expect("imported object must verify"), input);
});

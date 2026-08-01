#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

fuzz_target!(|input: &[u8]| {
    let temporary = tempfile::tempdir().expect("temporary cache root must be creatable");
    let cache = nix_seal_cache::Cache::open(temporary.path().join("cache"))
        .expect("private cache root must be creatable");
    let digest = cache.put(input).expect("bounded cache put must succeed");
    assert_eq!(cache.get(&digest).expect("stored object must verify"), input);
    assert_eq!(cache.put(input).expect("idempotent cache put must succeed"), digest);
    let secondary_input = if input == b"nix-seal-cache-fuzz-secondary" {
        b"nix-seal-cache-fuzz-secondary-alt".as_slice()
    } else {
        b"nix-seal-cache-fuzz-secondary".as_slice()
    };
    let secondary_digest = cache
        .put(secondary_input)
        .expect("second bounded cache put must succeed");
    assert_ne!(digest, secondary_digest);
    let inventory = cache.inventory().expect("cache inventory must verify");
    assert_eq!(inventory.object_count, 2);

    let retention = BTreeSet::from([digest.clone()]);
    let dry_run = cache
        .garbage_collect(&nix_seal_cache::GcRequest {
            retained_artifacts: BTreeSet::new(),
            retained_objects: retention.clone(),
            execute: false,
        })
        .expect("cache garbage-collection dry run must verify");
    assert!(!dry_run.executed);
    assert_eq!(dry_run.retained_objects, 1);
    assert_eq!(dry_run.candidate_objects, 1);
    assert_eq!(
        cache.get(&secondary_digest).expect("dry run must retain candidate"),
        secondary_input
    );
    let collected = cache
        .garbage_collect(&nix_seal_cache::GcRequest {
            retained_artifacts: BTreeSet::new(),
            retained_objects: retention,
            execute: true,
        })
        .expect("executing cache garbage collection must verify");
    assert!(collected.executed);
    assert_eq!(collected.candidate_objects, 1);
    assert_eq!(cache.get(&digest).expect("retained object must verify"), input);
    assert!(cache.get(&secondary_digest).is_err());
    assert_eq!(
        cache
            .inventory()
            .expect("post-GC cache inventory must verify")
            .object_count,
        1
    );

    let exported = temporary.path().join("exported");
    cache.export_to(&exported).expect("verified cache export must succeed");
    let imported = nix_seal_cache::Cache::open(temporary.path().join("imported"))
        .expect("second private cache root must be creatable");
    imported
        .import_from(&exported)
        .expect("verified cache import must succeed");
    assert_eq!(imported.get(&digest).expect("imported object must verify"), input);
    let emptied = imported
        .garbage_collect(&nix_seal_cache::GcRequest {
            retained_artifacts: BTreeSet::new(),
            retained_objects: BTreeSet::new(),
            execute: true,
        })
        .expect("imported cache collection must verify");
    assert_eq!(emptied.candidate_objects, 1);
    assert!(imported.get(&digest).is_err());
});

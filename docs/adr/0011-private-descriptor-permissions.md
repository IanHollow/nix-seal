# ADR 0011: Descriptor-relative private file permissions

Status: accepted; implemented

Private files created or received from a generator are restricted through the
already-open file descriptor, never by changing permissions through a pathname
after an earlier metadata check. This applies to identities, prompt and
generator state, generator dependency files, and generator outputs.

Generator output directories are controlled by the invoked executable. The
runtime therefore opens each declared output with `O_NOFOLLOW|O_CLOEXEC`,
requires a regular single-link file owned by the invoking user, and applies
mode `0600` to that descriptor before reading it. A hostile generator can
still read or replace its own workspace files, but cannot turn a pathname-based
permission race into chmod'ing an unrelated file. The opened descriptor also
remains the source of the bounded read, so a later pathname substitution does
not change the bytes consumed by nix-seal.

The same invariant is used for newly-created private identity and state files:
`create_new` establishes the directory entry, descriptor permissions are set
immediately, and bytes are written and synchronized through that descriptor.
This is defense in depth and does not replace private-parent validation or the
documented malicious-editor/generator boundary.

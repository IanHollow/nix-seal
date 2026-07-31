# ADR 0008: Plan-directed authoring and lifecycle

Status: accepted; create/import/edit/reveal/rotate foundation implemented

Canonical ciphertext authoring must derive its recipients and source path from
the validated plan. Arbitrary recipient and output arguments are not an
authoritative interface. Rekeyed sources include selected administrators and all
configured recovery identities. Direct sources additionally include the target
identities reached through their consumer groups and emit an explicit warning
about current and historical Git ciphertext exposure. Groups used in an
administrator or consumer position must resolve only to objects valid in that
context.

Create, import, and rotate read plaintext from stdin. The authoring crate writes
age ciphertext into a private same-directory temporary file, fsyncs it,
round-trip decrypts it through an authorized identity, compares bounded stream
hashes and byte counts, and commits by atomic rename. Create refuses existing
paths. Rotate requires a safe single-link regular file and atomically replaces
it. Symlinked ancestry, traversal, unauthorized verification identities, failed
round trips, and concurrent destination substitution fail closed. A post-rename
directory-fsync failure is reported as durability-unknown because the atomic
change may already be visible.

Edit decrypts into a mode-0600 file inside a private ephemeral workspace. The
editor executable must be an explicit absolute path; no shell is invoked and the
environment is cleared. After a successful exit, the edited path is reopened
without following links and must remain a single-link regular file owned by the
current user with no group/other permissions. The normal verified replacement
transaction then re-encrypts it. The workspace is removed on every return path.
Editors remain in the threat model: a malicious editor can read plaintext and
may deliberately copy it elsewhere.

Lifecycle timestamps are strict offset-bearing RFC 3339 values. Rotation due
dates use checked elapsed-day arithmetic from the last rotation or creation
instant. Expiry takes precedence over rotation-due state. `secret list --due`
reports public due/expired metadata without reading ciphertext. Rekey and rotate
remain separate commands and concepts.

# ADR 0012: Authoring permissions use open descriptors

Status: accepted; implemented

Authoring creates encrypted staging files, public-output staging files, editor
workspace values, and deletion tombstone metadata. Permission changes for those
objects must be applied to the descriptor that created or opened the object,
not by resolving its pathname again. A pathname chmod creates a substitution
window in which a local process that can modify the containing directory could
cause a different file to receive the intended mode.

On Unix, the authoring crate therefore applies `0600`, `0644`, and `0700`
through already-open descriptors. Path-based compatibility helpers also reopen
with `O_NOFOLLOW|O_CLOEXEC` and verify regular-file/directory type, single-link
status where applicable, and current-user ownership before changing modes.
Temporary ciphertext remains private for its entire transaction; public output
is made `0644` only immediately before its atomic commit. This invariant is
covered by authoring tests that inspect the committed private and public modes.

The project still treats the authoring workstation and explicit editor as part
of the trusted computing base. Descriptor-relative mode changes reduce
filesystem substitution risk but do not make a compromised editor safe.

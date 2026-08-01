# Security policy

## Reporting a vulnerability

Do not open a public issue. Submit a report through
[GitHub's private vulnerability-report form for nix-seal](https://github.com/IanHollow/nix-seal/security/advisories/new).
If that is unavailable, contact the maintainer through the private address
listed on the GitHub profile and request an encrypted channel. Do not include
live secrets, private identities, or exploit output in ordinary email.

We aim to acknowledge reports within 3 business days, provide an initial
assessment within 7 business days, and publish a remediation timeline after
triage. Coordinated disclosure timing is agreed with the reporter. Good-faith
research that avoids privacy violations, persistence, destructive actions, and
third-party systems is welcome.

## Supported versions

No version is production-supported before 1.0 and the required independent
audit. After 1.0, the latest minor release and the preceding minor release
receive security fixes. Critical fixes may require an immediate upgrade.

## Handling requirements

Security reports and reproductions are least-access, encrypted at rest, and
removed after the retention period. Releases identify affected versions,
mitigations, key-rotation needs, and whether historical ciphertext should be
treated as exposed.

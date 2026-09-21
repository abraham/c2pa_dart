# Vendored conformance fixtures

These files are pinned test inputs for C2PA interoperability, cryptography,
malformed-input, trust-list, and report-schema validation. They are not shipped
as runtime library assets.

`provenance.json` records the upstream repository, immutable revision, original
path, byte size, SHA-256 digest, license, and canonical source URL for every
vendored file. `conformance_index.json` records the initial executable fixture
set and its expected outcomes.

The source repositories retain their own copyright:

- `c2pa-public-testfiles`: CC BY-SA 4.0. Files are copied unmodified from
  `c2pa-org/public-testfiles` commit
  `22beccc075707475b038d8789d0136c009e43143`.
- `c2pa-rs-0.90.22`: MIT OR Apache-2.0. Files are copied unmodified from tag
  `c2pa-v0.90.22`, commit `1a56d244ee77d7e58221eabebede4281d9e868a4`.
  Test private keys are intentionally not vendored.
- `c2pa-conformance-public`: CC BY 4.0. Trust lists are a pinned snapshot from
  commit `9de7006b0bcf18c385842467ba19eec15772336b`; tests must not treat them as
  globally current trust lists.
- `c2pa-conformance-tool-cli`: MIT OR Apache-2.0. Files are copied unmodified
  from commit `c09f0340524b088a81475f7b7eaab5ba7042772f`.

The corresponding upstream license files are included in each source
directory.

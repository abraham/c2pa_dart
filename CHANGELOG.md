# Changelog

This file records changes across the whole workspace. Each package also keeps
its own `packages/<name>/CHANGELOG.md` containing the subset that applies to it.

Entries are generated from commit messages by `scripts/update-changelogs.sh`.

## 0.1.0-dev.1

- Initial pure Dart port of the C2PA SDK, covering reading, validation,
  reporting, building, and signing.
- Added `c2pa_io`, `c2pa_codec`, `c2pa_crypto`, `c2pa_formats`, `c2pa`,
  `c2pa_testkit`, and `c2patool_dart`.
- Added a conformance gate that checks this implementation against the
  `c2patool` binary built from c2pa-rs.
- Licensed under MIT OR Apache-2.0, at the user's option.

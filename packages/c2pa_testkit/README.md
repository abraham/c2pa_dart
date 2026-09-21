# c2pa_testkit

Testing helpers for `c2pa_dart`: deterministic byte mutation, campaign
shrinking, fixture metadata, conformance/differential runners, fake signing,
synthetic byte sources, and performance measurements.

## Platforms

The main library supports Dart VM, Flutter, and web. VM process-based
differential helpers are exported separately from
`package:c2pa_testkit/c2pa_testkit_vm.dart`.

```dart
import 'package:c2pa_testkit/c2pa_testkit.dart';

final changed = ByteMutation.flip([0x00, 0x01], 1, mask: 0x01);
print(changed); // [0, 0]
```

See
[`example/mutate.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_testkit/example/mutate.dart).

## Security and defaults

The helpers do not enable network access or trust in the SDK. Fake signers are
for tests only and must never be used as production key handling. Differential
processes and external corpora are caller controlled. Vendored conformance
fixtures retain their upstream licenses and immutable provenance under
`test/fixtures/vendor`.

## Conformance gate

`tool/conformance.dart` compares this SDK against a pinned `c2patool`
reference build over a corpus signed by other producers, which is the only
check that can catch the SDK agreeing with itself while disagreeing with the
specification. `tool/conformance_pins.json` pins the reference build, its
checksum, the corpus commit, and each corpus size. The comparison itself is
`compareOracleReports`, exported from the main library and unit tested, so the
gate cannot silently stop detecting anything.

## Package relationships

`c2pa_testkit` depends on all core sibling packages and is intended for their
consumers' tests, not production runtime logic. `c2patool_dart` is the
separate user-facing CLI.

## Compatibility and limitations

The compatibility target and fixture baseline is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
The testkit exercises tracked conformance behavior but does not imply complete
parity for formats marked partial, including most container mutation paths or
Brotli-compressed manifest generation. The repository's vendored conformance
corpora are excluded from the published package; applications must provide
their own fixtures when using fixture-loading and differential helpers.

Licensed under **MIT OR Apache-2.0**, at your option. See
[`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_testkit/LICENSE),
[`LICENSE-MIT`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_testkit/LICENSE-MIT),
and
[`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_testkit/LICENSE-APACHE).
Copyright is held by contributors to
c2pa_dart.

Vendored fixtures remain under their documented upstream terms.

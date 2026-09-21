# c2pa

The high-level, pure Dart C2PA SDK. It reads and validates manifests, builds
and signs claims, manages assertions and resources, exports reports, handles
working archives, and supports CAWG identity workflows.

## Platforms

The public library supports Dart VM, Flutter, and web. Use memory byte sources
everywhere, `package:c2pa_io/c2pa_io_vm.dart` for VM files, or
`package:c2pa_io/c2pa_io_web.dart` for browser `Blob` input.

```dart
import 'package:c2pa/c2pa.dart';

final reader = await C2paReader.fromSource(
  source: MemoryByteSource(assetBytes),
  fileName: 'asset.jpg',
  context: C2paContext(),
);
print(reader.validationResults);
```

See
[`example/c2pa.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa/example/c2pa.dart)
for a VM file example.
Signing keys remain caller owned; configure a `C2paSigner` backed by a
keystore, HSM, or service when building manifests.

## Secure defaults

`C2paContext()` validates structure and cryptography but does not grant trust,
install a network resolver, fetch revocation data, or consult the operating
system trust store. Remote manifests require network access to be enabled, an
explicit resolver, and a restrictive `RemoteManifestPolicy`. Trust anchors and
intermediates are caller supplied. Reports keep validity and trust distinct.

Resource sizes, recursion, assertion counts, ingredient depth, and Brotli
expansion are bounded by `C2paSettings`.

## Package relationships

`c2pa` is the application-facing SDK over `c2pa_io`, `c2pa_codec`,
`c2pa_crypto`, and `c2pa_formats`. Use `c2pa_testkit` for tests and
`c2patool_dart` for VM command-line workflows.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
Claim v1 read/validation and claim v2 create/read/validation are supported.
Compressed manifests are bounded decode-only; builders do not generate
Brotli-compressed stores. Standalone C2PA is complete for the tracked
baseline, while most asset-container mutation paths have partial format parity
and should be tested against an application's corpus. API stability and full
cross-format parity are not claimed before 1.0.

Licensed under the **MIT License** ([`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa/LICENSE)).
As an alternative, you may instead use this package under the **Apache
License, Version 2.0**
([`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa/LICENSE-APACHE)), so the package is offered
as `MIT OR Apache-2.0`, at your option. Copyright is held by contributors to
c2pa_dart.

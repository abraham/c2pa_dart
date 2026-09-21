# c2pa_io

Bounded random-access byte I/O used by the pure Dart C2PA packages. It provides
memory sources and sinks on every Dart platform, `RandomAccessFile` adapters on
the Dart VM, and browser `Blob` input.

## Platforms

- Dart VM and Flutter: memory I/O plus `package:c2pa_io/c2pa_io_vm.dart`
- Web: memory I/O plus `package:c2pa_io/c2pa_io_web.dart`

```dart
import 'package:c2pa_io/c2pa_io.dart';

final source = MemoryByteSource([0x01, 0x02, 0x03]);
final bytes = await source.read(ByteRange(1, 3));
```

See
[`example/c2pa_io.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_io/example/c2pa_io.dart)
for a complete example.

## Security and limits

Reads are range checked, exact-length, and copy their results. Coordinates are
limited to JavaScript's exactly representable integer range. VM file sources
detect length changes, while file sinks stage beside the destination before a
filesystem rename; replacement atomicity follows the host filesystem. This
package performs no network access.

## Package relationships

`c2pa_io` is the lowest-level workspace package. `c2pa_codec`,
`c2pa_formats`, `c2pa_crypto`, and `c2pa` build on these byte-source and sink
interfaces.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
This package provides I/O primitives, not C2PA parsing or validation. Browser
support uses `Blob`; writable browser filesystem integration remains the
application's responsibility.

Licensed under the **MIT License** ([`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_io/LICENSE)).
As an alternative, you may instead use this package under the **Apache
License, Version 2.0**
([`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_io/LICENSE-APACHE)), so the package is offered
as `MIT OR Apache-2.0`, at your option. Copyright is held by contributors to
c2pa_dart.

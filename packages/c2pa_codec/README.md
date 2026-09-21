# c2pa_codec

Deterministic CBOR, COSE structures, ISO boxes, JUMBF, and bounded Brotli
decoding for the Dart C2PA implementation.

## Platforms

The public library supports the Dart VM, Flutter, and web. It uses `c2pa_io`
for bounded byte access and has no native runtime dependency.

```dart
import 'package:c2pa_codec/c2pa_codec.dart';

final encoded = encodeCbor({'answer': 42});
final decoded = decodeCbor(encoded);
```

See
[`example/c2pa_codec.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_codec/example/c2pa_codec.dart).

## Security and defaults

Decoders reject trailing data and malformed sizes, enforce configurable
nesting and expansion limits, and do not access the network. Strict CBOR
decoding requires canonical map order by default; callers parsing compatible
legacy data must opt into relaxed options explicitly.

## Package relationships

`c2pa_codec` depends on `c2pa_io`. It supplies encoding and container
primitives to `c2pa_crypto`, `c2pa_formats`, and the high-level `c2pa` SDK.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
The Brotli implementation decodes bounded compressed manifest data but does
not encode Brotli streams, so compressed-manifest generation parity is not
claimed. Format-level parity belongs to `c2pa_formats` and is partial for a
number of containers.

The vendored Brotli decoder retains its own MIT license under
`lib/src/brotli_vendor`. This package is licensed under the **MIT License**
([`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_codec/LICENSE)). As an alternative, you may instead use
this package under the **Apache License, Version 2.0**
([`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_codec/LICENSE-APACHE)), so the package is offered
as `MIT OR Apache-2.0`, at your option. Copyright is held by contributors to
c2pa_dart.

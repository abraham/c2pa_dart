# c2pa_formats

Asset-container detection, C2PA manifest extraction and mutation, remote
reference metadata, and hard-binding byte layouts for the Dart C2PA SDK.

## Platforms

The package supports Dart VM, Flutter, and web through `c2pa_io`. It operates
on random-access byte sources and sinks rather than filesystem APIs.

```dart
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';

final result = await AssetHandlerRegistry().detect(
  MemoryByteSource(const []),
  fileExtension: 'jpg',
);
print(result.format);
```

See
[`example/c2pa_formats.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_formats/example/c2pa_formats.dart).

## Security and defaults

Parsing and mutation are bounded by source sizes and checked ranges. ZIP paths
and collection layouts are validated against traversal. This package does not
perform network access; remote references are metadata only. Preserve the
original asset when adopting a mutation workflow and validate the result.

## Package relationships

`c2pa_formats` depends on `c2pa_io` and `c2pa_codec`. The high-level `c2pa`
reader and builder select these handlers automatically.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
Standalone C2PA support is complete for the tracked baseline. JPEG, PNG,
TIFF/DNG, GIF, RIFF, MP3, FLAC, SVG, ISO BMFF, JPEG XL, and ZIP-family
read/write paths are useful but full baseline parity is not claimed. PDF
reading is tracked as complete; PDF mutation remains partial. Brotli
compression is handled above this layer and generation is not available.

Licensed under the **MIT License** ([`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_formats/LICENSE)).
As an alternative, you may instead use this package under the **Apache
License, Version 2.0**
([`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_formats/LICENSE-APACHE)), so the package is offered
as `MIT OR Apache-2.0`, at your option. Copyright is held by contributors to
c2pa_dart.

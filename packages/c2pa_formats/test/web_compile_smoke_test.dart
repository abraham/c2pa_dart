import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  test(
    'ISO BMFF APIs compile and run without native 64-bit integers',
    () async {
      final bytes = Uint8List.fromList(<int>[
        0,
        0,
        0,
        16,
        ...'ftyp'.codeUnits,
        ...'mp42'.codeUnits,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        8,
        ...'free'.codeUnits,
      ]);
      final source = MemoryByteSource(bytes);

      expect(
        await const IsoBmffAssetHandler(format: AssetFormat.mp4).detect(source),
        isTrue,
      );
      final layout = await const IsoBmffHashLayoutReader().read(
        source,
        const <IsoBmffExclusion>[],
      );
      expect(layout.events.whereType<IsoBmffOffsetDigestEvent>(), hasLength(2));
    },
  );
}

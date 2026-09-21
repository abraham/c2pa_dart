import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  final fixtures = <AssetFormat, String>{
    AssetFormat.mp4: 'mp42',
    AssetFormat.mov: 'qt  ',
    AssetFormat.m4a: 'M4A ',
    AssetFormat.avif: 'avif',
    AssetFormat.heif: 'mif1',
    AssetFormat.heic: 'heic',
  };

  group('IsoBmffAssetHandler', () {
    for (final entry in fixtures.entries) {
      test('detects and round-trips ${entry.key.name}', () async {
        final handler = IsoBmffAssetHandler(format: entry.key);
        final ftyp = _ftyp(entry.value);
        final free = _box('free', const [0xaa, 0xbb, 0xcc]);
        final mdat = _box('mdat', const [1, 2, 3, 4]);
        final source = [...ftyp, ...free, ...mdat];
        final manifest = Uint8List.fromList(
          List<int>.generate(257, (index) => index & 0xff),
        );
        final output = MemoryByteSink();

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        expect(written.sublist(0, ftyp.length), ftyp);
        expect(written.sublist(ftyp.length + 45 + manifest.length), [
          ...free,
          ...mdat,
        ]);
        expect(
          String.fromCharCodes(
            written.sublist(ftyp.length + 4, ftyp.length + 8),
          ),
          'uuid',
        );
        expect(
          written.sublist(ftyp.length + 8, ftyp.length + 24),
          IsoBmffAssetHandler.c2paUuid,
        );
        expect(
          String.fromCharCodes(
            written.sublist(ftyp.length + 28, ftyp.length + 36),
          ),
          'manifest',
        );
      });
    }

    test('routes representative brands through the registry', () async {
      final registry = AssetHandlerRegistry();
      for (final entry in fixtures.entries) {
        final result = await registry.detect(
          MemoryByteSource([
            ..._ftyp(entry.value),
            ..._box('mdat', const [1]),
          ]),
        );
        expect(result.format, entry.key, reason: entry.value);
        expect(result.method, AssetDetectionMethod.magicBytes);
      }
    });

    test('uses compatible brands for specific image routing', () async {
      final registry = AssetHandlerRegistry();
      final avif = await registry.detect(
        MemoryByteSource([
          ..._ftyp('mif1', compatible: const ['avif']),
          ..._box('free', const []),
        ]),
      );
      final heic = await registry.detect(
        MemoryByteSource([
          ..._ftyp('mif1', compatible: const ['heic']),
          ..._box('free', const []),
        ]),
      );

      expect(avif.format, AssetFormat.avif);
      expect(heic.format, AssetFormat.heic);
    });

    test('replaces and removes while preserving unrelated boxes', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final ftyp = _ftyp('mp42');
      final before = _box('free', const [8, 7, 6]);
      final after = _box('mdat', const [5, 4, 3, 2, 1]);
      final source = [
        ...ftyp,
        ...before,
        ..._c2paBox(const [1, 2]),
        ...after,
      ];
      final replacement = Uint8List.fromList(const [9, 10, 11, 12]);
      final replaced = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(source),
        replacement,
        replaced,
      );
      expect(replaced.toBytes(), [
        ...ftyp,
        ...before,
        ..._c2paBox(replacement),
        ...after,
      ]);

      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(replaced.toBytes()),
        removed,
      );
      expect(removed.toBytes(), [...ftyp, ...before, ...after]);
    });

    test('parses extended-size and size-to-EOF top-level boxes', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final ftyp = _ftyp('mp42');
      final wide = _box('wide', const [1, 2, 3], extended: true);
      final mdat = _box('mdat', const [4, 5, 6], toEnd: true);
      final source = [...ftyp, ...wide, ...mdat];

      final boxes = await handler.getTopLevelBoxes(MemoryByteSource(source));

      expect(boxes.map((box) => box.type), ['ftyp', 'wide', 'mdat']);
      expect(boxes[1].usesExtendedSize, isTrue);
      expect(boxes[1].headerSize, 16);
      expect(boxes[2].extendsToEnd, isTrue);
      expect(boxes[2].end, source.length);

      final output = MemoryByteSink();
      await handler.embedManifest(
        MemoryByteSource(source),
        Uint8List.fromList(const [9]),
        output,
      );
      expect(output.toBytes().sublist(ftyp.length + 46), [...wide, ...mdat]);
    });

    test('extracts an extended-size C2PA UUID box', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final manifest = Uint8List.fromList(const [1, 3, 5, 7]);
      final source = [
        ..._ftyp('mp42'),
        ..._c2paBox(manifest, extended: true),
        ..._box('mdat', const [9]),
      ];

      expect(await handler.extractManifest(MemoryByteSource(source)), manifest);
      final boxes = await handler.getTopLevelBoxes(MemoryByteSource(source));
      expect(boxes[1].usesExtendedSize, isTrue);
      expect(boxes[1].headerSize, 16);
    });

    test('exposes box lists and manifest DataHash exclusion', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final ftyp = _ftyp('mp42');
      final manifestBox = _c2paBox(const [1, 2, 3]);
      final source = [
        ...ftyp,
        ...manifestBox,
        ..._box('mdat', const [4]),
      ];

      final boxes = await AssetHandlerRegistry().getTopLevelBoxes(
        MemoryByteSource(source),
        fileExtension: '.MP4',
      );
      final layout = await handler.getDataHashLayout(MemoryByteSource(source));

      expect(boxes.map((box) => box.type), ['ftyp', 'uuid', 'mdat']);
      expect(boxes[1].userType, IsoBmffAssetHandler.c2paUuid);
      expect(layout.insertionOffset, ftyp.length);
      expect(layout.exclusions.single.range, boxes[1].range);
      expect(
        [
          for (final range in layout.includedRanges)
            ...source.sublist(range.start, range.end),
        ],
        [
          ...ftyp,
          ..._box('mdat', const [4]),
        ],
      );
      expect(handler.capabilities.canListTopLevelBoxes, isTrue);
    });

    test('reports the ftyp insertion point when no manifest exists', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final ftyp = _ftyp('mp42');
      final layout = await handler.getDataHashLayout(
        MemoryByteSource([...ftyp, ..._box('free', const [])]),
      );

      expect(layout.insertionOffset, ftyp.length);
      expect(layout.exclusions, isEmpty);
    });

    test(
      'rejects duplicate and nested C2PA UUID boxes before output',
      () async {
        const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
        final duplicate = [
          ..._ftyp('mp42'),
          ..._c2paBox(const [1]),
          ..._c2paBox(const [2]),
        ];
        final nested = [
          ..._ftyp('mp42'),
          ..._box('moov', _c2paBox(const [1])),
        ];
        final duplicateOutput = MemoryByteSink();
        final nestedOutput = MemoryByteSink();

        await expectLater(
          handler.replaceManifest(
            MemoryByteSource(duplicate),
            Uint8List.fromList(const [3]),
            duplicateOutput,
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        await expectLater(
          handler.embedManifest(
            MemoryByteSource(nested),
            Uint8List.fromList(const [3]),
            nestedOutput,
          ),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        expect(duplicateOutput.toBytes(), isEmpty);
        expect(nestedOutput.toBytes(), isEmpty);
      },
    );

    test('rejects malformed box sizes, ftyp, and trailing bytes', () {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final cases = <List<int>>[
        [..._ftyp('mp42'), 0, 0, 0, 7, ...'free'.codeUnits],
        [
          ..._ftyp('mp42'),
          0,
          0,
          0,
          1,
          ...'free'.codeUnits,
          0,
          0,
          0,
          0,
          0,
          0,
          0,
          15,
        ],
        [..._ftyp('mp42'), 0, 0, 0, 20, ...'free'.codeUnits],
        [..._ftyp('mp42'), 1, 2, 3],
        [
          ..._ftyp('mp42'),
          0,
          0,
          0,
          1,
          ...'wide'.codeUnits,
          0,
          0x20,
          0,
          0,
          0,
          0,
          0,
          0,
        ],
        _box('free', const [1, 2, 3, 4]),
        _box('ftyp', const [1, 2, 3]),
      ];

      for (final source in cases) {
        expect(
          handler.extractManifest(MemoryByteSource(source)),
          throwsA(isA<AssetFormatException>()),
        );
      }
    });

    test('rejects unsupported C2PA purpose and auxiliary offset', () {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final wrongPurpose = [
        ..._ftyp('mp42'),
        ..._c2paBox(const [1], purpose: 'merkle'),
      ];
      final auxiliary = [
        ..._ftyp('mp42'),
        ..._c2paBox(const [1], auxiliaryOffset: 1),
      ];

      expect(
        handler.extractManifest(MemoryByteSource(wrongPurpose)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(auxiliary)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects mutation of fragmented streams', () {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final source = [
        ..._ftyp('mp42'),
        ..._box('moov', _box('mvex', const [])),
        ..._box('moof', const []),
        ..._box('mdat', const [1]),
      ];

      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [2]),
          MemoryByteSink(),
        ),
        throwsA(isA<UnsupportedIsoBmffFeatureException>()),
      );
    });

    test('enforces source, output, manifest, and box-count limits', () {
      final source = [
        ..._ftyp('mp42'),
        ..._box('free', const []),
        ..._box('mdat', const [1]),
      ];

      expect(
        const IsoBmffAssetHandler(
          format: AssetFormat.mp4,
          maxManifestSize: 2,
        ).embedManifest(
          MemoryByteSource(source),
          Uint8List(3),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        IsoBmffAssetHandler(
          format: AssetFormat.mp4,
          maxSourceSize: source.length - 1,
        ).extractManifest(MemoryByteSource(source)),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        IsoBmffAssetHandler(
          format: AssetFormat.mp4,
          maxOutputSize: source.length,
        ).embedManifest(
          MemoryByteSource(source),
          Uint8List(1),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const IsoBmffAssetHandler(
          format: AssetFormat.mp4,
          maxBoxCount: 2,
        ).getTopLevelBoxes(MemoryByteSource(source)),
        throwsA(isA<SegmentLimitExceededException>()),
      );
    });

    test('propagates sink failures only after validation', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final source = [
        ..._ftyp('mp42'),
        ..._box('mdat', const [1, 2]),
      ];
      final sink = _FailingSink();

      await expectLater(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [3]),
          sink,
        ),
        throwsA(isA<StateError>()),
      );
      expect(sink.appendCalls, 1);
    });

    test('round-trips, replaces, and removes an XMP UUID reference', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final keep = _box('free', const [7, 8, 9]);
      final source = [
        ..._ftyp('mp42'),
        ...keep,
        ..._box('mdat', const [1, 2]),
      ];
      final embedded = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(source),
        'https://example.com/one',
        embedded,
      );
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(embedded.toBytes()),
        ),
        'https://example.com/one',
      );
      expect(embedded.toBytes(), containsAllInOrder(keep));

      final replaced = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(embedded.toBytes()),
        'https://example.com/two',
        replaced,
      );
      final removed = MemoryByteSink();
      await handler.removeRemoteManifestReference(
        MemoryByteSource(replaced.toBytes()),
        removed,
      );
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(removed.toBytes()),
        ),
        isNull,
      );
      expect(removed.toBytes(), containsAllInOrder(keep));
    });

    test('rejects duplicate XMP UUID boxes and propagates sink failures', () {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final xmp = _uuidBox(IsoBmffAssetHandler.xmpUuid, '<rdf:RDF/>'.codeUnits);
      final duplicate = [..._ftyp('mp42'), ...xmp, ...xmp];
      expect(
        handler.readXmp(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.updateRemoteManifestReference(
          MemoryByteSource([..._ftyp('mp42'), ..._box('free', const [])]),
          'https://example.com',
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('adjusts absolute stco offsets when inserting XMP', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final ftyp = _ftyp('mp42');
      final placeholder = _box('stco', [
        0,
        0,
        0,
        0,
        ..._uint32(1),
        ..._uint32(0),
      ]);
      final moov = _box(
        'moov',
        _box('trak', _box('mdia', _box('minf', _box('stbl', placeholder)))),
      );
      final mdat = _box('mdat', const [1, 2, 3]);
      final source = Uint8List.fromList([...ftyp, ...moov, ...mdat]);
      final mdatOffset = ftyp.length + moov.length + 8;
      final stcoType = _indexOfAscii(source, 'stco');
      ByteData.sublistView(source)
          .setUint32(stcoType + 12, mdatOffset, Endian.big);

      final output = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(source),
        'https://example.com/manifest',
        output,
      );
      final written = output.toBytes();
      final writtenStco = _indexOfAscii(written, 'stco');
      final writtenMdat = _indexOfAscii(written, 'mdat') + 4;
      expect(
        ByteData.sublistView(written).getUint32(writtenStco + 12, Endian.big),
        writtenMdat,
      );
    });

    test('adjusts co64 offsets above the JavaScript exact-int range', () async {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final originalOffset = BigInt.parse('9007199254740991');
      final co64 = _box('co64', [
        0,
        0,
        0,
        0,
        ..._uint32(1),
        ..._bigUint64(originalOffset),
      ]);
      final source = Uint8List.fromList([
        ..._ftyp('mp42'),
        ..._box(
          'moov',
          _box('trak', _box('mdia', _box('minf', _box('stbl', co64)))),
        ),
        ..._box('mdat', const [1]),
      ]);
      final output = MemoryByteSink();

      await handler.updateRemoteManifestReference(
        MemoryByteSource(source),
        'https://example.com/manifest',
        output,
      );

      final written = output.toBytes();
      final adjustment = written.length - source.length;
      final co64Type = _indexOfAscii(written, 'co64');
      expect(
        written.sublist(co64Type + 12, co64Type + 20),
        _bigUint64(originalOffset + BigInt.from(adjustment)),
      );
    });

    test('retains strict co64 overflow rejection with BigInt arithmetic', () {
      const handler = IsoBmffAssetHandler(format: AssetFormat.mp4);
      final co64 = _box('co64', [
        0,
        0,
        0,
        0,
        ..._uint32(1),
        ..._bigUint64(BigInt.parse('9223372036854775807')),
      ]);
      final source = <int>[
        ..._ftyp('mp42'),
        ..._box(
          'moov',
          _box('trak', _box('mdia', _box('minf', _box('stbl', co64)))),
        ),
        ..._box('mdat', const [1]),
      ];

      expect(
        handler.updateRemoteManifestReference(
          MemoryByteSource(source),
          'https://example.com/manifest',
          MemoryByteSink(),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });
  });
}

List<int> _ftyp(String major, {List<String> compatible = const []}) =>
    _box('ftyp', [
      ...major.codeUnits,
      0,
      0,
      0,
      0,
      for (final brand in compatible) ...brand.codeUnits,
    ]);

List<int> _c2paBox(
  List<int> manifest, {
  String purpose = 'manifest',
  int auxiliaryOffset = 0,
  bool extended = false,
}) => _box('uuid', [
  ...IsoBmffAssetHandler.c2paUuid,
  0,
  0,
  0,
  0,
  ...purpose.codeUnits,
  0,
  ..._uint64(auxiliaryOffset),
  ...manifest,
], extended: extended);

List<int> _box(
  String type,
  List<int> payload, {
  bool extended = false,
  bool toEnd = false,
}) {
  if (toEnd) return [0, 0, 0, 0, ...type.codeUnits, ...payload];
  final size = (extended ? 16 : 8) + payload.length;
  if (extended) {
    return [0, 0, 0, 1, ...type.codeUnits, ..._uint64(size), ...payload];
  }

  return [..._uint32(size), ...type.codeUnits, ...payload];
}

List<int> _uuidBox(List<int> uuid, List<int> payload) => [
  ..._uint32(24 + payload.length),
  ...'uuid'.codeUnits,
  ...uuid,
  ...payload,
];

int _indexOfAscii(List<int> bytes, String value) {
  final pattern = value.codeUnits;
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  return -1;
}

List<int> _uint32(int value) => [
  value >> 24 & 0xff,
  value >> 16 & 0xff,
  value >> 8 & 0xff,
  value & 0xff,
];

List<int> _bigUint64(BigInt value) {
  final bytes = List<int>.filled(8, 0);
  var remaining = value;
  for (var index = 7; index >= 0; index--) {
    bytes[index] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
  return bytes;
}

List<int> _uint64(int value) => [0, 0, 0, 0, ..._uint32(value)];

final class _FailingSink implements WritableByteSink {
  int appendCalls = 0;

  @override
  Future<int> get length async => 0;

  @override
  Future<void> append(List<int> bytes) async {
    appendCalls++;
    throw StateError('sink failed');
  }

  @override
  Future<void> close() async {}
}

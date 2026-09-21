import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  const handler = JpegXlAssetHandler();

  group('JpegXlAssetHandler', () {
    test('detects container form and rejects a raw codestream', () async {
      final source = _container([
        _box('jxlc', const [0xff, 0x0a, 1]),
      ]);

      expect(await handler.detect(MemoryByteSource(source)), isTrue);
      expect(
        await handler.detect(
          MemoryByteSource(JpegXlAssetHandler.rawCodestreamSignature),
        ),
        isFalse,
      );
      expect(
        handler.extractManifest(
          MemoryByteSource(JpegXlAssetHandler.rawCodestreamSignature),
        ),
        throwsA(isA<UnsupportedJpegXlCodestreamException>()),
      );

      final registry = AssetHandlerRegistry();
      expect(
        (await registry.detect(MemoryByteSource(source))).format,
        AssetFormat.jpegXl,
      );
      expect(
        (await registry.detect(
          MemoryByteSource(const []),
          mimeType: ' IMAGE/JXL ',
        )).format,
        AssetFormat.jpegXl,
      );
      expect(
        (await registry.detect(
          MemoryByteSource(const []),
          fileExtension: '.JXL',
        )).format,
        AssetFormat.jpegXl,
      );
    });

    test('embeds after ftyp and round-trips a complete C2PA jumb', () async {
      final metadata = _box('Exif', const [1, 2, 3]);
      final codestream = _box('jxlc', const [0xff, 0x0a, 4, 5]);
      final source = _container([metadata, codestream]);
      final manifest = Uint8List.fromList(_c2paJumb(const [9, 8, 7]));
      final output = MemoryByteSink();

      await handler.embedManifest(MemoryByteSource(source), manifest, output);

      final signatureLength = JpegXlAssetHandler.containerSignature.length;
      final ftypLength = _jxlFtyp().length;
      final written = output.toBytes();
      expect(
        await handler.extractManifest(MemoryByteSource(written)),
        manifest,
      );
      expect(written.sublist(0, signatureLength + ftypLength), [
        ...JpegXlAssetHandler.containerSignature,
        ..._jxlFtyp(),
      ]);
      expect(
        written.sublist(
          signatureLength + ftypLength,
          signatureLength + ftypLength + manifest.length,
        ),
        manifest,
      );
      expect(written.sublist(signatureLength + ftypLength + manifest.length), [
        ...metadata,
        ...codestream,
      ]);
    });

    test('replaces and removes only the C2PA-labelled jumb box', () async {
      final unrelated = _labelledJumb('exif', const [4, 5]);
      final oldManifest = _c2paJumb(const [1, 2]);
      final codestream = _box('jxlc', const [0xff, 0x0a, 3]);
      final source = _container([unrelated, oldManifest, codestream]);
      final replacement = Uint8List.fromList(_c2paJumb(const [8, 9, 10]));
      final replaced = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(source),
        replacement,
        replaced,
      );
      expect(
        replaced.toBytes(),
        _container([unrelated, replacement, codestream]),
      );

      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(replaced.toBytes()),
        removed,
      );
      expect(removed.toBytes(), _container([unrelated, codestream]));
    });

    test('supports extended and size-to-EOF top-level boxes', () async {
      final metadata = _box('xml ', const [1, 2], extended: true);
      final codestream = _box('jxlc', const [0xff, 0x0a, 3, 4], toEnd: true);
      final source = _container([metadata, codestream]);
      final boxes = await handler.getTopLevelBoxes(MemoryByteSource(source));

      expect(boxes.map((box) => box.type), ['JXL ', 'ftyp', 'xml ', 'jxlc']);
      expect(boxes[2].usesExtendedSize, isTrue);
      expect(boxes[2].headerSize, 16);
      expect(boxes[3].extendsToEnd, isTrue);
      expect(boxes[3].end, source.length);

      final output = MemoryByteSink();
      final manifest = Uint8List.fromList(_c2paJumb(const [6]));
      await handler.embedManifest(MemoryByteSource(source), manifest, output);
      expect(
        output.toBytes().sublist(
          JpegXlAssetHandler.containerSignature.length + _jxlFtyp().length,
        ),
        [...manifest, ...metadata, ...codestream],
      );
    });

    test('extracts an extended-size C2PA jumb box', () async {
      final manifest = Uint8List.fromList(
        _c2paJumb(const [1, 2, 3], extended: true),
      );
      final source = _container([
        manifest,
        _box('jxlc', const [0xff, 0x0a]),
      ]);

      expect(await handler.extractManifest(MemoryByteSource(source)), manifest);
    });

    test('rejects duplicate C2PA jumb boxes before writing', () async {
      final source = _container([
        _c2paJumb(const [1]),
        _labelledJumb('exif', const [2]),
        _c2paJumb(const [3]),
        _box('jxlc', const [0xff, 0x0a]),
      ]);
      final output = MemoryByteSink();

      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(source),
          Uint8List.fromList(_c2paJumb(const [4])),
          output,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(output.toBytes(), isEmpty);
    });

    test('rejects malformed signatures, boxes, and C2PA labels', () {
      final malformedCases = <List<int>>[
        [
          ...JpegXlAssetHandler.containerSignature.sublist(0, 11),
          0,
          ..._jxlFtyp(),
          ..._box('jxlc', const [1]),
        ],
        [
          ...JpegXlAssetHandler.containerSignature,
          ..._jxlFtyp(),
          0,
          0,
          0,
          7,
          ...'free'.codeUnits,
        ],
        [
          ...JpegXlAssetHandler.containerSignature,
          ..._jxlFtyp(),
          0,
          0,
          0,
          20,
          ...'free'.codeUnits,
        ],
        [
          ...JpegXlAssetHandler.containerSignature,
          ..._box('ftyp', [...'nope'.codeUnits, 0, 0, 0, 0]),
          ..._box('jxlc', const [1]),
        ],
        [
          ...JpegXlAssetHandler.containerSignature,
          ..._jxlFtyp(),
          ..._box('free', const []),
        ],
        [
          ...JpegXlAssetHandler.containerSignature,
          ..._jxlFtyp(),
          ..._malformedC2paJumb(),
          ..._box('jxlc', const [1]),
        ],
      ];

      for (final source in malformedCases) {
        expect(
          handler.extractManifest(MemoryByteSource(source)),
          throwsA(isA<AssetFormatException>()),
          reason: source.toString(),
        );
      }
    });

    test('rejects 64-bit size overflow', () {
      final source = [
        ...JpegXlAssetHandler.containerSignature,
        ..._jxlFtyp(),
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
      ];

      expect(
        handler.getTopLevelBoxes(MemoryByteSource(source)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('validates complete manifest input before mutating', () async {
      final source = _container([
        _box('jxlc', const [0xff, 0x0a]),
      ]);
      final output = MemoryByteSink();

      await expectLater(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(_box('jumb', const [1, 2, 3])),
          output,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(output.toBytes(), isEmpty);
    });

    test('reports physical and synthetic BoxHash layouts', () async {
      final source = _container([
        _box('Exif', const [1]),
        _box('jxlc', const [2]),
      ]);
      final absent = await handler.getBoxHashLayout(MemoryByteSource(source));

      expect(absent.entries.map((entry) => entry.names.single), [
        'JXL ',
        'ftyp',
        'C2PA',
        'Exif',
        'jxlc',
      ]);
      final synthetic = absent.entries.singleWhere((entry) => entry.synthetic);
      expect(synthetic.excluded, isTrue);
      expect(synthetic.range.isEmpty, isTrue);
      expect(
        synthetic.range.start,
        JpegXlAssetHandler.containerSignature.length + _jxlFtyp().length,
      );

      final manifest = _c2paJumb(const [7]);
      final embedded = _container([
        manifest,
        _box('jxlc', const [2]),
      ]);
      final present = await handler.getBoxHashLayout(
        MemoryByteSource(embedded),
      );
      final c2pa = present.entries.singleWhere(
        (entry) => entry.names.single == 'C2PA',
      );
      expect(c2pa.synthetic, isFalse);
      expect(embedded.sublist(c2pa.range.start, c2pa.range.end), manifest);
      expect(handler.capabilities.canProvideDataHashLayout, isFalse);
      expect(handler.capabilities.canProvideBoxHashLayout, isTrue);
      expect(
        AssetHandlerRegistry().getDataHashLayout(
          MemoryByteSource(source),
          mimeType: 'image/jxl',
        ),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
    });

    test('enforces source, output, manifest, and box-count limits', () {
      final source = _container([
        _box('free', const []),
        _box('jxlc', const [1]),
      ]);
      final manifest = Uint8List.fromList(_c2paJumb(const [2]));

      expect(
        JpegXlAssetHandler(
          maxManifestSize: manifest.length - 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        JpegXlAssetHandler(maxSourceSize: source.length - 1)
            .extractManifest(MemoryByteSource(source)),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        JpegXlAssetHandler(
          maxOutputSize: source.length,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const JpegXlAssetHandler(maxBoxCount: 3)
            .getTopLevelBoxes(MemoryByteSource(source)),
        throwsA(isA<SegmentLimitExceededException>()),
      );
    });

    test('propagates sink failures after staged validation', () {
      final source = _container([
        _box('jxlc', const [1]),
      ]);
      final sink = _FailingSink();

      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(_c2paJumb(const [2])),
          sink,
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('round-trips, replaces, and removes an XML XMP reference', () async {
      final keep = _box('Exif', const [7, 8, 9]);
      final source = _container([
        keep,
        _box('jxlc', const [1, 2]),
      ]);
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
      expect(_containsBytes(embedded.toBytes(), keep), isTrue);

      final replaced = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(embedded.toBytes()),
        'self#jumbf=c2pa/two',
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
      expect(_containsBytes(removed.toBytes(), keep), isTrue);
    });

    test('rejects duplicate, malformed, compressed, and oversized XMP', () {
      final xml = _box('xml ', utf8.encode(_minimalXmp));
      expect(
        handler.readXmp(
          MemoryByteSource(
            _container([
              xml,
              xml,
              _box('jxlc', const [1]),
            ]),
          ),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.readRemoteManifestReference(
          MemoryByteSource(
            _container([
              _box('xml ', utf8.encode('<bad')),
              _box('jxlc', const [1]),
            ]),
          ),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.readXmp(
          MemoryByteSource(
            _container([
              _box('brob', [...'xml '.codeUnits, 1, 2, 3]),
              _box('jxlc', const [1]),
            ]),
          ),
        ),
        throwsA(isA<UnsupportedJpegXlFeatureException>()),
      );
      expect(
        const JpegXlAssetHandler(maxRemoteReferenceLength: 3)
            .updateRemoteManifestReference(
              MemoryByteSource(
                _container([
                  _box('jxlc', const [1]),
                ]),
              ),
              'long',
              MemoryByteSink(),
            ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        handler.updateRemoteManifestReference(
          MemoryByteSource(
            _container([
              _box('jxlc', const [1]),
            ]),
          ),
          'https://example.com',
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });
  });
}

const _minimalXmp =
    '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description/></rdf:RDF></x:xmpmeta>';

List<int> _container(List<List<int>> boxes) => [
  ...JpegXlAssetHandler.containerSignature,
  ..._jxlFtyp(),
  for (final box in boxes) ...box,
];

List<int> _jxlFtyp() =>
    _box('ftyp', [...'jxl '.codeUnits, 0, 0, 0, 0, ...'jxl '.codeUnits]);

List<int> _c2paJumb(List<int> extra, {bool extended = false}) =>
    _labelledJumb('c2pa', extra, extended: extended);

List<int> _labelledJumb(
  String label,
  List<int> extra, {
  bool extended = false,
}) {
  final jumd = _box('jumd', [
    ...List<int>.filled(16, 0),
    0x03,
    ...label.codeUnits,
    0,
  ]);
  return _box('jumb', [...jumd, ...extra], extended: extended);
}

List<int> _malformedC2paJumb() {
  final jumd = _box('jumd', [
    ...List<int>.filled(16, 0),
    0x03,
    ...'c2pa'.codeUnits,
    0,
  ]);
  jumd[3] = 31;
  return _box('jumb', jumd);
}

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

List<int> _uint32(int value) => [
  value >> 24 & 0xff,
  value >> 16 & 0xff,
  value >> 8 & 0xff,
  value & 0xff,
];

List<int> _uint64(int value) => [0, 0, 0, 0, ..._uint32(value)];

bool _containsBytes(List<int> bytes, List<int> pattern) {
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

final class _FailingSink implements WritableByteSink {
  @override
  Future<int> get length async => 0;

  @override
  Future<void> append(List<int> bytes) async {
    throw StateError('sink failed');
  }

  @override
  Future<void> close() async {}
}

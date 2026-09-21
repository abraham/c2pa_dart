import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('GifAssetHandler', () {
    const handler = GifAssetHandler();

    test('detects both supported GIF versions', () async {
      expect(await handler.detect(MemoryByteSource(_baseGif())), isTrue);
      expect(
        await handler.detect(MemoryByteSource(_baseGif(version: '89a'))),
        isTrue,
      );
    });

    test('embeds exact C2PA application framing and round-trips', () async {
      final manifest = Uint8List.fromList(
        List<int>.generate(600, (index) => index & 0xff),
      );
      final source = _baseGif(withGlobalColorTable: true);
      final output = MemoryByteSink();

      await handler.embedManifest(MemoryByteSource(source), manifest, output);

      final written = output.toBytes();
      expect(String.fromCharCodes(written.sublist(0, 6)), 'GIF89a');
      const preambleLength = 6 + 7 + 6;
      expect(written.sublist(preambleLength, preambleLength + 14), [
        0x21,
        0xff,
        0x0b,
        ...'C2PA_GIF'.codeUnits,
        0x01,
        0x00,
        0x00,
      ]);
      expect(written[preambleLength + 14], 255);
      expect(written[preambleLength + 14 + 256], 255);
      expect(written[preambleLength + 14 + 512], 90);
      expect(
        await handler.extractManifest(MemoryByteSource(written)),
        manifest,
      );
    });

    test('preserves unrelated extensions and image bytes exactly', () async {
      final manifest = Uint8List.fromList(const [1, 2, 3, 4]);
      final source = _baseGif(
        beforeImage: const [
          0x21,
          0xfe,
          3,
          9,
          8,
          7,
          0,
          0x21,
          0xff,
          0x0b,
          0x55,
          0x4e,
          0x52,
          0x45,
          0x4c,
          0x41,
          0x54,
          0x44,
          1,
          2,
          3,
          2,
          4,
          5,
          0,
        ],
      );
      final embedded = MemoryByteSink();
      await handler.embedManifest(MemoryByteSource(source), manifest, embedded);
      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(embedded.toBytes()),
        removed,
      );

      final expected = Uint8List.fromList(source)
        ..setRange(3, 6, '89a'.codeUnits);
      expect(removed.toBytes(), expected);
    });

    test('replaces an existing application extension in place', () async {
      final oldManifest = Uint8List.fromList(const [1, 2]);
      final newManifest = Uint8List.fromList(
        List<int>.generate(300, (index) => index),
      );
      final original = _baseGif(beforeImage: _c2paExtension(oldManifest));
      final output = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(original),
        newManifest,
        output,
      );

      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        newManifest,
      );
      expect(output.toBytes().sublist(13, 16), [0x21, 0xff, 0x0b]);
    });

    test('rejects duplicate and misplaced C2PA extensions', () {
      final block = _c2paExtension(const [1]);
      final duplicate = _baseGif(beforeImage: [...block, ...block]);
      final misplaced = _baseGif(afterImage: block);

      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(misplaced)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test(
      'rejects malformed sub-blocks, missing trailer, and trailing data',
      () {
        final truncatedSubBlock = [
          ...'GIF89a'.codeUnits,
          1,
          0,
          1,
          0,
          0,
          0,
          0,
          0x21,
          0xfe,
          5,
          1,
          2,
        ];
        final missingTrailer = _baseGif()..removeLast();
        final trailing = [..._baseGif(), 0];

        expect(
          handler.extractManifest(MemoryByteSource(truncatedSubBlock)),
          throwsA(isA<TruncatedAssetException>()),
        );
        expect(
          handler.extractManifest(MemoryByteSource(missingTrailer)),
          throwsA(isA<MalformedAssetFormatException>()),
        );
        expect(
          handler.extractManifest(MemoryByteSource(trailing)),
          throwsA(isA<MalformedAssetFormatException>()),
        );
      },
    );

    test('rejects malformed writes before emitting output', () async {
      final output = MemoryByteSink();
      final malformed = _baseGif()..removeLast();

      await expectLater(
        handler.embedManifest(
          MemoryByteSource(malformed),
          Uint8List.fromList(const [1]),
          output,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(output.toBytes(), isEmpty);
    });

    test('enforces manifest, sub-block, source, and output limits', () {
      final source = _baseGif();
      final manifest = Uint8List(300);

      expect(
        const GifAssetHandler(
          maxManifestSize: 10,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const GifAssetHandler(
          maxSubBlockCount: 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<SegmentLimitExceededException>()),
      );
      expect(
        GifAssetHandler(maxSourceSize: source.length - 1).embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [1]),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        GifAssetHandler(maxOutputSize: source.length).embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [1]),
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('propagates destination failures and reports capabilities', () {
      expect(
        handler.embedManifest(
          MemoryByteSource(_baseGif()),
          Uint8List.fromList(const [1]),
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
      expect(handler.capabilities.canDetect, isTrue);
      expect(handler.capabilities.canExtractManifest, isTrue);
      expect(handler.capabilities.canEmbedManifest, isTrue);
      expect(handler.capabilities.canReplaceManifest, isTrue);
      expect(handler.capabilities.canRemoveManifest, isTrue);
    });

    test('round-trips and removes an XMP application reference', () async {
      final source = _baseGif(beforeImage: const [0x21, 0xfe, 1, 7, 0]);
      final embedded = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(source),
        'https://example.com/one',
        embedded,
      );
      final bytes = embedded.toBytes();
      expect(_containsAscii(bytes, 'XMP DataXMP'), isTrue);
      expect(_containsSequence(bytes, const [1, 255, 254, 253]), isTrue);
      expect(
        await handler.readRemoteManifestReference(MemoryByteSource(bytes)),
        'https://example.com/one',
      );

      final replaced = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(bytes),
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
      expect(
        _containsSequence(removed.toBytes(), const [0x21, 0xfe, 1, 7, 0]),
        isTrue,
      );
    });

    test('rejects duplicate or malformed XMP and enforces limits', () async {
      final packet = utf8.encode(_minimalXmp);
      final extension = _xmpExtension(packet);
      await expectLater(
        handler.readXmp(
          MemoryByteSource(_baseGif(beforeImage: [...extension, ...extension])),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      final malformed = List<int>.from(extension)..[extension.length - 2] ^= 1;
      await expectLater(
        handler.readXmp(MemoryByteSource(_baseGif(beforeImage: malformed))),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        const GifAssetHandler(maxRemoteReferenceLength: 3)
            .updateRemoteManifestReference(
              MemoryByteSource(_baseGif()),
              'long',
              MemoryByteSink(),
            ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      await expectLater(
        handler.updateRemoteManifestReference(
          MemoryByteSource(_baseGif()),
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

List<int> _baseGif({
  String version = '87a',
  bool withGlobalColorTable = false,
  List<int> beforeImage = const [],
  List<int> afterImage = const [],
}) => [
  ...'GIF$version'.codeUnits,
  1,
  0,
  1,
  0,
  if (withGlobalColorTable) 0x80 else 0,
  0,
  0,
  if (withGlobalColorTable) ...const [0, 0, 0, 255, 255, 255],
  ...beforeImage,
  0x2c,
  0,
  0,
  0,
  0,
  1,
  0,
  1,
  0,
  0,
  2,
  2,
  0x44,
  0x01,
  0,
  ...afterImage,
  0x3b,
];

List<int> _c2paExtension(List<int> manifest) {
  final output = <int>[
    0x21,
    0xff,
    0x0b,
    ...'C2PA_GIF'.codeUnits,
    0x01,
    0x00,
    0x00,
  ];
  for (var offset = 0; offset < manifest.length; offset += 255) {
    final remaining = manifest.length - offset;
    final size = remaining < 255 ? remaining : 255;
    output
      ..add(size)
      ..addAll(manifest.sublist(offset, offset + size));
  }
  output.add(0);
  return output;
}

List<int> _xmpExtension(List<int> xmp) {
  final data = <int>[
    ...xmp,
    1,
    for (var value = 255; value >= 0; value--) value,
  ];
  final output = <int>[0x21, 0xff, 0x0b, ...'XMP DataXMP'.codeUnits];
  for (var offset = 0; offset < data.length; offset += 255) {
    final size = data.length - offset < 255 ? data.length - offset : 255;
    output
      ..add(size)
      ..addAll(data.sublist(offset, offset + size));
  }
  return output..add(0);
}

bool _containsAscii(List<int> bytes, String value) =>
    _containsSequence(bytes, value.codeUnits);

bool _containsSequence(List<int> bytes, List<int> value) {
  for (var offset = 0; offset <= bytes.length - value.length; offset++) {
    var equal = true;
    for (var index = 0; index < value.length; index++) {
      if (bytes[offset + index] != value[index]) {
        equal = false;
        break;
      }
    }
    if (equal) return true;
  }
  return false;
}

final class _FailingSink implements WritableByteSink {
  @override
  Future<int> get length async => 0;

  @override
  Future<void> append(List<int> bytes) async {
    throw StateError('simulated sink failure');
  }

  @override
  Future<void> close() async {}
}

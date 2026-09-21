import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('Mp3AssetHandler', () {
    const handler = Mp3AssetHandler();

    test('embeds an exact GEOB frame and round-trips', () async {
      final source = _bareMp3();
      final manifest = Uint8List.fromList(
        List<int>.generate(300, (i) => i & 0xff),
      );
      final output = MemoryByteSink();

      await handler.embedManifest(MemoryByteSource(source), manifest, output);

      final written = output.toBytes();
      expect(String.fromCharCodes(written.sublist(0, 3)), 'ID3');
      expect(_containsAscii(written, 'GEOB'), isTrue);
      expect(_containsAscii(written, 'application/c2pa\u0000'), isTrue);
      expect(_containsAscii(written, 'c2pa\u0000'), isTrue);
      expect(_containsAscii(written, 'c2pa manifest store\u0000'), isTrue);
      expect(
        await handler.extractManifest(MemoryByteSource(written)),
        manifest,
      );
    });

    test('preserves unrelated frames, padding, and MPEG audio bytes', () async {
      final unrelated = _frame('TIT2', [0, ...'title'.codeUnits, 0], 4);
      final source = _id3(
        version: 4,
        frames: [unrelated],
        padding: 7,
        audio: _bareMp3(),
      );
      final embedded = MemoryByteSink();
      await handler.embedManifest(
        MemoryByteSource(source),
        Uint8List.fromList(const [1, 2, 3, 4, 5]),
        embedded,
      );
      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(embedded.toBytes()),
        removed,
      );

      expect(removed.toBytes(), source);
    });

    test(
      'supports ID3v2.3 extended headers and global unsynchronization',
      () async {
        final extended = [0, 0, 0, 6, 0, 0, 0, 0, 0, 0];
        final source = _id3(
          version: 3,
          flags: 0xc0,
          extendedHeader: extended,
          audio: _bareMp3(),
        );
        final manifest = Uint8List.fromList(const [
          1,
          0xff,
          0xe1,
          2,
          0xff,
          0x00,
          3,
        ]);
        final output = MemoryByteSink();

        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        expect(
          await handler.extractManifest(MemoryByteSource(output.toBytes())),
          manifest,
        );
        expect(output.toBytes().sublist(10, 20), extended);
      },
    );

    test('replaces a single manifest and rejects duplicates', () async {
      final first = _geobFrame(const [1, 2, 3, 4, 5], 4);
      final source = _id3(version: 4, frames: [first], audio: _bareMp3());
      final replacement = Uint8List.fromList(const [8, 9, 10, 11, 12, 13]);
      final output = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(source),
        replacement,
        output,
      );
      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        replacement,
      );

      final duplicate = _id3(
        version: 4,
        frames: [first, first],
        audio: _bareMp3(),
      );
      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects malformed sync-safe sizes and truncated frames', () {
      final badSyncSafe = [...'ID3'.codeUnits, 4, 0, 0, 0x80, 0, 0, 0];
      final truncatedFrame = [
        ..._id3Header(4, 10, 0),
        ...'GEOB'.codeUnits,
        0,
        0,
        0,
        20,
        0,
        0,
      ];
      final transformedGeob = _id3(
        version: 4,
        frames: [
          [...'GEOB'.codeUnits, ..._syncSafe(1), 0, 0x08, 0],
        ],
        audio: _bareMp3(),
      );

      expect(
        handler.extractManifest(MemoryByteSource(badSyncSafe)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(truncatedFrame)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(transformedGeob)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('enforces limits and propagates sink failures', () {
      final source = _bareMp3();
      final manifest = Uint8List(20);
      expect(
        const Mp3AssetHandler(
          maxManifestSize: 10,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        Mp3AssetHandler(
          maxSourceSize: source.length - 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const Mp3AssetHandler(
          maxOutputSize: 20,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          manifest,
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('round-trips, replaces, and removes an XMP PRIV reference', () async {
      final source = _bareMp3();
      final embedded = MemoryByteSink();
      await handler.updateRemoteManifestReference(
        MemoryByteSource(source),
        'https://example.com/one',
        embedded,
      );
      expect(_containsAscii(embedded.toBytes(), 'PRIV'), isTrue);
      expect(_containsAscii(embedded.toBytes(), 'XMP\u0000'), isTrue);
      expect(_payloadAfterId3(embedded.toBytes()), source);
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(embedded.toBytes()),
        ),
        'https://example.com/one',
      );

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
      expect(_payloadAfterId3(removed.toBytes()), source);
    });

    test('rejects duplicate XMP frames and enforces reference limits', () {
      final frame = _privFrame(utf8.encode(_minimalXmp), 4);
      expect(
        handler.readXmp(
          MemoryByteSource(
            _id3(version: 4, frames: [frame, frame], audio: _bareMp3()),
          ),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        const Mp3AssetHandler(maxRemoteReferenceLength: 3)
            .updateRemoteManifestReference(
              MemoryByteSource(_bareMp3()),
              'long',
              MemoryByteSink(),
            ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        handler.updateRemoteManifestReference(
          MemoryByteSource(_bareMp3()),
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

List<int> _bareMp3() => [0xff, 0xe3, ...List<int>.generate(40, (i) => i)];

List<int> _id3({
  required int version,
  int flags = 0,
  List<int> extendedHeader = const [],
  List<List<int>> frames = const [],
  int padding = 0,
  List<int> audio = const [],
}) {
  final body = [
    ...extendedHeader,
    for (final frame in frames) ...frame,
    ...List<int>.filled(padding, 0),
  ];
  return [..._id3Header(version, body.length, flags), ...body, ...audio];
}

List<int> _id3Header(int version, int size, int flags) => [
  ...'ID3'.codeUnits,
  version,
  0,
  flags,
  (size >> 21) & 0x7f,
  (size >> 14) & 0x7f,
  (size >> 7) & 0x7f,
  size & 0x7f,
];

List<int> _frame(String id, List<int> body, int version) => [
  ...id.codeUnits,
  if (version == 4) ..._syncSafe(body.length) else ..._big32(body.length),
  0,
  0,
  ...body,
];

List<int> _geobFrame(List<int> manifest, int version) => _frame('GEOB', [
  0,
  ...'application/c2pa'.codeUnits,
  0,
  ...'c2pa'.codeUnits,
  0,
  ...'c2pa manifest store'.codeUnits,
  0,
  ...manifest,
], version);

List<int> _privFrame(List<int> xmp, int version) =>
    _frame('PRIV', [...'XMP'.codeUnits, 0, ...xmp], version);

List<int> _syncSafe(int value) => [
  (value >> 21) & 0x7f,
  (value >> 14) & 0x7f,
  (value >> 7) & 0x7f,
  value & 0x7f,
];

List<int> _big32(int value) => [
  (value >> 24) & 0xff,
  (value >> 16) & 0xff,
  (value >> 8) & 0xff,
  value & 0xff,
];

bool _containsAscii(List<int> bytes, String value) {
  final pattern = value.codeUnits;
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

List<int> _payloadAfterId3(List<int> bytes) {
  final size = (bytes[6] << 21) | (bytes[7] << 14) | (bytes[8] << 7) | bytes[9];
  return bytes.sublist(10 + size);
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

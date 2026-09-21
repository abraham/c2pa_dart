import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('FlacAssetHandler', () {
    const handler = FlacAssetHandler();

    test(
      'embeds a c2pa-rs-compatible ID3 GEOB frame and round-trips',
      () async {
        final source = _flac();
        final manifest = Uint8List.fromList(
          List<int>.generate(300, (index) => index & 0xff),
        );
        final output = MemoryByteSink();

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(String.fromCharCodes(written.sublist(0, 3)), 'ID3');
        expect(_containsAscii(written, 'GEOB'), isTrue);
        expect(_containsAscii(written, 'application/c2pa\u0000'), isTrue);
        expect(_containsAscii(written, 'c2pa manifest store\u0000'), isTrue);
        expect(_payloadAfterId3(written), source);
        expect(await handler.detect(MemoryByteSource(written)), isTrue);
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
      },
    );

    test(
      'preserves FLAC metadata and audio through replacement and removal',
      () async {
        final source = _flac(
          extraBlocks: [
            _metadataBlock(4, const [1, 2, 3], last: true),
          ],
          audio: const [0xff, 0xf8, 1, 2, 3, 4, 5],
        );
        final embedded = MemoryByteSink();
        await handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [1, 2, 3, 4, 5]),
          embedded,
        );
        expect(_payloadAfterId3(embedded.toBytes()), source);

        final replacement = Uint8List.fromList(const [8, 9, 10, 11, 12, 13]);
        final replaced = MemoryByteSink();
        await handler.replaceManifest(
          MemoryByteSource(embedded.toBytes()),
          replacement,
          replaced,
        );
        expect(_payloadAfterId3(replaced.toBytes()), source);
        expect(
          await handler.extractManifest(MemoryByteSource(replaced.toBytes())),
          replacement,
        );

        final removed = MemoryByteSink();
        await handler.removeManifest(
          MemoryByteSource(replaced.toBytes()),
          removed,
        );
        expect(removed.toBytes(), source);
      },
    );

    test(
      'preserves unrelated ID3 frames and accepts deprecated MIME',
      () async {
        final title = _frame('TIT2', [0, ...'title'.codeUnits, 0]);
        final deprecated = _geobFrame(const [
          1,
          2,
          3,
          4,
        ], mimeType: 'application/x-c2pa-manifest-store');
        final source = _id3([title, deprecated], _flac());

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        expect(await handler.extractManifest(MemoryByteSource(source)), const [
          1,
          2,
          3,
          4,
        ]);

        final removed = MemoryByteSink();
        await handler.removeManifest(MemoryByteSource(source), removed);
        expect(_containsAscii(removed.toBytes(), 'TIT2'), isTrue);
        expect(_containsAscii(removed.toBytes(), 'title'), isTrue);
        expect(_payloadAfterId3(removed.toBytes()), _flac());
      },
    );

    test('rejects duplicate C2PA GEOB frames', () {
      final frame = _geobFrame(const [1, 2, 3, 4]);
      final duplicate = _id3([frame, frame], _flac());

      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects malformed metadata lengths and missing last-block flag', () {
      final truncated = [
        ...'fLaC'.codeUnits,
        0,
        0,
        0,
        34,
        ...List<int>.filled(10, 0),
      ];
      final noLast = [
        ...'fLaC'.codeUnits,
        ..._metadataBlock(0, List<int>.filled(34, 0), last: false),
      ];

      expect(
        handler.extractManifest(MemoryByteSource(truncated)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(noLast)),
        throwsA(isA<TruncatedAssetException>()),
      );
    });

    test(
      'enforces limits, validates before output, and propagates failures',
      () async {
        final source = _flac();
        final manifest = Uint8List(20);
        expect(
          const FlacAssetHandler(
            maxManifestSize: 10,
          ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
          throwsA(isA<AssetLimitExceededException>()),
        );
        expect(
          FlacAssetHandler(
            maxSourceSize: source.length - 1,
          ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
          throwsA(isA<AssetLimitExceededException>()),
        );
        expect(
          const FlacAssetHandler(
            maxOutputSize: 20,
          ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
          throwsA(isA<AssetLimitExceededException>()),
        );
        expect(
          const FlacAssetHandler(maxMetadataBlockSize: 10)
              .extractManifest(MemoryByteSource(source)),
          throwsA(isA<AssetLimitExceededException>()),
        );

        final malformedOutput = MemoryByteSink();
        await expectLater(
          handler.embedManifest(
            MemoryByteSource(source.sublist(0, 20)),
            manifest,
            malformedOutput,
          ),
          throwsA(isA<TruncatedAssetException>()),
        );
        expect(malformedOutput.toBytes(), isEmpty);
        expect(
          handler.embedManifest(
            MemoryByteSource(source),
            manifest,
            _FailingSink(),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    test('round-trips and removes an ID3 XMP reference', () async {
      final source = _flac(audio: const [0xff, 0xf8, 9, 8, 7]);
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
      expect(_payloadAfterId3(removed.toBytes()), source);
    });

    test('rejects duplicate XMP PRIV frames and enforces limits', () {
      final frame = _frame('PRIV', [
        ...'XMP'.codeUnits,
        0,
        ...utf8.encode(_minimalXmp),
      ]);
      final source = _id3([frame, frame], _flac());
      expect(
        handler.readXmp(MemoryByteSource(source)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        const FlacAssetHandler(maxRemoteReferenceLength: 3)
            .updateRemoteManifestReference(
              MemoryByteSource(_flac()),
              'long',
              MemoryByteSink(),
            ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        handler.updateRemoteManifestReference(
          MemoryByteSource(_flac()),
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

List<int> _flac({
  List<List<int>> extraBlocks = const [],
  List<int> audio = const [0xff, 0xf8, 0, 1, 2, 3],
}) {
  final streamInfoLast = extraBlocks.isEmpty;
  return [
    ...'fLaC'.codeUnits,
    ..._metadataBlock(0, List<int>.filled(34, 0), last: streamInfoLast),
    for (final block in extraBlocks) ...block,
    ...audio,
  ];
}

List<int> _metadataBlock(int type, List<int> data, {bool last = false}) => [
  (last ? 0x80 : 0) | type,
  (data.length >> 16) & 0xff,
  (data.length >> 8) & 0xff,
  data.length & 0xff,
  ...data,
];

List<int> _id3(List<List<int>> frames, List<int> payload) {
  final body = [for (final frame in frames) ...frame];
  return [
    ...'ID3'.codeUnits,
    4,
    0,
    0,
    ..._syncSafe(body.length),
    ...body,
    ...payload,
  ];
}

List<int> _frame(String id, List<int> body) => [
  ...id.codeUnits,
  ..._syncSafe(body.length),
  0,
  0,
  ...body,
];

List<int> _geobFrame(
  List<int> manifest, {
  String mimeType = 'application/c2pa',
}) => _frame('GEOB', [
  0,
  ...mimeType.codeUnits,
  0,
  ...'c2pa'.codeUnits,
  0,
  ...'c2pa manifest store'.codeUnits,
  0,
  ...manifest,
]);

List<int> _syncSafe(int value) => [
  (value >> 21) & 0x7f,
  (value >> 14) & 0x7f,
  (value >> 7) & 0x7f,
  value & 0x7f,
];

List<int> _payloadAfterId3(List<int> bytes) {
  final size = (bytes[6] << 21) | (bytes[7] << 14) | (bytes[8] << 7) | bytes[9];
  return bytes.sublist(10 + size);
}

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

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('JpegAssetHandler', () {
    const handler = JpegAssetHandler();

    test('extracts a constructed multipart C2PA manifest store', () async {
      final manifest = _manifest(payloadLength: 80);
      final jpeg = _jpegWithManifest(
        manifest,
        chunkLengths: const [32, 27, 62],
      );

      expect(await handler.detect(MemoryByteSource(jpeg)), isTrue);
      expect(await handler.extractManifest(MemoryByteSource(jpeg)), manifest);
    });

    test('ignores unrelated JPEG data and JPEG XT APP11 boxes', () async {
      final manifest = _manifest(payloadLength: 40);
      final unrelatedXt = _app11([
        0x4a,
        0x50,
        0x33,
        0x44,
        0,
        0,
        0,
        1,
        ..._isoBox('jumb', _isoBox('free', const [1, 2, 3])),
      ]);
      final jpeg = _jpegWithManifest(
        manifest,
        chunkLengths: const [30, 51],
        before: [
          ..._segment(0xe1, List<int>.filled(200, 7)),
          ...unrelatedXt,
          ..._segment(0xe2, List<int>.filled(5000, 9)),
        ],
      );
      final source = _TrackingSource(jpeg);

      expect(await handler.extractManifest(source), manifest);
      expect(source.largestRead, lessThan(jpeg.length));
      expect(source.largestRead, lessThanOrEqualTo(500));
    });

    test('rejects truncated and invalid JPEG segments', () async {
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(const [0xff, 0xd8, 0xff, 0xeb, 0, 20, 1, 2]),
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(const [0xff, 0xd8, 0xff, 0xeb, 0, 1, 0xff, 0xd9]),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource(const [0xff, 0xd8, 1, 2, 0xff, 0xd9]),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects duplicate, missing, and out-of-order packets', () async {
      final manifest = _manifest(payloadLength: 100);

      for (final sequences in <List<int>>[
        const [1, 2, 2, 4],
        const [1, 3, 4, 5],
        const [1, 3, 2, 4],
      ]) {
        final jpeg = _jpegWithManifest(
          manifest,
          chunkLengths: const [32, 32, 32, 45],
          sequences: sequences,
        );
        await expectLater(
          handler.extractManifest(MemoryByteSource(jpeg)),
          throwsA(isA<MalformedAssetFormatException>()),
        );
      }
    });

    test('rejects a continuation with a different repeated box header', () {
      final manifest = _manifest(payloadLength: 60);
      final jpeg = _jpegWithManifest(
        manifest,
        chunkLengths: const [32, 69],
        mutateContinuationHeader: true,
      );

      expect(
        handler.extractManifest(MemoryByteSource(jpeg)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects truncated reconstruction and oversized declarations', () {
      final manifest = _manifest(payloadLength: 50);
      final truncated = _jpegWithManifest(
        manifest,
        chunkLengths: [manifest.length - 1],
      );

      expect(
        handler.extractManifest(MemoryByteSource(truncated)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        JpegAssetHandler(maxManifestSize: manifest.length - 1).extractManifest(
          MemoryByteSource(
            _jpegWithManifest(manifest, chunkLengths: [manifest.length]),
          ),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('rejects duplicate stores and reports a missing store', () {
      final manifest = _manifest(payloadLength: 4);
      final store = _jpegXtSegments(manifest, [manifest.length]);
      final duplicate = [
        0xff,
        0xd8,
        ...store,
        ..._jpegXtSegments(manifest, [manifest.length], entity: 0x3344),
        0xff,
        0xd9,
      ];

      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(
          MemoryByteSource(const [0xff, 0xd8, 0xff, 0xd9]),
        ),
        throwsA(isA<ManifestNotFoundException>()),
      );
    });

    test('reports extraction support', () {
      expect(handler.capabilities.canDetect, isTrue);
      expect(handler.capabilities.canExtractManifest, isTrue);
      expect(handler.capabilities.canEmbedManifest, isTrue);
      expect(handler.capabilities.canReplaceManifest, isTrue);
      expect(handler.capabilities.canRemoveManifest, isTrue);
    });

    test(
      'embeds a single segment at the metadata position and round-trips',
      () async {
        final manifest = Uint8List.fromList(_manifest(payloadLength: 20));
        final source = _baseJpeg();
        final output = MemoryByteSink();

        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        final app0 = _segment(0xe0, const [1, 2]);
        expect(written.sublist(0, 2 + app0.length), [0xff, 0xd8, ...app0]);
        expect(written[2 + app0.length], 0xff);
        expect(written[3 + app0.length], 0xeb);
      },
    );

    test(
      'splits a large store into compatible sequenced APP11 segments',
      () async {
        final manifest = Uint8List.fromList(_manifest(payloadLength: 70000));
        final output = MemoryByteSink();

        await handler.embedManifest(
          MemoryByteSource(_baseJpeg()),
          manifest,
          output,
        );

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        expect(_countApp11BeforeScan(written), 2);
      },
    );

    test('replaces and removes while preserving unrelated bytes', () async {
      final source = _baseJpeg();
      final oldManifest = Uint8List.fromList(_manifest(payloadLength: 12));
      final newManifest = Uint8List.fromList(_manifest(payloadLength: 18));
      final embedded = MemoryByteSink();
      await handler.embedManifest(
        MemoryByteSource(source),
        oldManifest,
        embedded,
      );

      final replaced = MemoryByteSink();
      await handler.replaceManifest(
        MemoryByteSource(embedded.toBytes()),
        newManifest,
        replaced,
      );
      expect(
        await handler.extractManifest(MemoryByteSource(replaced.toBytes())),
        newManifest,
      );

      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(replaced.toBytes()),
        removed,
      );
      expect(removed.toBytes(), source);
    });

    test('preserves stuffed and restart bytes in entropy-coded data', () async {
      final source = _baseJpeg(
        entropy: const [
          0x11,
          0xff,
          0x00,
          0x22,
          0xff,
          0xd0,
          0x33,
          0xff,
          0xd7,
          0x44,
        ],
      );
      final manifest = Uint8List.fromList(_manifest(payloadLength: 4));
      final embedded = MemoryByteSink();
      await handler.embedManifest(MemoryByteSource(source), manifest, embedded);
      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(embedded.toBytes()),
        removed,
      );

      expect(removed.toBytes(), source);
    });

    test('rejects malformed and duplicate inputs before output', () async {
      final manifest = Uint8List.fromList(_manifest(payloadLength: 4));
      final malformedOutput = MemoryByteSink();
      final duplicateOutput = MemoryByteSink();
      final malformedStoreOutput = MemoryByteSink();
      final malformed = [0xff, 0xd8, 0xff, 0xe1, 0, 8, 1, 2];
      final duplicate = [
        0xff,
        0xd8,
        ..._jpegXtSegments(manifest, [manifest.length]),
        ..._jpegXtSegments(manifest, [manifest.length], entity: 0x3344),
        0xff,
        0xd9,
      ];
      final malformedStore = _jpegWithManifest(
        manifest,
        chunkLengths: [32, manifest.length - 32],
        sequences: const [1, 3],
      );

      await expectLater(
        handler.embedManifest(
          MemoryByteSource(malformed),
          manifest,
          malformedOutput,
        ),
        throwsA(isA<AssetFormatException>()),
      );
      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(duplicate),
          manifest,
          duplicateOutput,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(malformedStore),
          manifest,
          malformedStoreOutput,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(malformedOutput.toBytes(), isEmpty);
      expect(duplicateOutput.toBytes(), isEmpty);
      expect(malformedStoreOutput.toBytes(), isEmpty);
    });

    test('enforces manifest, segment, source, and output limits', () {
      final smallManifest = Uint8List.fromList(_manifest(payloadLength: 4));
      final largeManifest = Uint8List.fromList(_manifest(payloadLength: 65000));
      final source = _baseJpeg();

      expect(
        const JpegAssetHandler(maxManifestSize: 8).embedManifest(
          MemoryByteSource(source),
          smallManifest,
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const JpegAssetHandler(maxSegmentCount: 1).embedManifest(
          MemoryByteSource(source),
          largeManifest,
          MemoryByteSink(),
        ),
        throwsA(isA<SegmentLimitExceededException>()),
      );
      expect(
        JpegAssetHandler(maxSourceSize: source.length - 1).embedManifest(
          MemoryByteSource(source),
          smallManifest,
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        JpegAssetHandler(maxOutputSize: source.length).embedManifest(
          MemoryByteSource(source),
          smallManifest,
          MemoryByteSink(),
        ),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('propagates destination sink failures', () {
      final manifest = Uint8List.fromList(_manifest(payloadLength: 4));

      expect(
        handler.embedManifest(
          MemoryByteSource(_baseJpeg()),
          manifest,
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test(
      'round-trips, replaces, and removes an XMP remote reference',
      () async {
        final source = _baseJpeg(entropy: const [9, 8, 7, 0xff, 0x00, 6]);
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

        final replaced = MemoryByteSink();
        await handler.updateRemoteManifestReference(
          MemoryByteSource(embedded.toBytes()),
          'self#jumbf=c2pa/two',
          replaced,
        );
        expect(replaced.toBytes().length, embedded.toBytes().length);
        expect(
          await handler.readRemoteManifestReference(
            MemoryByteSource(replaced.toBytes()),
          ),
          'self#jumbf=c2pa/two',
        );
        expect(
          replaced.toBytes().sublist(replaced.toBytes().length - 10),
          source.sublist(source.length - 10),
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
      },
    );

    test('rejects duplicate XMP and propagates XMP sink failures', () async {
      const signature = 'http://ns.adobe.com/xap/1.0/\u0000';
      final packet = utf8.encode(_minimalXmp);
      final xmp = _segment(0xe1, [...ascii.encode(signature), ...packet]);
      final duplicate = [0xff, 0xd8, ...xmp, ...xmp, 0xff, 0xd9];
      await expectLater(
        handler.readXmp(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.updateRemoteManifestReference(
          MemoryByteSource(_baseJpeg()),
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

List<int> _manifest({required int payloadLength}) {
  const c2paUuid = [
    0x63,
    0x32,
    0x70,
    0x61,
    0x00,
    0x11,
    0x00,
    0x10,
    0x80,
    0x00,
    0x00,
    0xaa,
    0x00,
    0x38,
    0x9b,
    0x71,
  ];
  final description = _isoBox('jumd', [...c2paUuid, 1]);
  final payload = _isoBox(
    'cbor',
    List<int>.generate(payloadLength, (index) => index & 0xff),
  );
  return _isoBox('jumb', [...description, ...payload]);
}

List<int> _jpegWithManifest(
  List<int> manifest, {
  required List<int> chunkLengths,
  List<int> sequences = const [],
  List<int> before = const [],
  bool mutateContinuationHeader = false,
}) => [
  0xff,
  0xd8,
  ...before,
  ..._jpegXtSegments(
    manifest,
    chunkLengths,
    sequences: sequences,
    mutateContinuationHeader: mutateContinuationHeader,
  ),
  0xff,
  0xd9,
];

List<int> _jpegXtSegments(
  List<int> manifest,
  List<int> chunkLengths, {
  int entity = 0x0211,
  List<int> sequences = const [],
  bool mutateContinuationHeader = false,
}) {
  final output = <int>[];
  var offset = 0;
  for (var index = 0; index < chunkLengths.length; index++) {
    final end = offset + chunkLengths[index];
    final chunk = manifest.sublist(offset, end);
    final sequence = sequences.isEmpty ? index + 1 : sequences[index];
    final repeatedHeader = manifest.sublist(0, 8);
    if (mutateContinuationHeader && index == 1) {
      repeatedHeader[7] ^= 1;
    }
    output.addAll(
      _app11([
        0x4a,
        0x50,
        entity >> 8,
        entity,
        sequence >> 24,
        sequence >> 16,
        sequence >> 8,
        sequence,
        if (index > 0) ...repeatedHeader,
        ...chunk,
      ]),
    );
    offset = end;
  }
  return output;
}

List<int> _baseJpeg({List<int> entropy = const [1, 2, 3, 4]}) => [
  0xff,
  0xd8,
  ..._segment(0xe0, const [1, 2]),
  ..._segment(0xe1, const [7, 8, 9]),
  ..._segment(0xda, const [1, 1]),
  ...entropy,
  0xff,
  0xd9,
];

int _countApp11BeforeScan(List<int> jpeg) {
  var count = 0;
  var offset = 2;
  while (offset + 4 <= jpeg.length && jpeg[offset] == 0xff) {
    final marker = jpeg[offset + 1];
    if (marker == 0xda || marker == 0xd9) break;
    final length = (jpeg[offset + 2] << 8) | jpeg[offset + 3];
    if (marker == 0xeb) count++;
    offset += 2 + length;
  }
  return count;
}

List<int> _app11(List<int> payload) => _segment(0xeb, payload);

List<int> _segment(int marker, List<int> payload) {
  final length = payload.length + 2;
  return [0xff, marker, length >> 8, length, ...payload];
}

List<int> _isoBox(String type, List<int> payload) {
  final length = payload.length + 8;
  return [
    length >> 24,
    length >> 16,
    length >> 8,
    length,
    ...type.codeUnits,
    ...payload,
  ];
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

final class _TrackingSource implements RandomAccessByteSource {
  _TrackingSource(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int largestRead = 0;

  @override
  Future<int> get length async => _bytes.length;

  @override
  Future<Uint8List> read(ByteRange range) async {
    largestRead = range.length > largestRead ? range.length : largestRead;
    return Uint8List.fromList(_bytes.sublist(range.start, range.end));
  }
}

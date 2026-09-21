import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('PngAssetHandler', () {
    const handler = PngAssetHandler();

    test('extracts the caBX manifest and streams unrelated chunks', () async {
      final manifest = _box('jumb', const [1, 2, 3, 4]);
      final png = _png([
        _chunk('IHDR', List<int>.filled(13, 0)),
        _chunk('aaAa', List<int>.filled(150000, 7)),
        _chunk('caBX', manifest),
        _chunk('IDAT', const [8, 9, 10]),
        _chunk('IEND', const []),
      ]);
      final source = _TrackingSource(png);

      expect(await handler.detect(source), isTrue);
      expect(await handler.extractManifest(source), manifest);
      expect(source.largestRead, lessThanOrEqualTo(64 * 1024));
    });

    test('extracts through the registry', () async {
      final manifest = _box('jumb', const [9, 8, 7]);
      final png = _png([_chunk('caBX', manifest), _chunk('IEND', const [])]);

      expect(
        await AssetHandlerRegistry().extractManifest(MemoryByteSource(png)),
        manifest,
      );
    });

    test('rejects duplicate caBX chunks', () {
      final manifest = _box('jumb', const []);
      final png = _png([
        _chunk('caBX', manifest),
        _chunk('caBX', manifest),
        _chunk('IEND', const []),
      ]);

      expect(
        handler.extractManifest(MemoryByteSource(png)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects invalid CRC values for manifest and unrelated chunks', () {
      final manifest = _box('jumb', const []);
      final badManifest = _chunk('caBX', manifest)..last ^= 1;
      final badAncillary = _chunk('tEXt', const [1, 2, 3])..last ^= 1;

      expect(
        handler.extractManifest(
          MemoryByteSource(_png([badManifest, _chunk('IEND', const [])])),
        ),
        throwsA(isA<InvalidChunkCrcException>()),
      );
      expect(
        handler.extractManifest(
          MemoryByteSource(
            _png([
              badAncillary,
              _chunk('caBX', manifest),
              _chunk('IEND', const []),
            ]),
          ),
        ),
        throwsA(isA<InvalidChunkCrcException>()),
      );
    });

    test('rejects truncation and overflowing 32-bit lengths', () {
      expect(
        handler.extractManifest(MemoryByteSource([..._signature, 0, 0, 0])),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(
          MemoryByteSource([
            ..._signature,
            0xff,
            0xff,
            0xff,
            0xff,
            ...'caBX'.codeUnits,
            0,
            0,
            0,
            0,
          ]),
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
    });

    test('enforces the configured manifest size limit', () {
      final manifest = _box('jumb', List<int>.filled(20, 0));
      final png = _png([_chunk('caBX', manifest), _chunk('IEND', const [])]);

      expect(
        const PngAssetHandler(maxManifestSize: 16)
            .extractManifest(MemoryByteSource(png)),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('requires a valid terminal IEND with no trailing bytes', () {
      final manifest = _box('jumb', const []);
      final withoutEnd = _png([_chunk('caBX', manifest)]);
      final nonEmptyEnd = _png([
        _chunk('caBX', manifest),
        _chunk('IEND', const [0]),
      ]);
      final trailing = [
        ..._png([_chunk('caBX', manifest), _chunk('IEND', const [])]),
        0,
      ];

      expect(
        handler.extractManifest(MemoryByteSource(withoutEnd)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(nonEmptyEnd)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(trailing)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects invalid chunk type codes and reports missing caBX', () {
      final invalidType = _chunk('tEXt', const [])..[5] = 0;
      final noManifest = _png([_chunk('IEND', const [])]);

      expect(
        handler.extractManifest(
          MemoryByteSource(_png([invalidType, _chunk('IEND', const [])])),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(noManifest)),
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

    test('embeds after IHDR and round-trips through extraction', () async {
      final manifest = _box('jumb', const [4, 3, 2, 1]);
      final header = _chunk('IHDR', List<int>.filled(13, 0));
      final text = _chunk('tEXt', const [1, 2, 3]);
      final image = _chunk('IDAT', const [9, 8, 7]);
      final end = _chunk('IEND', const []);
      final source = _png([header, text, image, end]);
      final output = MemoryByteSink();

      await handler.embedManifest(
        MemoryByteSource(source),
        Uint8List.fromList(manifest),
        output,
      );

      final written = output.toBytes();
      expect(
        written,
        _png([header, _chunk('caBX', manifest), text, image, end]),
      );
      expect(
        await handler.extractManifest(MemoryByteSource(written)),
        manifest,
      );
    });

    test('supports embedding through the handler registry', () async {
      final manifest = Uint8List.fromList(_box('jumb', const [6, 7]));
      final source = _png([_chunk('IEND', const [])]);
      final output = MemoryByteSink();

      await AssetHandlerRegistry().embedManifest(
        MemoryByteSource(source),
        manifest,
        output,
      );

      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        manifest,
      );
    });

    test('replaces one caBX at the compatible post-IHDR position', () async {
      final oldManifest = _box('jumb', const [1]);
      final newManifest = _box('jumb', const [2, 3]);
      final header = _chunk('IHDR', List<int>.filled(13, 0));
      final text = _chunk('tEXt', const [5, 6, 7]);
      final image = _chunk('IDAT', const [8, 9]);
      final end = _chunk('IEND', const []);
      final source = _png([
        header,
        text,
        image,
        _chunk('caBX', oldManifest),
        end,
      ]);
      final output = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(source),
        Uint8List.fromList(newManifest),
        output,
      );

      expect(
        output.toBytes(),
        _png([header, _chunk('caBX', newManifest), text, image, end]),
      );
      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        newManifest,
      );
    });

    test('removes caBX while preserving every unrelated byte', () async {
      final manifest = _box('jumb', const [1, 2, 3]);
      final header = _chunk('IHDR', List<int>.filled(13, 0));
      final custom = _chunk('vpAg', const [0, 255, 17, 34]);
      final image = _chunk('IDAT', const [99, 88, 77]);
      final end = _chunk('IEND', const []);
      final source = _png([
        header,
        custom,
        _chunk('caBX', manifest),
        image,
        end,
      ]);
      final output = MemoryByteSink();

      await handler.removeManifest(MemoryByteSource(source), output);

      expect(output.toBytes(), _png([header, custom, image, end]));
    });

    test('rejects invalid mutation state before writing output', () async {
      final manifest = _box('jumb', const []);
      final duplicateSource = _png([
        _chunk('caBX', manifest),
        _chunk('caBX', manifest),
        _chunk('IEND', const []),
      ]);
      final badChunk = _chunk('tEXt', const [1])..last ^= 1;
      final malformedSource = _png([badChunk, _chunk('IEND', const [])]);
      final duplicateOutput = MemoryByteSink();
      final malformedOutput = MemoryByteSink();

      await expectLater(
        handler.replaceManifest(
          MemoryByteSource(duplicateSource),
          Uint8List.fromList(manifest),
          duplicateOutput,
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.embedManifest(
          MemoryByteSource(malformedSource),
          Uint8List.fromList(manifest),
          malformedOutput,
        ),
        throwsA(isA<InvalidChunkCrcException>()),
      );
      expect(duplicateOutput.toBytes(), isEmpty);
      expect(malformedOutput.toBytes(), isEmpty);
    });

    test('requires correct insertion, replacement, and removal state', () {
      final manifest = Uint8List.fromList(_box('jumb', const []));
      final withoutManifest = _png([_chunk('IEND', const [])]);
      final withManifest = _png([
        _chunk('caBX', manifest),
        _chunk('IEND', const []),
      ]);

      expect(
        handler.embedManifest(
          MemoryByteSource(withManifest),
          manifest,
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestAlreadyExistsException>()),
      );
      expect(
        handler.replaceManifest(
          MemoryByteSource(withoutManifest),
          manifest,
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestNotFoundException>()),
      );
      expect(
        handler.removeManifest(
          MemoryByteSource(withoutManifest),
          MemoryByteSink(),
        ),
        throwsA(isA<ManifestNotFoundException>()),
      );
    });

    test('enforces source, output, and manifest write limits', () {
      final manifest = Uint8List.fromList(_box('jumb', const [1, 2, 3]));
      final source = _png([_chunk('IEND', const [])]);

      expect(
        const PngAssetHandler(
          maxManifestSize: 4,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        PngAssetHandler(
          maxSourceSize: source.length - 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        PngAssetHandler(
          maxOutputSize: source.length,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('propagates destination sink failures', () {
      final manifest = Uint8List.fromList(_box('jumb', const [1]));
      final source = _png([_chunk('IEND', const [])]);
      final output = _FailingSink();

      expect(
        handler.embedManifest(MemoryByteSource(source), manifest, output),
        throwsA(isA<StateError>()),
      );
    });

    test(
      'round-trips, replaces, and removes an XMP remote reference',
      () async {
        final keep = _chunk('tEXt', ascii.encode('keep\u0000exact'));
        final source = _png([
          _chunk('IHDR', List<int>.filled(13, 0)),
          keep,
          _chunk('IDAT', const [1, 2, 3]),
          _chunk('IEND', const []),
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
        expect(_containsBytes(removed.toBytes(), keep), isTrue);
      },
    );

    test('rejects duplicate XMP chunks and propagates sink failures', () async {
      final packet = utf8.encode(_minimalXmp);
      final payload = [
        ...ascii.encode('XML:com.adobe.xmp'),
        0,
        0,
        0,
        0,
        0,
        ...packet,
      ];
      final source = _png([
        _chunk('IHDR', List<int>.filled(13, 0)),
        _chunk('iTXt', payload),
        _chunk('iTXt', payload),
        _chunk('IEND', const []),
      ]);
      await expectLater(
        handler.readXmp(MemoryByteSource(source)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.updateRemoteManifestReference(
          MemoryByteSource(_png([_chunk('IEND', const [])])),
          'https://example.com',
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });
  });
}

const List<int> _signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const _minimalXmp =
    '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    '<rdf:Description/></rdf:RDF></x:xmpmeta>';

List<int> _png(List<List<int>> chunks) {
  final hasHeader =
      chunks.isNotEmpty &&
      chunks.first.length >= 8 &&
      String.fromCharCodes(chunks.first.sublist(4, 8)) == 'IHDR';
  return [
    ..._signature,
    if (!hasHeader) ..._chunk('IHDR', List<int>.filled(13, 0)),
    for (final chunk in chunks) ...chunk,
  ];
}

bool _containsBytes(List<int> haystack, List<int> needle) {
  for (var offset = 0; offset <= haystack.length - needle.length; offset++) {
    if (List.generate(
      needle.length,
      (index) => haystack[offset + index] == needle[index],
    ).every((matches) => matches)) {
      return true;
    }
  }
  return false;
}

List<int> _chunk(String type, List<int> data) {
  final typeBytes = type.codeUnits;
  final crc = _crc32([...typeBytes, ...data]);
  return [
    (data.length >> 24) & 0xff,
    (data.length >> 16) & 0xff,
    (data.length >> 8) & 0xff,
    data.length & 0xff,
    ...typeBytes,
    ...data,
    (crc >> 24) & 0xff,
    (crc >> 16) & 0xff,
    (crc >> 8) & 0xff,
    crc & 0xff,
  ];
}

List<int> _box(String type, List<int> payload) {
  final length = payload.length + 8;
  return [
    (length >> 24) & 0xff,
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
    ...type.codeUnits,
    ...payload,
  ];
}

int _crc32(List<int> bytes) {
  var crc = 0xffffffff;
  for (final byte in bytes) {
    crc ^= byte;
    for (var bit = 0; bit < 8; bit++) {
      crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320 : crc >> 1;
    }
  }
  return crc ^ 0xffffffff;
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

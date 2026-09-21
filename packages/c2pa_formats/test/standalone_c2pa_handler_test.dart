import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('StandaloneC2paHandler', () {
    const handler = StandaloneC2paHandler();

    test('extracts the complete JUMBF box', () async {
      final bytes = _box(type: 'jumb', payload: const [1, 2, 3, 4]);

      expect(await handler.detect(MemoryByteSource(bytes)), isTrue);
      expect(await handler.extractManifest(MemoryByteSource(bytes)), bytes);
    });

    test('recognizes a C2PA box and a size extending to EOF', () async {
      final bytes = [0, 0, 0, 0, ...'c2pa'.codeUnits, 1, 2];

      expect(await handler.detect(MemoryByteSource(bytes)), isTrue);
      expect(await handler.extractManifest(MemoryByteSource(bytes)), bytes);
    });

    test('supports a valid extended-size box', () async {
      final bytes = [
        0,
        0,
        0,
        1,
        ...'jumb'.codeUnits,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        18,
        1,
        2,
      ];

      expect(await handler.extractManifest(MemoryByteSource(bytes)), bytes);
    });

    test('rejects truncated headers and declared payloads', () async {
      await expectLater(
        handler.extractManifest(MemoryByteSource(const [0, 0, 0])),
        throwsA(isA<TruncatedAssetException>()),
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource([0, 0, 0, 20, ...'jumb'.codeUnits, 1]),
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
      await expectLater(
        handler.extractManifest(
          MemoryByteSource([0, 0, 0, 1, ...'jumb'.codeUnits]),
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
    });

    test('rejects invalid sizes, types, and trailing bytes', () async {
      await expectLater(
        handler.extractManifest(
          MemoryByteSource([0, 0, 0, 7, ...'jumb'.codeUnits]),
        ),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.extractManifest(MemoryByteSource(_box(type: 'free'))),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      await expectLater(
        handler.extractManifest(MemoryByteSource([..._box(type: 'jumb'), 0])),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('reports extraction capability only for standalone data', () {
      expect(handler.capabilities.canDetect, isTrue);
      expect(handler.capabilities.canExtractManifest, isTrue);
      expect(const JpegHandler().capabilities.canExtractManifest, isTrue);
      expect(const PngHandler().capabilities.canExtractManifest, isTrue);
    });
  });
}

List<int> _box({required String type, List<int> payload = const []}) {
  final length = 8 + payload.length;
  return [
    length >> 24,
    length >> 16,
    length >> 8,
    length,
    ...type.codeUnits,
    ...payload,
  ];
}

import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('AssetHandlerRegistry', () {
    test('uses MIME hints before extensions and magic bytes', () async {
      final registry = AssetHandlerRegistry();
      final source = MemoryByteSource(_pngBytes);

      final result = await registry.detect(
        source,
        mimeType: 'image/jpeg',
        fileExtension: '.png',
      );

      expect(result.format, AssetFormat.jpeg);
      expect(result.method, AssetDetectionMethod.mimeType);
    });

    test('preserves handler order for matching hints', () async {
      final first = _TestHandler('first');
      final second = _TestHandler('second');
      final registry = AssetHandlerRegistry(handlers: [first, second]);

      final result = await registry.detect(
        MemoryByteSource(const []),
        mimeType: 'application/example',
      );

      expect(result.handler, same(first));
    });

    test('normalizes MIME types and extensions', () async {
      final registry = AssetHandlerRegistry();
      final source = MemoryByteSource(const []);

      final mimeResult = await registry.detect(
        source,
        mimeType: '  IMAGE/PNG ; charset=binary ',
      );
      final extensionResult = await registry.detect(
        source,
        fileExtension: ' ..JpEg ',
      );

      expect(mimeResult.format, AssetFormat.png);
      expect(mimeResult.method, AssetDetectionMethod.mimeType);
      expect(extensionResult.format, AssetFormat.jpeg);
      expect(extensionResult.method, AssetDetectionMethod.fileExtension);
    });

    test('falls back to magic-byte detection', () async {
      final registry = AssetHandlerRegistry();

      final jpeg = await registry.detect(
        MemoryByteSource(const [0xff, 0xd8, 0xff, 0xe1]),
      );
      final png = await registry.detect(MemoryByteSource(_pngBytes));
      final standalone = await registry.detect(
        MemoryByteSource(_box(type: 'jumb')),
      );
      final gif = await registry.detect(MemoryByteSource('GIF89a'.codeUnits));
      final webp = await registry.detect(
        MemoryByteSource([
          ...'RIFF'.codeUnits,
          4,
          0,
          0,
          0,
          ...'WEBP'.codeUnits,
        ]),
      );
      final wav = await registry.detect(
        MemoryByteSource([
          ...'RIFF'.codeUnits,
          4,
          0,
          0,
          0,
          ...'WAVE'.codeUnits,
        ]),
      );
      final avi = await registry.detect(
        MemoryByteSource([
          ...'RIFF'.codeUnits,
          4,
          0,
          0,
          0,
          ...'AVI '.codeUnits,
        ]),
      );
      final mp3 = await registry.detect(
        MemoryByteSource([...'ID3'.codeUnits, 4, 0, 0, 0, 0, 0, 0]),
      );
      final flac = await registry.detect(MemoryByteSource('fLaC'.codeUnits));

      expect(jpeg.format, AssetFormat.jpeg);
      expect(png.format, AssetFormat.png);
      expect(standalone.format, AssetFormat.standaloneC2pa);
      expect(gif.format, AssetFormat.gif);
      expect(webp.format, AssetFormat.webp);
      expect(wav.format, AssetFormat.wav);
      expect(avi.format, AssetFormat.avi);
      expect(mp3.format, AssetFormat.mp3);
      expect(flac.format, AssetFormat.flac);
      expect(jpeg.method, AssetDetectionMethod.magicBytes);
      expect(png.method, AssetDetectionMethod.magicBytes);
      expect(standalone.method, AssetDetectionMethod.magicBytes);
      expect(gif.method, AssetDetectionMethod.magicBytes);
      expect(webp.method, AssetDetectionMethod.magicBytes);
      expect(wav.method, AssetDetectionMethod.magicBytes);
      expect(avi.method, AssetDetectionMethod.magicBytes);
      expect(mp3.method, AssetDetectionMethod.magicBytes);
      expect(flac.method, AssetDetectionMethod.magicBytes);
    });

    test('returns an unknown result for unrecognized data', () async {
      final result = await AssetHandlerRegistry().detect(
        MemoryByteSource(const [1, 2, 3, 4]),
      );

      expect(result.format, AssetFormat.unknown);
      expect(result.method, AssetDetectionMethod.none);
      expect(result.handler, isNull);
      expect(result.isKnown, isFalse);
    });

    test('throws typed errors when extraction is unavailable', () async {
      final registry = AssetHandlerRegistry(
        handlers: const [_TestHandler('unsupported')],
      );

      await expectLater(
        registry.extractManifest(
          MemoryByteSource(const []),
          mimeType: 'application/example',
        ),
        throwsA(isA<UnsupportedManifestExtractionException>()),
      );
      await expectLater(
        AssetHandlerRegistry().extractManifest(
          MemoryByteSource(const [1, 2, 3]),
        ),
        throwsA(isA<UnknownAssetFormatException>()),
      );
    });

    test('reports and enforces remote-reference capabilities', () async {
      final registry = AssetHandlerRegistry();
      for (final format in const {
        AssetFormat.jpeg,
        AssetFormat.png,
        AssetFormat.tiff,
        AssetFormat.svg,
        AssetFormat.mp4,
        AssetFormat.mov,
        AssetFormat.m4a,
        AssetFormat.avif,
        AssetFormat.heif,
        AssetFormat.heic,
        AssetFormat.jpegXl,
        AssetFormat.gif,
        AssetFormat.webp,
        AssetFormat.wav,
        AssetFormat.avi,
        AssetFormat.mp3,
        AssetFormat.flac,
      }) {
        final capabilities = registry.handlers
            .firstWhere((handler) => handler.format == format)
            .capabilities;
        expect(capabilities.canReadXmp, isTrue, reason: format.name);
        expect(
          capabilities.canReadRemoteReference,
          isTrue,
          reason: format.name,
        );
        expect(
          capabilities.canEmbedRemoteReference,
          isTrue,
          reason: format.name,
        );
        expect(
          capabilities.canRemoveRemoteReference,
          isTrue,
          reason: format.name,
        );
      }

      await expectLater(
        registry.readRemoteManifestReference(
          MemoryByteSource(const []),
          mimeType: 'application/pdf',
        ),
        throwsA(isA<UnsupportedXmpOperationException>()),
      );
    });
  });
}

final class _TestHandler implements AssetHandler {
  const _TestHandler(this.name);

  @override
  final String name;

  @override
  AssetHandlerCapabilities get capabilities => const AssetHandlerCapabilities(
    canDetect: true,
    canExtractManifest: false,
    mimeTypes: ['application/example'],
    fileExtensions: ['example'],
  );

  @override
  AssetFormat get format => AssetFormat.unknown;

  @override
  Future<bool> detect(RandomAccessByteSource source) async => true;

  @override
  Future<Uint8List> extractManifest(RandomAccessByteSource source) {
    throw const UnsupportedManifestExtractionException(AssetFormat.unknown);
  }

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.unknown,
      ManifestMutationOperation.embed,
    );
  }

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.unknown,
      ManifestMutationOperation.replace,
    );
  }

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) {
    throw const UnsupportedManifestMutationException(
      AssetFormat.unknown,
      ManifestMutationOperation.remove,
    );
  }
}

const List<int> _pngBytes = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

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

import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  for (final order in [Endian.little, Endian.big]) {
    group('${order == Endian.little ? 'little' : 'big'}-endian TIFF', () {
      const handler = TiffAssetHandler();

      test('embeds, extracts, and preserves original image data', () async {
        final source = _singlePageTiff(order);
        final manifest = Uint8List.fromList(
          List<int>.generate(300, (index) => index & 0xff),
        );
        final output = MemoryByteSink();

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        expect(written.sublist(0, 4), source.sublist(0, 4));
        expect(written.sublist(8, source.length), source.sublist(8));
        expect(_read32(written, 4, order), greaterThanOrEqualTo(source.length));
      });

      test('replaces and removes the manifest', () async {
        final source = _singlePageTiff(order);
        final first = MemoryByteSink();
        await handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(List<int>.filled(20, 1)),
          first,
        );
        final replacement = Uint8List.fromList(List<int>.filled(33, 2));
        final second = MemoryByteSink();
        await handler.replaceManifest(
          MemoryByteSource(first.toBytes()),
          replacement,
          second,
        );
        expect(
          await handler.extractManifest(MemoryByteSource(second.toBytes())),
          replacement,
        );

        final removed = MemoryByteSink();
        await handler.removeManifest(
          MemoryByteSource(second.toBytes()),
          removed,
        );
        await expectLater(
          handler.extractManifest(MemoryByteSource(removed.toBytes())),
          throwsA(isA<ManifestNotFoundException>()),
        );
      });
    });
  }

  group('TIFF multi-IFD and DNG routing', () {
    const handler = TiffAssetHandler();

    test(
      'appends a dedicated IFD without relocating strips or unknown tags',
      () async {
        final source = _multiPageTiff(Endian.little);
        final manifest = Uint8List.fromList(List<int>.filled(24, 4));
        final output = MemoryByteSink();

        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        expect(written.sublist(0, 76), source.sublist(0, 76));
        expect(written.sublist(80, source.length), source.sublist(80));
        expect(_read32(written, 76, Endian.little), greaterThan(source.length));
      },
    );

    test('routes TIFF and DNG MIME and extension hints', () async {
      final source = MemoryByteSource(_singlePageTiff(Endian.little));
      final registry = AssetHandlerRegistry();

      expect(
        (await registry.detect(source, mimeType: 'image/x-adobe-dng')).format,
        AssetFormat.tiff,
      );
      expect(
        (await registry.detect(source, fileExtension: '.DNG')).format,
        AssetFormat.tiff,
      );
      expect(
        (await registry.detect(MemoryByteSource(_singlePageTiff(Endian.big))))
            .format,
        AssetFormat.tiff,
      );
    });
  });

  group('TIFF validation', () {
    const handler = TiffAssetHandler();

    test('rejects BigTIFF explicitly', () {
      expect(
        handler.extractManifest(
          MemoryByteSource(const [0x49, 0x49, 43, 0, 8, 0, 0, 0]),
        ),
        throwsA(isA<UnsupportedTiffVariantException>()),
      );
    });

    test('rejects invalid IFD offsets, counts, and page cycles', () {
      final badOffset = _header(Endian.little, 100);
      final excessiveCount = [
        ..._header(Endian.little, 8),
        0xff,
        0xff,
        0,
        0,
        0,
        0,
      ];
      final cycle = [
        ..._header(Endian.little, 8),
        0,
        0,
        ..._u32(8, Endian.little),
      ];

      expect(
        handler.extractManifest(MemoryByteSource(badOffset)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(excessiveCount)),
        throwsA(isA<SegmentLimitExceededException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(cycle)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects forged entry data ranges and referenced IFD cycles', () {
      final badData = _tiffWithEntries(Endian.little, [
        _entry(65000, 1, 10, 0xfffffff0, Endian.little),
      ]);
      final referenceCycle = _tiffWithEntries(Endian.little, [
        _entry(0x014a, 4, 1, 8, Endian.little),
      ]);

      expect(
        handler.extractManifest(MemoryByteSource(badData)),
        throwsA(isA<TruncatedAssetException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(referenceCycle)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects duplicate C2PA tags across page IFDs', () {
      final duplicate = _twoPageC2paTiff();

      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('enforces source, output, manifest, and IFD limits', () {
      final source = _singlePageTiff(Endian.little);
      final manifest = Uint8List(20);

      expect(
        const TiffAssetHandler(
          maxManifestSize: 10,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        TiffAssetHandler(
          maxSourceSize: source.length - 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        TiffAssetHandler(
          maxOutputSize: source.length,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const TiffAssetHandler(maxIfdCount: 1)
            .extractManifest(MemoryByteSource(_multiPageTiff(Endian.little))),
        throwsA(isA<SegmentLimitExceededException>()),
      );
    });

    test(
      'rejects malformed input before output and propagates sink failures',
      () async {
        final malformedOutput = MemoryByteSink();
        await expectLater(
          handler.embedManifest(
            MemoryByteSource(_header(Endian.little, 100)),
            Uint8List(20),
            malformedOutput,
          ),
          throwsA(isA<TruncatedAssetException>()),
        );
        expect(malformedOutput.toBytes(), isEmpty);

        await expectLater(
          handler.embedManifest(
            MemoryByteSource(_singlePageTiff(Endian.little)),
            Uint8List(20),
            _FailingSink(),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    test('round-trips remote references for TIFF and DNG routing', () async {
      final source = _singlePageTiff(Endian.little);
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
      expect(embedded.toBytes().sublist(8, source.length), source.sublist(8));

      final replaced = MemoryByteSink();
      await AssetHandlerRegistry().updateRemoteManifestReference(
        MemoryByteSource(embedded.toBytes()),
        'self#jumbf=c2pa/two',
        replaced,
        fileExtension: '.DNG',
      );
      expect(
        await handler.readRemoteManifestReference(
          MemoryByteSource(replaced.toBytes()),
        ),
        'self#jumbf=c2pa/two',
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
    });

    test(
      'enforces XMP limits and propagates remote-reference sink failures',
      () {
        final source = _singlePageTiff(Endian.little);
        expect(
          const TiffAssetHandler(maxRemoteReferenceLength: 3)
              .updateRemoteManifestReference(
                MemoryByteSource(source),
                'long',
                MemoryByteSink(),
              ),
          throwsA(isA<AssetLimitExceededException>()),
        );
        expect(
          handler.updateRemoteManifestReference(
            MemoryByteSource(source),
            'https://example.com',
            _FailingSink(),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );
  });
}

List<int> _singlePageTiff(Endian order) {
  const entryCount = 4;
  const ifdOffset = 8;
  const ifdLength = 2 + entryCount * 12 + 4;
  const stripOffset = ifdOffset + ifdLength;
  return [
    ..._header(order, ifdOffset),
    ..._u16(entryCount, order),
    ..._entry(256, 3, 1, 1, order),
    ..._entry(273, 4, 1, stripOffset, order),
    ..._entry(279, 4, 1, 6, order),
    ..._entry(65000, 1, 3, 0x00030201, order),
    ..._u32(0, order),
    10,
    20,
    30,
    40,
    50,
    60,
  ];
}

List<int> _multiPageTiff(Endian order) {
  const firstOffset = 8;
  const firstIfdLength = 2 + 2 * 12 + 4;
  const secondOffset = firstOffset + firstIfdLength;
  const secondIfdLength = 2 + 3 * 12 + 4;
  const pixelsOffset = secondOffset + secondIfdLength;
  return [
    ..._header(order, firstOffset),
    ..._u16(2, order),
    ..._entry(273, 4, 1, pixelsOffset, order),
    ..._entry(65000, 1, 2, 0x00000201, order),
    ..._u32(secondOffset, order),
    ..._u16(3, order),
    ..._entry(324, 4, 1, pixelsOffset + 3, order),
    ..._entry(325, 4, 1, 3, order),
    ..._entry(65001, 1, 2, 0x00000403, order),
    ..._u32(0, order),
    11,
    12,
    13,
    21,
    22,
    23,
  ];
}

List<int> _twoPageC2paTiff() {
  const firstOffset = 8;
  const ifdLength = 18;
  const secondOffset = firstOffset + ifdLength;
  const firstManifest = secondOffset + ifdLength;
  const secondManifest = firstManifest + 8;
  return [
    ..._header(Endian.little, firstOffset),
    ..._u16(1, Endian.little),
    ..._entry(0xcd41, 7, 8, firstManifest, Endian.little),
    ..._u32(secondOffset, Endian.little),
    ..._u16(1, Endian.little),
    ..._entry(0xcd41, 7, 8, secondManifest, Endian.little),
    ..._u32(0, Endian.little),
    ...List<int>.filled(16, 1),
  ];
}

List<int> _tiffWithEntries(Endian order, List<List<int>> entries) => [
  ..._header(order, 8),
  ..._u16(entries.length, order),
  for (final entry in entries) ...entry,
  ..._u32(0, order),
];

List<int> _header(Endian order, int firstIfdOffset) => [
  if (order == Endian.little) ...const [0x49, 0x49] else ...const [0x4d, 0x4d],
  ..._u16(42, order),
  ..._u32(firstIfdOffset, order),
];

List<int> _entry(int tag, int type, int count, int value, Endian order) => [
  ..._u16(tag, order),
  ..._u16(type, order),
  ..._u32(count, order),
  ..._u32(value, order),
];

List<int> _u16(int value, Endian order) {
  final data = ByteData(2)..setUint16(0, value, order);
  return data.buffer.asUint8List();
}

List<int> _u32(int value, Endian order) {
  final data = ByteData(4)..setUint32(0, value, order);
  return data.buffer.asUint8List();
}

int _read32(List<int> bytes, int offset, Endian order) =>
    ByteData.sublistView(Uint8List.fromList(bytes)).getUint32(offset, order);

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

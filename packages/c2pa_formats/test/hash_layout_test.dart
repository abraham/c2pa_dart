import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  final manifest = Uint8List.fromList(
    _isoBox('jumb', [
      ..._isoBox('jumd', [
        ...'c2pa'.codeUnits,
        0,
        0x11,
        0,
        0x10,
        0x80,
        0,
        0,
        0xaa,
        0,
        0x38,
        0x9b,
        0x71,
        1,
      ]),
      ..._isoBox('cbor', List<int>.generate(70000, (index) => index & 0xff)),
    ]),
  );

  group('DataHashLayout', () {
    test('JPEG exclusions cover the physical multipart APP11 store', () async {
      const handler = JpegAssetHandler();
      final source = _baseJpeg();
      final embedded = await _embed(handler, source, manifest);
      final layout = await handler.getDataHashLayout(
        MemoryByteSource(embedded),
      );

      expect(layout.exclusions, hasLength(1));
      for (final exclusion in layout.exclusions) {
        expect(
          embedded.sublist(exclusion.range.start, exclusion.range.start + 2),
          [0xff, 0xeb],
        );
        expect(
          _countPair(
            embedded.sublist(exclusion.range.start, exclusion.range.end),
            0xff,
            0xeb,
          ),
          greaterThan(1),
        );
      }
      _expectComplementReconstructs(layout, embedded);
    });

    test('PNG, GIF, and RIFF exclusions match complete containers', () async {
      const png = PngAssetHandler();
      const gif = GifAssetHandler();
      const riff = RiffAssetHandler(format: AssetFormat.webp);
      final cases = <(AssetHandler, DataHashLayoutProvider, List<int>)>[
        (png, png, _basePng()),
        (gif, gif, _baseGif()),
        (riff, riff, _baseRiff()),
      ];

      for (final (handler, provider, source) in cases) {
        final embedded = await _embed(handler, source, manifest);
        final layout = await provider.getDataHashLayout(
          MemoryByteSource(embedded),
        );
        expect(layout.exclusions, hasLength(1));
        final range = layout.exclusions.single.range;
        final excluded = embedded.sublist(range.start, range.end);
        switch (handler.format) {
          case AssetFormat.png:
            expect(String.fromCharCodes(excluded.sublist(4, 8)), 'caBX');
          case AssetFormat.gif:
            expect(String.fromCharCodes(excluded.sublist(3, 11)), 'C2PA_GIF');
          case AssetFormat.webp:
            expect(String.fromCharCodes(excluded.sublist(0, 4)), 'C2PA');
          default:
            fail('Unexpected format ${handler.format}.');
        }
        _expectComplementReconstructs(layout, embedded);
      }
    });

    test('TIFF excludes the tag value and mutable count field', () async {
      const handler = TiffAssetHandler();
      final embedded = await _embed(
        handler,
        _baseTiff(Endian.little),
        manifest,
      );
      final layout = await handler.getDataHashLayout(
        MemoryByteSource(embedded),
      );

      expect(layout.exclusions, hasLength(2));
      final manifestExclusion = layout.exclusions.singleWhere(
        (entry) => entry.kind == DataHashExclusionKind.manifest,
      );
      final countExclusion = layout.exclusions.singleWhere(
        (entry) => entry.kind == DataHashExclusionKind.mutableMetadata,
      );
      expect(
        embedded.sublist(
          manifestExclusion.range.start,
          manifestExclusion.range.end,
        ),
        manifest,
      );
      expect(
        ByteData.sublistView(
          Uint8List.fromList(
            embedded.sublist(
              countExclusion.range.start,
              countExclusion.range.end,
            ),
          ),
        ).getUint32(0, Endian.little),
        manifest.length,
      );
      _expectComplementReconstructs(layout, embedded);
    });

    test('absent stores report writer-compatible insertion offsets', () async {
      const jpeg = JpegAssetHandler();
      const png = PngAssetHandler();
      const gif = GifAssetHandler();
      const riff = RiffAssetHandler(format: AssetFormat.webp);
      const tiff = TiffAssetHandler();

      final jpegLayout = await jpeg.getDataHashLayout(
        MemoryByteSource(_baseJpeg()),
      );
      final pngLayout = await png.getDataHashLayout(
        MemoryByteSource(_basePng()),
      );
      final gifLayout = await gif.getDataHashLayout(
        MemoryByteSource(_baseGif()),
      );
      final riffSource = _baseRiff();
      final riffLayout = await riff.getDataHashLayout(
        MemoryByteSource(riffSource),
      );
      final tiffSource = _baseTiff(Endian.little);
      final tiffLayout = await tiff.getDataHashLayout(
        MemoryByteSource(tiffSource),
      );

      expect(jpegLayout.insertionOffset, 8);
      expect(pngLayout.insertionOffset, 33);
      expect(gifLayout.insertionOffset, 19);
      expect(riffLayout.insertionOffset, riffSource.length);
      expect(tiffLayout.insertionOffset, _align(tiffSource.length, 4));
      for (final layout in [
        jpegLayout,
        pngLayout,
        gifLayout,
        riffLayout,
        tiffLayout,
      ]) {
        expect(layout.exclusions, isEmpty);
      }
    });
  });

  group('BoxHashLayout', () {
    test('synthetic C2PA entries appear at future insertion points', () async {
      final jpeg = await const JpegAssetHandler().getBoxHashLayout(
        MemoryByteSource(_baseJpeg()),
      );
      final png = await const PngAssetHandler().getBoxHashLayout(
        MemoryByteSource(_basePng()),
      );
      final gif = await const GifAssetHandler().getBoxHashLayout(
        MemoryByteSource(_baseGif()),
      );

      expect(_names(jpeg), ['SOI', 'APP0', 'C2PA', 'APP1', 'SOS', 'EOI']);
      expect(_names(png), ['PNGh', 'IHDR', 'C2PA', 'IEND']);
      expect(_names(gif), ['GIF87a', 'LSD', '', 'C2PA', '2C', 'TBID', '3B']);
      for (final layout in [jpeg, png, gif]) {
        final synthetic = layout.entries.singleWhere(
          (entry) => entry.synthetic,
        );
        expect(synthetic.excluded, isTrue);
        expect(synthetic.range.isEmpty, isTrue);
        _expectBoxesCoverSource(layout);
      }
    });

    test('embedded C2PA entries use exact physical exclusion ranges', () async {
      const jpegHandler = JpegAssetHandler();
      const pngHandler = PngAssetHandler();
      const gifHandler = GifAssetHandler();
      for (final (handler, provider, source)
          in <(AssetHandler, BoxHashLayoutProvider, List<int>)>[
            (jpegHandler, jpegHandler, _baseJpeg()),
            (pngHandler, pngHandler, _basePng()),
            (gifHandler, gifHandler, _baseGif()),
          ]) {
        final embedded = await _embed(handler, source, manifest);
        final dataLayout = await (handler as DataHashLayoutProvider)
            .getDataHashLayout(MemoryByteSource(embedded));
        final boxLayout = await provider.getBoxHashLayout(
          MemoryByteSource(embedded),
        );
        final c2paRanges = boxLayout.entries
            .where((entry) => entry.names.contains('C2PA'))
            .map((entry) => '${entry.range.start}:${entry.range.end}')
            .toList();
        expect(
          c2paRanges,
          dataLayout.exclusions
              .map((entry) => '${entry.range.start}:${entry.range.end}')
              .toList(),
        );
        expect(boxLayout.entries.any((entry) => entry.synthetic), isFalse);
        _expectBoxesCoverSource(boxLayout);
      }
    });

    test('standalone is one physical C2PA entry', () async {
      final layout = await const StandaloneC2paHandler().getBoxHashLayout(
        MemoryByteSource(manifest),
      );

      expect(layout.entries, hasLength(1));
      expect(layout.entries.single.names, ['C2PA']);
      expect(layout.entries.single.range.start, 0);
      expect(layout.entries.single.range.end, manifest.length);
      expect(layout.entries.single.excluded, isFalse);
    });

    test('RIFF and TIFF explicitly reject BoxHash layouts', () {
      expect(
        const RiffAssetHandler(format: AssetFormat.webp)
            .getBoxHashLayout(MemoryByteSource(_baseRiff())),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
      expect(
        const TiffAssetHandler().getBoxHashLayout(
          MemoryByteSource(_baseTiff(Endian.big)),
        ),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
    });
  });

  test('layout APIs reject malformed assets', () {
    expect(
      const JpegAssetHandler().getDataHashLayout(
        MemoryByteSource(const [0xff, 0xd8, 0xff]),
      ),
      throwsA(isA<TruncatedAssetException>()),
    );
    expect(
      const PngAssetHandler().getBoxHashLayout(
        MemoryByteSource(const [0x89, 0x50, 0x4e, 0x47]),
      ),
      throwsA(isA<TruncatedAssetException>()),
    );
  });

  test('capabilities and registry report supported layout kinds', () async {
    final registry = AssetHandlerRegistry();
    final png = registry.handlers.singleWhere(
      (handler) => handler.format == AssetFormat.png,
    );
    final riff = registry.handlers.singleWhere(
      (handler) => handler.format == AssetFormat.webp,
    );

    expect(png.capabilities.canProvideDataHashLayout, isTrue);
    expect(png.capabilities.canProvideBoxHashLayout, isTrue);
    expect(riff.capabilities.canProvideDataHashLayout, isTrue);
    expect(riff.capabilities.canProvideBoxHashLayout, isFalse);
    expect(
      await registry.getDataHashLayout(
        MemoryByteSource(_basePng()),
        mimeType: 'image/png',
      ),
      isA<DataHashLayout>(),
    );
    expect(
      registry.getBoxHashLayout(
        MemoryByteSource(_baseRiff()),
        mimeType: 'image/webp',
      ),
      throwsA(
        isA<UnsupportedHashLayoutException>().having(
          (error) => error.layout,
          'layout',
          HashLayoutKind.boxHash,
        ),
      ),
    );
  });
}

Future<List<int>> _embed(
  AssetHandler handler,
  List<int> source,
  Uint8List manifest,
) async {
  final output = MemoryByteSink();
  await handler.embedManifest(MemoryByteSource(source), manifest, output);
  return output.toBytes();
}

void _expectComplementReconstructs(DataHashLayout layout, List<int> source) {
  final rebuilt = <int>[];
  final ordered = <ByteRange>[
    ...layout.includedRanges,
    for (final exclusion in layout.exclusions) exclusion.range,
  ]..sort((left, right) => left.start.compareTo(right.start));
  for (final range in ordered) {
    rebuilt.addAll(source.sublist(range.start, range.end));
  }
  expect(rebuilt, source);
}

void _expectBoxesCoverSource(BoxHashLayout layout) {
  final bytesCovered = layout.entries
      .where((entry) => !entry.synthetic)
      .fold<int>(0, (total, entry) => total + entry.range.length);
  expect(bytesCovered, layout.sourceLength);
}

List<String> _names(BoxHashLayout layout) => [
  for (final entry in layout.entries) entry.names.join('+'),
];

List<int> _baseJpeg() => [
  0xff,
  0xd8,
  ..._jpegSegment(0xe0, const [1, 2]),
  ..._jpegSegment(0xe1, const [7, 8, 9]),
  ..._jpegSegment(0xda, const [1, 1]),
  1,
  2,
  3,
  4,
  0xff,
  0xd9,
];

List<int> _jpegSegment(int marker, List<int> payload) {
  final length = payload.length + 2;
  return [0xff, marker, length >> 8, length & 0xff, ...payload];
}

List<int> _basePng() => [
  ...const [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  ..._pngChunk('IHDR', List<int>.filled(13, 0)),
  ..._pngChunk('IEND', const []),
];

List<int> _pngChunk(String type, List<int> data) {
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

List<int> _baseGif() => [
  ...'GIF87a'.codeUnits,
  1,
  0,
  1,
  0,
  0x80,
  0,
  0,
  0,
  0,
  0,
  255,
  255,
  255,
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
  0x3b,
];

List<int> _baseRiff() {
  final child = [...'VP8 '.codeUnits, 2, 0, 0, 0, 1, 2];
  final size = 4 + child.length;
  return [
    ...'RIFF'.codeUnits,
    ..._little32(size),
    ...'WEBP'.codeUnits,
    ...child,
  ];
}

List<int> _baseTiff(Endian order) {
  const ifdOffset = 8;
  const entryCount = 1;
  const stripOffset = ifdOffset + 2 + entryCount * 12 + 4;
  return [
    if (order == Endian.little) ...'II'.codeUnits else ...'MM'.codeUnits,
    ..._u16(42, order),
    ..._u32(ifdOffset, order),
    ..._u16(entryCount, order),
    ..._u16(273, order),
    ..._u16(4, order),
    ..._u32(1, order),
    ..._u32(stripOffset, order),
    ..._u32(0, order),
    1,
    2,
    3,
    4,
  ];
}

List<int> _u16(int value, Endian order) {
  final bytes = Uint8List(2);
  ByteData.sublistView(bytes).setUint16(0, value, order);
  return bytes;
}

List<int> _u32(int value, Endian order) {
  final bytes = Uint8List(4);
  ByteData.sublistView(bytes).setUint32(0, value, order);
  return bytes;
}

List<int> _little32(int value) => [
  value & 0xff,
  (value >> 8) & 0xff,
  (value >> 16) & 0xff,
  (value >> 24) & 0xff,
];

List<int> _isoBox(String type, List<int> payload) {
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

int _align(int value, int alignment) => (value + alignment - 1) & -alignment;

int _countPair(List<int> bytes, int first, int second) {
  var count = 0;
  for (var index = 0; index + 1 < bytes.length; index++) {
    if (bytes[index] == first && bytes[index + 1] == second) count++;
  }
  return count;
}

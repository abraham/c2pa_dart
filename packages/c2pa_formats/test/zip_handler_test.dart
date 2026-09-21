import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  const handler = ZipAssetHandler(format: AssetFormat.zip);

  group('ZipAssetHandler', () {
    test(
      'round-trips stored entries and uses the exact manifest path',
      () async {
        final source = _archive([_Entry('hello.txt', utf8.encode('hello'))]);
        final manifest = Uint8List.fromList(const [1, 2, 3, 4]);
        final output = MemoryByteSink();

        expect(await handler.detect(MemoryByteSource(source)), isTrue);
        await handler.embedManifest(MemoryByteSource(source), manifest, output);

        final written = output.toBytes();
        expect(
          await handler.extractManifest(MemoryByteSource(written)),
          manifest,
        );
        final layout = await handler.getCollectionHashLayout(
          MemoryByteSource(written),
        );
        expect(
          layout.entries.map((entry) => entry.uri.path),
          contains('hello.txt'),
        );
        expect(
          layout.entries.map((entry) => entry.uri.path),
          isNot(contains(ZipAssetHandler.manifestPath)),
        );
      },
    );

    test('preserves deflated bytes and data descriptors exactly', () async {
      final source = _archive([
        _Entry(
          'compressed.bin',
          const [1, 2, 3, 4, 5],
          method: 8,
          compressed: const [0x63, 0x64, 0x62],
          descriptor: true,
        ),
        _Entry('streamed.txt', utf8.encode('streamed'), descriptor: true),
        _Entry(
          'unsigned-descriptor.txt',
          const [6, 7],
          descriptor: true,
          descriptorSignature: false,
        ),
      ]);
      final before = await handler.getCollectionHashLayout(
        MemoryByteSource(source),
      );
      final originalRanges = {
        for (final entry in before.entries)
          entry.uri.path: source.sublist(entry.range.start, entry.range.end),
      };
      final output = MemoryByteSink();

      await handler.embedManifest(
        MemoryByteSource(source),
        Uint8List.fromList(const [9]),
        output,
      );

      final written = output.toBytes();
      final after = await handler.getCollectionHashLayout(
        MemoryByteSource(written),
      );
      for (final entry in after.entries) {
        final ranges = originalRanges[entry.uri.path];
        if (ranges != null) {
          expect(written.sublist(entry.range.start, entry.range.end), ranges);
        }
      }
      final streamed = after.entries.singleWhere(
        (entry) => entry.uri.path == 'streamed.txt',
      );
      expect(streamed.range.length, greaterThan(streamed.compressedSize + 30));
    });

    test('replaces and removes without rewriting unrelated entries', () async {
      final source = _archive([
        _Entry('before.txt', const [1, 2]),
        _Entry(ZipAssetHandler.manifestPath, const [3, 4]),
        _Entry('after.txt', const [5, 6], descriptor: true),
      ]);
      final originalLayout = await handler.getCollectionHashLayout(
        MemoryByteSource(source),
      );
      final originalBytes = {
        for (final entry in originalLayout.entries)
          entry.uri.path: source.sublist(entry.range.start, entry.range.end),
      };
      final replacement = Uint8List.fromList(const [7, 8, 9]);
      final replaced = MemoryByteSink();

      await handler.replaceManifest(
        MemoryByteSource(source),
        replacement,
        replaced,
      );
      expect(
        await handler.extractManifest(MemoryByteSource(replaced.toBytes())),
        replacement,
      );
      final replacedLayout = await handler.getCollectionHashLayout(
        MemoryByteSource(replaced.toBytes()),
      );
      for (final entry in replacedLayout.entries) {
        final original = originalBytes[entry.uri.path];
        if (original == null) continue;
        expect(
          replaced.toBytes().sublist(entry.range.start, entry.range.end),
          original,
        );
      }

      final removed = MemoryByteSink();
      await handler.removeManifest(
        MemoryByteSource(replaced.toBytes()),
        removed,
      );
      expect(
        handler.extractManifest(MemoryByteSource(removed.toBytes())),
        throwsA(isA<ManifestNotFoundException>()),
      );
      final removedLayout = await handler.getCollectionHashLayout(
        MemoryByteSource(removed.toBytes()),
      );
      expect(
        removedLayout.entries.map((entry) => entry.uri.path),
        containsAll(<String>['before.txt', 'after.txt']),
      );
    });

    test('parses ZIP64 end records and preserves archive comments', () async {
      final source = _archive(
        [
          _Entry('file.txt', const [1, 2, 3]),
        ],
        zip64: true,
        comment: utf8.encode('keep-comment'),
      );
      final output = MemoryByteSink();
      await handler.embedManifest(
        MemoryByteSource(source),
        Uint8List.fromList(const [4]),
        output,
      );

      expect(
        await handler.extractManifest(MemoryByteSource(output.toBytes())),
        const [4],
      );
      expect(
        utf8.decode(output.toBytes().sublist(output.toBytes().length - 12)),
        'keep-comment',
      );
      expect(_containsSignature(output.toBytes(), 0x06064b50), isTrue);
      expect(_containsSignature(output.toBytes(), 0x07064b50), isTrue);
    });

    test('routes representative ZIP-family formats', () async {
      final fixtures = <AssetFormat, List<int>>{
        AssetFormat.zip: _archive([
          _Entry('file.txt', const [1]),
        ]),
        AssetFormat.epub: _archive([
          _Entry('mimetype', utf8.encode('application/epub+zip')),
          _Entry('META-INF/container.xml', const [1]),
        ]),
        AssetFormat.openDocument: _archive([
          _Entry(
            'mimetype',
            utf8.encode('application/vnd.oasis.opendocument.text'),
          ),
          _Entry('content.xml', const [1]),
        ]),
        AssetFormat.ooxml: _archive([
          _Entry('[Content_Types].xml', const [1]),
          _Entry('word/document.xml', const [2]),
        ]),
        AssetFormat.openXps: _archive([
          _Entry('[Content_Types].xml', const [1]),
          _Entry('FixedDocumentSequence.fdseq', const [2]),
        ]),
      };
      final registry = AssetHandlerRegistry();
      for (final fixture in fixtures.entries) {
        final detected = await registry.detect(MemoryByteSource(fixture.value));
        expect(detected.format, fixture.key);
      }

      expect(
        (await registry.detect(
          MemoryByteSource(const []),
          mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        )).format,
        AssetFormat.ooxml,
      );
      expect(
        (await registry.detect(
          MemoryByteSource(const []),
          fileExtension: '.ODT',
        )).format,
        AssetFormat.openDocument,
      );
    });

    test('exposes safe URIs, sizes, MIME hints, and complete ranges', () async {
      final source = _archive([
        _Entry(r'folder\image.png', const [1, 2, 3], descriptor: true),
        _Entry('empty/', const [], directory: true),
      ]);
      final layout = await AssetHandlerRegistry().getCollectionHashLayout(
        MemoryByteSource(source),
        mimeType: 'application/zip',
      );
      final image = layout.entries.singleWhere(
        (entry) => entry.uri.path == 'folder/image.png',
      );

      expect(image.compressedSize, 3);
      expect(image.uncompressedSize, 3);
      expect(image.compressionMethod, 0);
      expect(image.mimeType, 'image/png');
      expect(image.isDirectory, isFalse);
      expect(
        source.sublist(image.range.start, image.range.start + 4),
        _little32(0x04034b50),
      );
      expect(
        source.sublist(image.range.end - 16, image.range.end - 12),
        _little32(0x08074b50),
      );
      expect(
        layout.entries.singleWhere((entry) => entry.isDirectory).uri.path,
        'empty/',
      );
    });

    test('exposes central-directory hash ranges and material', () async {
      final source = _archive([
        _Entry('a.txt', const [1]),
        _Entry(ZipAssetHandler.manifestPath, const [2, 3]),
      ]);
      final layout = await handler.getCollectionHashLayout(
        MemoryByteSource(source),
      );
      final material = await handler.readCentralDirectoryHashMaterial(
        MemoryByteSource(source),
      );
      final expected = <int>[
        for (final range in layout.centralDirectoryHashRanges)
          ...source.sublist(range.start, range.end),
      ];

      expect(layout.centralDirectoryHashRanges, hasLength(2));
      expect(
        layout.centralDirectoryHashRanges[1].start -
            layout.centralDirectoryHashRanges[0].end,
        4,
      );
      expect(material, expected);
      expect(handler.capabilities.canProvideCollectionHashLayout, isTrue);
    });

    test('rejects ZIP-slip and normalized duplicate paths', () {
      final unsafe = _archive([
        _Entry('../evil.txt', const [1]),
      ]);
      final duplicate = _archive([
        _Entry(r'a\b.txt', const [1]),
        _Entry('a/b.txt', const [2]),
      ]);

      expect(
        handler.getCollectionHashLayout(MemoryByteSource(unsafe)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.getCollectionHashLayout(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects overlapping local entry ranges', () {
      final source = _archive([
        _Entry('a.txt', const [1]),
        _Entry('b.txt', const [2]),
      ]);
      final centralOffset = _findSignature(source, 0x02014b50);
      source
        ..setRange(18, 22, _little32(10))
        ..setRange(22, 26, _little32(10))
        ..setRange(centralOffset + 20, centralOffset + 24, _little32(10))
        ..setRange(centralOffset + 24, centralOffset + 28, _little32(10));

      expect(
        handler.getCollectionHashLayout(MemoryByteSource(source)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
    });

    test('rejects duplicate manifests and encrypted entries', () {
      final duplicate = _archive([
        _Entry(ZipAssetHandler.manifestPath, const [1]),
        _Entry(ZipAssetHandler.manifestPath, const [2]),
      ]);
      final encrypted = _archive([
        _Entry('secret.txt', const [1], flags: 1),
      ]);

      expect(
        handler.extractManifest(MemoryByteSource(duplicate)),
        throwsA(isA<MalformedAssetFormatException>()),
      );
      expect(
        handler.getCollectionHashLayout(MemoryByteSource(encrypted)),
        throwsA(isA<UnsupportedZipFeatureException>()),
      );
    });

    test('rejects malformed headers, descriptors, and multi-disk ZIP', () {
      final badLocal = _archive([
        _Entry('a.txt', const [1]),
      ])..[0] = 0;
      final badDescriptor = _archive([
        _Entry('a.txt', const [1], descriptor: true),
      ]);
      final descriptorOffset = _findSignature(badDescriptor, 0x08074b50);
      badDescriptor[descriptorOffset + 4] ^= 0xff;
      final multiDisk = _archive([
        _Entry('a.txt', const [1]),
      ]);
      final eocd = _findSignature(multiDisk, 0x06054b50);
      multiDisk[eocd + 4] = 1;

      for (final source in [badLocal, badDescriptor]) {
        expect(
          handler.getCollectionHashLayout(MemoryByteSource(source)),
          throwsA(isA<MalformedAssetFormatException>()),
        );
      }
      expect(
        handler.getCollectionHashLayout(MemoryByteSource(multiDisk)),
        throwsA(isA<UnsupportedZipFeatureException>()),
      );
      expect(
        handler.getCollectionHashLayout(
          MemoryByteSource(const [0x50, 0x4b, 1]),
        ),
        throwsA(isA<TruncatedAssetException>()),
      );
    });

    test('rejects unsupported compression and compressed manifests', () {
      final unsupported = _archive([
        _Entry('a.bin', const [1], method: 99),
      ]);
      final compressedManifest = _archive([
        _Entry(
          ZipAssetHandler.manifestPath,
          const [1, 2],
          method: 8,
          compressed: const [3],
        ),
      ]);

      expect(
        handler.getCollectionHashLayout(MemoryByteSource(unsupported)),
        throwsA(isA<UnsupportedZipFeatureException>()),
      );
      expect(
        handler.extractManifest(MemoryByteSource(compressedManifest)),
        throwsA(isA<UnsupportedZipFeatureException>()),
      );
      expect(
        AssetHandlerRegistry().getDataHashLayout(
          MemoryByteSource(
            _archive([
              _Entry('a.txt', const [1]),
            ]),
          ),
          mimeType: 'application/zip',
        ),
        throwsA(isA<UnsupportedHashLayoutException>()),
      );
    });

    test('enforces source, output, manifest, entry, and name limits', () {
      final source = _archive([
        _Entry('a.txt', const [1]),
        _Entry('b.txt', const [2]),
      ]);
      final manifest = Uint8List.fromList(const [3, 4]);

      expect(
        const ZipAssetHandler(
          format: AssetFormat.zip,
          maxManifestSize: 1,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        ZipAssetHandler(
          format: AssetFormat.zip,
          maxSourceSize: source.length - 1,
        ).getCollectionHashLayout(MemoryByteSource(source)),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        ZipAssetHandler(
          format: AssetFormat.zip,
          maxOutputSize: source.length,
        ).embedManifest(MemoryByteSource(source), manifest, MemoryByteSink()),
        throwsA(isA<AssetLimitExceededException>()),
      );
      expect(
        const ZipAssetHandler(
          format: AssetFormat.zip,
          maxEntryCount: 1,
        ).getCollectionHashLayout(MemoryByteSource(source)),
        throwsA(isA<SegmentLimitExceededException>()),
      );
      expect(
        const ZipAssetHandler(
          format: AssetFormat.zip,
          maxNameLength: 3,
        ).getCollectionHashLayout(MemoryByteSource(source)),
        throwsA(isA<AssetLimitExceededException>()),
      );
    });

    test('propagates sink failures after staged validation', () {
      final source = _archive([
        _Entry('a.txt', const [1]),
      ]);

      expect(
        handler.embedManifest(
          MemoryByteSource(source),
          Uint8List.fromList(const [2]),
          _FailingSink(),
        ),
        throwsA(isA<StateError>()),
      );
    });
  });
}

final class _Entry {
  const _Entry(
    this.name,
    this.data, {
    this.method = 0,
    this.compressed,
    this.descriptor = false,
    this.directory = false,
    this.flags = 0,
    this.descriptorSignature = true,
  });

  final String name;
  final List<int> data;
  final int method;
  final List<int>? compressed;
  final bool descriptor;
  final bool directory;
  final int flags;
  final bool descriptorSignature;
}

List<int> _archive(
  List<_Entry> entries, {
  bool zip64 = false,
  List<int> comment = const [],
}) {
  final output = <int>[];
  final central = <List<int>>[];
  for (final entry in entries) {
    final offset = output.length;
    final name = utf8.encode(entry.name);
    final compressed = entry.compressed ?? entry.data;
    final crc = _crc32(entry.data);
    final flags = entry.flags | 0x0800 | (entry.descriptor ? 0x0008 : 0);
    output.addAll([
      ..._little32(0x04034b50),
      ..._little16(20),
      ..._little16(flags),
      ..._little16(entry.method),
      ..._little16(0),
      ..._little16(0),
      ..._little32(entry.descriptor ? 0 : crc),
      ..._little32(entry.descriptor ? 0 : compressed.length),
      ..._little32(entry.descriptor ? 0 : entry.data.length),
      ..._little16(name.length),
      ..._little16(0),
      ...name,
      ...compressed,
      if (entry.descriptor) ...[
        if (entry.descriptorSignature) ..._little32(0x08074b50),
        ..._little32(crc),
        ..._little32(compressed.length),
        ..._little32(entry.data.length),
      ],
    ]);
    central.add([
      ..._little32(0x02014b50),
      ..._little16(0x0314),
      ..._little16(20),
      ..._little16(flags),
      ..._little16(entry.method),
      ..._little16(0),
      ..._little16(0),
      ..._little32(crc),
      ..._little32(compressed.length),
      ..._little32(entry.data.length),
      ..._little16(name.length),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little16(0),
      ..._little32(entry.directory ? 0x41ed0010 : 0x81a40000),
      ..._little32(offset),
      ...name,
    ]);
  }
  final centralOffset = output.length;
  for (final record in central) {
    output.addAll(record);
  }
  final centralSize = output.length - centralOffset;
  if (zip64) {
    final zip64Offset = output.length;
    output.addAll([
      ..._little32(0x06064b50),
      ..._little64(44),
      ..._little16(45),
      ..._little16(45),
      ..._little32(0),
      ..._little32(0),
      ..._little64(entries.length),
      ..._little64(entries.length),
      ..._little64(centralSize),
      ..._little64(centralOffset),
      ..._little32(0x07064b50),
      ..._little32(0),
      ..._little64(zip64Offset),
      ..._little32(1),
    ]);
  }
  output.addAll([
    ..._little32(0x06054b50),
    ..._little16(0),
    ..._little16(0),
    ..._little16(zip64 ? 0xffff : entries.length),
    ..._little16(zip64 ? 0xffff : entries.length),
    ..._little32(zip64 ? 0xffffffff : centralSize),
    ..._little32(zip64 ? 0xffffffff : centralOffset),
    ..._little16(comment.length),
    ...comment,
  ]);
  return output;
}

int _findSignature(List<int> bytes, int signature) {
  final pattern = _little32(signature);
  for (var offset = 0; offset <= bytes.length - 4; offset++) {
    if (bytes[offset] == pattern[0] &&
        bytes[offset + 1] == pattern[1] &&
        bytes[offset + 2] == pattern[2] &&
        bytes[offset + 3] == pattern[3]) {
      return offset;
    }
  }
  return -1;
}

bool _containsSignature(List<int> bytes, int signature) =>
    _findSignature(bytes, signature) >= 0;

List<int> _little16(int value) => [value & 0xff, value >> 8 & 0xff];

List<int> _little32(int value) => [
  value & 0xff,
  value >> 8 & 0xff,
  value >> 16 & 0xff,
  value >> 24 & 0xff,
];

List<int> _little64(int value) => [..._little32(value), 0, 0, 0, 0];

int _crc32(List<int> bytes) {
  var crc = 0xffffffff;
  for (final byte in bytes) {
    crc ^= byte;
    for (var bit = 0; bit < 8; bit++) {
      crc = crc & 1 == 0 ? crc >> 1 : (crc >> 1) ^ 0xedb88320;
    }
  }
  return (crc ^ 0xffffffff) & 0xffffffff;
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

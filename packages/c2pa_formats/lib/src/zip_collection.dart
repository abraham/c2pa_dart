import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

final class ZipCollectionEntry {
  const ZipCollectionEntry({
    required this.uri,
    required this.range,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.compressionMethod,
    required this.isDirectory,
    this.mimeType,
  });

  final Uri uri;
  final ByteRange range;
  final int compressedSize;
  final int uncompressedSize;
  final int compressionMethod;
  final bool isDirectory;
  final String? mimeType;
}

final class ZipCollectionLayout {
  ZipCollectionLayout({
    required Iterable<ZipCollectionEntry> entries,
    required Iterable<ByteRange> centralDirectoryHashRanges,
  }) : entries = List<ZipCollectionEntry>.unmodifiable(entries),
       centralDirectoryHashRanges = List<ByteRange>.unmodifiable(
         centralDirectoryHashRanges,
       );

  final List<ZipCollectionEntry> entries;
  final List<ByteRange> centralDirectoryHashRanges;
}

abstract interface class ZipCollectionLayoutProvider {
  Future<ZipCollectionLayout> getCollectionHashLayout(
    RandomAccessByteSource source,
  );

  Future<Uint8List> readCentralDirectoryHashMaterial(
    RandomAccessByteSource source,
  );
}

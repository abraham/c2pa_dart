import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

/// A ZIP member entry participating in C2PA collection hashing.
final class ZipCollectionEntry {
  /// Creates collection metadata for one ZIP entry.
  const ZipCollectionEntry({
    required this.uri,
    required this.range,
    required this.compressedSize,
    required this.uncompressedSize,
    required this.compressionMethod,
    required this.isDirectory,
    this.mimeType,
  });

  /// Normalized entry URI used by the C2PA collection hash.
  final Uri uri;

  /// Absolute local-file-header bytes for the entry, as `[start, end)`.
  final ByteRange range;

  /// Compressed payload size in bytes from the ZIP central directory.
  final int compressedSize;

  /// Uncompressed payload size in bytes from the ZIP central directory.
  final int uncompressedSize;

  /// ZIP compression method number recorded for the entry.
  final int compressionMethod;

  /// Whether the entry name represents a directory.
  final bool isDirectory;

  /// Best-effort MIME type for [uri], or `null` when unknown.
  final String? mimeType;
}

/// A C2PA collection-hash layout for a ZIP-like archive.
final class ZipCollectionLayout {
  /// Creates a collection layout from archive [entries] and hash ranges.
  ZipCollectionLayout({
    required Iterable<ZipCollectionEntry> entries,
    required Iterable<ByteRange> centralDirectoryHashRanges,
  }) : entries = List<ZipCollectionEntry>.unmodifiable(entries),
       centralDirectoryHashRanges = List<ByteRange>.unmodifiable(
         centralDirectoryHashRanges,
       );

  /// ZIP entries included in collection hashing, excluding the C2PA manifest.
  final List<ZipCollectionEntry> entries;

  /// Absolute central-directory ranges hashed as raw bytes.
  final List<ByteRange> centralDirectoryHashRanges;
}

/// A handler capability for ZIP collection-hash metadata.
abstract interface class ZipCollectionLayoutProvider {
  /// Builds the ZIP collection-hash layout for [source].
  Future<ZipCollectionLayout> getCollectionHashLayout(
    RandomAccessByteSource source,
  );

  /// Reads the central-directory bytes included in collection hashing.
  Future<Uint8List> readCentralDirectoryHashMaterial(
    RandomAccessByteSource source,
  );
}

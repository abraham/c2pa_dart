import 'package:c2pa_io/c2pa_io.dart';

/// The reason a byte range is omitted from a data hash.
enum DataHashExclusionKind {
  /// Embedded C2PA manifest bytes excluded from content hashing.
  manifest,

  /// Mutable metadata bytes, such as XMP, excluded from content hashing.
  mutableMetadata,
}

/// A byte range that must be excluded from C2PA data hashing.
final class DataHashExclusion {
  /// Creates an exclusion for an absolute half-open [range].
  const DataHashExclusion({
    required this.range,
    required this.kind,
    required this.name,
  });

  /// The absolute source bytes to skip, expressed as `[start, end)`.
  final ByteRange range;

  /// The C2PA reason the [range] is excluded.
  final DataHashExclusionKind kind;

  /// The format-specific box, chunk, segment, or tag name being excluded.
  final String name;
}

/// A C2PA data-hash plan for one contiguous asset byte stream.
final class DataHashLayout {
  /// Creates a layout from source bounds and ordered exclusions.
  ///
  /// [sourceLength] and [insertionOffset] are absolute byte coordinates.
  /// Throws [ArgumentError] if bounds are negative, if [insertionOffset] is
  /// outside the portable byte-coordinate range, or if [exclusions] are not
  /// sorted, non-overlapping, and bounded by [sourceLength].
  DataHashLayout({
    required this.sourceLength,
    required this.insertionOffset,
    Iterable<DataHashExclusion> exclusions = const [],
  }) : exclusions = List<DataHashExclusion>.unmodifiable(exclusions) {
    if (sourceLength < 0 ||
        insertionOffset < 0 ||
        insertionOffset > ByteRange.maxCoordinate) {
      throw ArgumentError('Invalid data-hash layout bounds.');
    }
    var previousEnd = 0;
    for (final exclusion in this.exclusions) {
      if (exclusion.range.start < previousEnd ||
          exclusion.range.end > sourceLength) {
        throw ArgumentError(
          'Data-hash exclusions must be ordered and bounded.',
        );
      }
      previousEnd = exclusion.range.end;
    }
  }

  /// Total number of bytes in the source asset.
  final int sourceLength;

  /// Absolute byte offset where a new manifest would be inserted.
  final int insertionOffset;

  /// Ordered, non-overlapping ranges omitted from the data hash.
  final List<DataHashExclusion> exclusions;

  /// Half-open ranges included in the data hash after applying [exclusions].
  List<ByteRange> get includedRanges {
    final included = <ByteRange>[];
    var offset = 0;
    for (final exclusion in exclusions) {
      if (offset < exclusion.range.start) {
        included.add(ByteRange(offset, exclusion.range.start));
      }
      offset = exclusion.range.end;
    }
    if (offset < sourceLength) included.add(ByteRange(offset, sourceLength));
    return List<ByteRange>.unmodifiable(included);
  }
}

/// One logical box entry used when constructing C2PA box hashes.
final class BoxHashEntry {
  /// Creates a box-hash entry over an absolute half-open [range].
  BoxHashEntry({
    required Iterable<String> names,
    required this.range,
    this.excluded = false,
    this.synthetic = false,
  }) : names = List<String>.unmodifiable(names);

  /// Logical container names from outermost to innermost.
  final List<String> names;

  /// Absolute source bytes covered by this entry, expressed as `[start, end)`.
  final ByteRange range;

  /// Whether the entry is excluded from the box hash.
  final bool excluded;

  /// Whether the entry represents an insertion point not present in source.
  final bool synthetic;
}

/// An ordered set of box-hash entries for a source asset.
final class BoxHashLayout {
  /// Creates a box-hash layout with bounded, ordered [entries].
  ///
  /// Throws [ArgumentError] if [sourceLength] is negative or any non-synthetic
  /// entry overlaps, is out of order, or extends beyond [sourceLength].
  BoxHashLayout({
    required this.sourceLength,
    required Iterable<BoxHashEntry> entries,
  }) : entries = List<BoxHashEntry>.unmodifiable(entries) {
    if (sourceLength < 0) throw ArgumentError.value(sourceLength);
    var previousEnd = 0;
    for (final entry in this.entries) {
      if (entry.range.start < previousEnd || entry.range.end > sourceLength) {
        throw ArgumentError('Box-hash entries must be ordered and bounded.');
      }
      if (!entry.synthetic) previousEnd = entry.range.end;
    }
  }

  /// Total number of bytes in the source asset.
  final int sourceLength;

  /// Ordered logical boxes participating in the box-hash layout.
  final List<BoxHashEntry> entries;
}

/// A handler capability for describing C2PA data-hash byte ranges.
abstract interface class DataHashLayoutProvider {
  /// Builds the data-hash layout for [source] without mutating it.
  Future<DataHashLayout> getDataHashLayout(RandomAccessByteSource source);
}

/// A handler capability for describing C2PA box-hash entries.
abstract interface class BoxHashLayoutProvider {
  /// Builds the box-hash layout for [source] without mutating it.
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source);
}

import 'package:c2pa_io/c2pa_io.dart';

enum DataHashExclusionKind { manifest, mutableMetadata }

final class DataHashExclusion {
  const DataHashExclusion({
    required this.range,
    required this.kind,
    required this.name,
  });

  final ByteRange range;
  final DataHashExclusionKind kind;
  final String name;
}

final class DataHashLayout {
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

  final int sourceLength;
  final int insertionOffset;
  final List<DataHashExclusion> exclusions;

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

final class BoxHashEntry {
  BoxHashEntry({
    required Iterable<String> names,
    required this.range,
    this.excluded = false,
    this.synthetic = false,
  }) : names = List<String>.unmodifiable(names);

  final List<String> names;
  final ByteRange range;
  final bool excluded;
  final bool synthetic;
}

final class BoxHashLayout {
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

  final int sourceLength;
  final List<BoxHashEntry> entries;
}

abstract interface class DataHashLayoutProvider {
  Future<DataHashLayout> getDataHashLayout(RandomAccessByteSource source);
}

abstract interface class BoxHashLayoutProvider {
  Future<BoxHashLayout> getBoxHashLayout(RandomAccessByteSource source);
}

import 'byte_io_exceptions.dart';

/// A half-open byte range, `[start, end)`.
final class ByteRange implements Comparable<ByteRange> {
  /// Creates a half-open range from [start] inclusive to [end] exclusive.
  ByteRange(this.start, this.end) {
    _checkCoordinate(start, 'start');
    _checkCoordinate(end, 'end');
    if (end < start) {
      throw InvalidByteRangeException(
        'Range end ($end) must not be less than start ($start).',
      );
    }
  }

  /// Creates a range beginning at [start] and spanning [length] bytes.
  ByteRange.fromStartAndLength(int start, int length)
    : this(start, checkedAdd(start, length));

  /// Largest integer that is represented exactly on every Dart platform.
  static const int maxCoordinate = 0x1fffffffffffff;

  /// Byte offset of the first byte in the range, relative to the asset start.
  final int start;

  /// Byte offset immediately after the last byte in the range.
  final int end;

  /// Number of bytes covered by this range.
  int get length => end - start;

  /// Whether this range covers no bytes.
  bool get isEmpty => start == end;

  /// Adds two non-negative coordinates and checks for cross-platform overflow.
  static int checkedAdd(int left, int right) {
    _checkCoordinate(left, 'left operand');
    _checkCoordinate(right, 'right operand');
    if (right > maxCoordinate - left) {
      throw ByteRangeOverflowException(
        'Adding $left and $right exceeds $maxCoordinate.',
      );
    }
    return left + right;
  }

  /// Whether [offset] is within this range.
  bool containsOffset(int offset) {
    _checkCoordinate(offset, 'offset');
    return start <= offset && offset < end;
  }

  /// Whether [other] is fully contained by this range.
  bool containsRange(ByteRange other) =>
      start <= other.start && other.end <= end;

  /// Whether this range and [other] cover at least one common byte.
  bool overlaps(ByteRange other) => start < other.end && other.start < end;

  /// The common non-empty range shared with [other], or `null`.
  ByteRange? intersection(ByteRange other) {
    final intersectionStart = start > other.start ? start : other.start;
    final intersectionEnd = end < other.end ? end : other.end;
    return intersectionStart < intersectionEnd
        ? ByteRange(intersectionStart, intersectionEnd)
        : null;
  }

  /// Creates a range translated forward by [delta] bytes.
  ByteRange shift(int delta) =>
      ByteRange(checkedAdd(start, delta), checkedAdd(end, delta));

  @override
  int compareTo(ByteRange other) {
    final startComparison = start.compareTo(other.start);
    return startComparison != 0 ? startComparison : end.compareTo(other.end);
  }

  @override
  bool operator ==(Object other) =>
      other is ByteRange && start == other.start && end == other.end;

  @override
  int get hashCode => Object.hash(start, end);

  @override
  String toString() => '[$start, $end)';

  static void _checkCoordinate(int value, String name) {
    if (value < 0) {
      throw InvalidByteRangeException('$name must be non-negative: $value.');
    }
    if (value > maxCoordinate) {
      throw ByteRangeOverflowException(
        '$name exceeds the cross-platform limit $maxCoordinate: $value.',
      );
    }
  }
}

/// Sorts ranges and merges overlapping or adjacent non-empty ranges.
List<ByteRange> mergeByteRanges(Iterable<ByteRange> ranges) {
  final sorted = ranges.where((range) => !range.isEmpty).toList()..sort();
  if (sorted.isEmpty) return const [];

  final merged = <ByteRange>[];
  var current = sorted.first;
  for (final next in sorted.skip(1)) {
    if (next.start <= current.end) {
      if (next.end > current.end) {
        current = ByteRange(current.start, next.end);
      }
    } else {
      merged.add(current);
      current = next;
    }
  }
  merged.add(current);
  return List.unmodifiable(merged);
}

/// Returns portions of [container] not covered by [excluded].
///
/// Empty exclusions are ignored. Every non-empty exclusion must be fully
/// contained by [container].
List<ByteRange> complementByteRanges(
  ByteRange container,
  Iterable<ByteRange> excluded,
) {
  final checked = <ByteRange>[];
  for (final range in excluded) {
    if (range.isEmpty) continue;
    if (!container.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, container);
    }
    checked.add(range);
  }

  final result = <ByteRange>[];
  var cursor = container.start;
  for (final range in mergeByteRanges(checked)) {
    if (cursor < range.start) result.add(ByteRange(cursor, range.start));
    cursor = range.end;
  }
  if (cursor < container.end) result.add(ByteRange(cursor, container.end));
  return List.unmodifiable(result);
}

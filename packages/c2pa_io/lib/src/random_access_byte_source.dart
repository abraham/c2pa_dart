import 'dart:typed_data';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';
import 'byte_sink.dart';

/// An asynchronously readable, fixed-length random-access byte source.
///
/// Implementations must either return exactly the requested range's length or
/// throw.
/// Returned bytes must not alias mutable source storage.
abstract interface class RandomAccessByteSource {
  /// Total number of bytes available from the source.
  Future<int> get length;

  /// Reads exactly the bytes covered by [range].
  Future<Uint8List> read(ByteRange range);
}

/// A fixed random-access byte source backed by an isolated in-memory copy.
final class MemoryByteSource implements RandomAccessByteSource {
  /// Creates a source from [bytes], copying them into immutable source state.
  MemoryByteSource(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;

  @override
  Future<int> get length async => _bytes.length;

  @override
  Future<Uint8List> read(ByteRange range) async {
    final available = ByteRange(0, _bytes.length);
    if (!available.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, available);
    }
    return Uint8List.fromList(_bytes.sublist(range.start, range.end));
  }
}

/// Copies [range] from [source] to [sink] without closing [sink].
Future<void> copyByteRange(
  RandomAccessByteSource source,
  WritableByteSink sink,
  ByteRange range, {
  int chunkSize = 64 * 1024,
}) async {
  if (chunkSize <= 0) {
    throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
  }

  var offset = range.start;
  while (offset < range.end) {
    final remaining = range.end - offset;
    final count = remaining < chunkSize ? remaining : chunkSize;
    final chunkRange = ByteRange.fromStartAndLength(offset, count);
    final bytes = await source.read(chunkRange);
    if (bytes.length != count) {
      throw TruncatedReadException(
        range: chunkRange,
        expectedLength: count,
        actualLength: bytes.length,
      );
    }
    await sink.append(bytes);
    offset = chunkRange.end;
  }
}

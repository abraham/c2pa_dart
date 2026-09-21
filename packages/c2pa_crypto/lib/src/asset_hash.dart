import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'hash_algorithm.dart';

typedef AssetHashCancellationCallback = FutureOr<bool> Function();
typedef AssetHashProgressCallback = void Function(AssetHashProgress progress);

/// Progress reported after each source chunk or injected-byte event.
final class AssetHashProgress {
  const AssetHashProgress({
    required this.bytesProcessed,
    required this.totalBytes,
    required this.eventIndex,
    this.sourceRange,
  });

  final int bytesProcessed;
  final int totalBytes;
  final int eventIndex;
  final ByteRange? sourceRange;

  double get fraction => totalBytes == 0 ? 1 : bytesProcessed / totalBytes;
}

/// One ordered input event in an asset hash stream.
sealed class AssetHashEvent {
  const AssetHashEvent();
  int get length;
}

/// Hashes bytes read from [range].
final class AssetHashRangeEvent extends AssetHashEvent {
  const AssetHashRangeEvent(this.range);

  final ByteRange range;

  @override
  int get length => range.length;
}

/// Hashes caller-provided bytes between source ranges.
///
/// This is suitable for future BMFF hard-binding fields such as encoded
/// 64-bit offsets without changing the source-range streaming machinery.
final class AssetHashInjectedBytesEvent extends AssetHashEvent {
  AssetHashInjectedBytesEvent(List<int> bytes)
    : _bytes = Uint8List.fromList(_checkedBytes(bytes, 'bytes'));

  final Uint8List _bytes;

  Uint8List get bytes => Uint8List.fromList(_bytes);

  @override
  int get length => _bytes.length;
}

/// Digest associated with one independent source range.
final class AssetRangeDigest {
  AssetRangeDigest(this.range, List<int> digest)
    : _digest = Uint8List.fromList(digest);

  final ByteRange range;
  final Uint8List _digest;

  Uint8List get digest => Uint8List.fromList(_digest);
}

sealed class AssetHashException implements Exception {
  const AssetHashException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

final class AssetHashCancelledException extends AssetHashException {
  const AssetHashCancelledException() : super('Asset hashing was cancelled');
}

final class AssetHashSourceLengthChangedException extends AssetHashException {
  const AssetHashSourceLengthChangedException(this.before, this.after)
    : super('Source length changed from $before to $after while hashing');

  final int before;
  final int after;
}

final class AssetHashShortReadException extends AssetHashException {
  const AssetHashShortReadException({
    required this.range,
    required this.expectedLength,
    required this.actualLength,
  }) : super('Read $actualLength bytes for $range; expected $expectedLength');

  final ByteRange range;
  final int expectedLength;
  final int actualLength;
}

/// Streaming asset hashing over random-access sources.
final class AssetHashEngine {
  AssetHashEngine({
    this.chunkSize = 64 * 1024,
    this.isCancelled,
    this.onProgress,
  }) {
    if (chunkSize <= 0 || chunkSize > ByteRange.maxCoordinate) {
      throw ArgumentError.value(
        chunkSize,
        'chunkSize',
        'Must be between 1 and ${ByteRange.maxCoordinate}',
      );
    }
  }

  final int chunkSize;
  final AssetHashCancellationCallback? isCancelled;
  final AssetHashProgressCallback? onProgress;

  /// Hashes the entire source without whole-file buffering.
  Future<Uint8List> digestSource(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
  ) async {
    final length = await _checkedSourceLength(source);
    return _digestEventsAtLength(source, algorithm, [
      AssetHashRangeEvent(ByteRange(0, length)),
    ], length);
  }

  /// Hashes ordered, non-overlapping inclusion ranges as one byte stream.
  Future<Uint8List> digestRanges(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
    Iterable<ByteRange> ranges,
  ) async {
    final length = await _checkedSourceLength(source);
    final events = ranges
        .map<AssetHashEvent>(AssetHashRangeEvent.new)
        .toList(growable: false);
    _validateEvents(events, length);
    return _digestEventsAtLength(source, algorithm, events, length);
  }

  /// Normalizes exclusions and hashes their ordered complement.
  Future<Uint8List> digestExcluding(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
    Iterable<ByteRange> exclusions,
  ) async {
    final length = await _checkedSourceLength(source);
    final included = complementByteRanges(ByteRange(0, length), exclusions);
    return _digestEventsAtLength(
      source,
      algorithm,
      included.map<AssetHashEvent>(AssetHashRangeEvent.new).toList(),
      length,
    );
  }

  /// Hashes ordered source ranges and injected bytes as one stream.
  Future<Uint8List> digestEvents(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
    Iterable<AssetHashEvent> events,
  ) async {
    final length = await _checkedSourceLength(source);
    final copied = List<AssetHashEvent>.unmodifiable(events);
    _validateEvents(copied, length);
    return _digestEventsAtLength(source, algorithm, copied, length);
  }

  /// Computes an independent digest for each range, preserving input order.
  Future<List<AssetRangeDigest>> digestRangesIndependently(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
    Iterable<ByteRange> ranges,
  ) async {
    final sourceLength = await _checkedSourceLength(source);
    final copied = List<ByteRange>.unmodifiable(ranges);
    for (final range in copied) {
      if (!ByteRange(0, sourceLength).containsRange(range)) {
        throw ByteRangeOutOfBoundsException(range, ByteRange(0, sourceLength));
      }
    }
    final total = _checkedTotal(copied.map((range) => range.length));
    var processed = 0;
    final results = <AssetRangeDigest>[];
    for (var index = 0; index < copied.length; index++) {
      final range = copied[index];
      final sink = _hashImplementation(algorithm).newHashSink();
      var offset = range.start;
      while (offset < range.end) {
        await _checkCancellation();
        final count = _minimum(chunkSize, range.end - offset);
        final chunkRange = ByteRange.fromStartAndLength(offset, count);
        final chunk = await _readChunk(source, chunkRange, count, sourceLength);
        sink.add(chunk);
        offset = chunkRange.end;
        processed = ByteRange.checkedAdd(processed, count);
        onProgress?.call(
          AssetHashProgress(
            bytesProcessed: processed,
            totalBytes: total,
            eventIndex: index,
            sourceRange: chunkRange,
          ),
        );
      }
      sink.close();
      results.add(AssetRangeDigest(range, (await sink.hash()).bytes));
    }
    await _checkCancellation();
    await _requireUnchangedLength(source, sourceLength);
    return List.unmodifiable(results);
  }

  Future<Uint8List> _digestEventsAtLength(
    RandomAccessByteSource source,
    HashAlgorithm algorithm,
    List<AssetHashEvent> events,
    int sourceLength,
  ) async {
    if (chunkSize <= 0 || chunkSize > ByteRange.maxCoordinate) {
      throw ArgumentError.value(
        chunkSize,
        'chunkSize',
        'Must be between 1 and ${ByteRange.maxCoordinate}',
      );
    }
    _validateEvents(events, sourceLength);
    final total = _checkedTotal(events.map((event) => event.length));
    final sink = _hashImplementation(algorithm).newHashSink();
    var processed = 0;
    for (var index = 0; index < events.length; index++) {
      await _checkCancellation();
      final event = events[index];
      switch (event) {
        case AssetHashRangeEvent():
          var offset = event.range.start;
          while (offset < event.range.end) {
            await _checkCancellation();
            final count = _minimum(chunkSize, event.range.end - offset);
            final chunkRange = ByteRange.fromStartAndLength(offset, count);
            final chunk = await _readChunk(
              source,
              chunkRange,
              count,
              sourceLength,
            );
            sink.add(chunk);
            offset = chunkRange.end;
            processed = ByteRange.checkedAdd(processed, count);
            onProgress?.call(
              AssetHashProgress(
                bytesProcessed: processed,
                totalBytes: total,
                eventIndex: index,
                sourceRange: chunkRange,
              ),
            );
          }
        case AssetHashInjectedBytesEvent():
          sink.add(event._bytes);
          processed = ByteRange.checkedAdd(processed, event.length);
          onProgress?.call(
            AssetHashProgress(
              bytesProcessed: processed,
              totalBytes: total,
              eventIndex: index,
            ),
          );
      }
    }
    await _checkCancellation();
    sink.close();
    final digest = Uint8List.fromList((await sink.hash()).bytes);
    await _requireUnchangedLength(source, sourceLength);
    return digest;
  }

  void _validateEvents(List<AssetHashEvent> events, int sourceLength) {
    final available = ByteRange(0, sourceLength);
    var previousEnd = 0;
    for (final event in events) {
      if (event is! AssetHashRangeEvent) {
        continue;
      }
      if (!available.containsRange(event.range)) {
        throw ByteRangeOutOfBoundsException(event.range, available);
      }
      if (event.range.start < previousEnd) {
        throw ArgumentError.value(
          event.range,
          'events',
          'Source ranges must be ordered and non-overlapping',
        );
      }
      previousEnd = event.range.end;
    }
  }

  Future<void> _checkCancellation() async {
    if (await isCancelled?.call() ?? false) {
      throw const AssetHashCancelledException();
    }
  }

  static Future<Uint8List> _readChunk(
    RandomAccessByteSource source,
    ByteRange range,
    int expected,
    int sourceLength,
  ) async {
    late Uint8List bytes;
    try {
      bytes = await source.read(range);
    } catch (_) {
      await _requireUnchangedLength(source, sourceLength);
      rethrow;
    }
    if (bytes.length != expected) {
      throw AssetHashShortReadException(
        range: range,
        expectedLength: expected,
        actualLength: bytes.length,
      );
    }
    await _requireUnchangedLength(source, sourceLength);
    return bytes;
  }

  static Future<int> _checkedSourceLength(RandomAccessByteSource source) async {
    final length = await source.length;
    if (length < 0 || length > ByteRange.maxCoordinate) {
      throw ArgumentError.value(
        length,
        'source.length',
        'Outside the portable byte-coordinate range',
      );
    }
    return length;
  }

  static Future<void> _requireUnchangedLength(
    RandomAccessByteSource source,
    int before,
  ) async {
    final after = await _checkedSourceLength(source);
    if (after != before) {
      throw AssetHashSourceLengthChangedException(before, after);
    }
  }
}

/// Compares digests without data-dependent early exit.
bool constantTimeDigestEquals(List<int> left, List<int> right) {
  var difference = left.length ^ right.length;
  final length = left.length > right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final leftByte = index < left.length ? left[index] : 0;
    final rightByte = index < right.length ? right[index] : 0;
    difference |= leftByte ^ rightByte;
  }
  return difference == 0;
}

cryptography.HashAlgorithm _hashImplementation(HashAlgorithm algorithm) =>
    switch (algorithm) {
      HashAlgorithm.sha256 => cryptography.Sha256().toSync(),
      HashAlgorithm.sha384 => cryptography.Sha384().toSync(),
      HashAlgorithm.sha512 => cryptography.Sha512().toSync(),
    };

List<int> _checkedBytes(List<int> bytes, String name) {
  for (final byte in bytes) {
    if (byte < 0 || byte > 255) {
      throw ArgumentError.value(bytes, name, 'Contains a non-byte value');
    }
  }
  return bytes;
}

int _checkedTotal(Iterable<int> lengths) {
  var total = 0;
  for (final length in lengths) {
    total = ByteRange.checkedAdd(total, length);
  }
  return total;
}

int _minimum(int left, int right) => left < right ? left : right;

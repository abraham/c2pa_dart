import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';
import 'package:cryptography/cryptography.dart' as cryptography;

import 'byte_compare.dart';
import 'hash_algorithm.dart';

/// Reports whether streaming asset hashing should stop before more I/O.
typedef AssetHashCancellationCallback = FutureOr<bool> Function();

/// Receives monotonic progress after each hashed source or injected chunk.
typedef AssetHashProgressCallback = void Function(AssetHashProgress progress);

/// Progress reported after each source chunk or injected-byte event.
final class AssetHashProgress {
  /// Creates an immutable asset-hashing progress sample.
  const AssetHashProgress({
    required this.bytesProcessed,
    required this.totalBytes,
    required this.eventIndex,
    this.sourceRange,
  });

  /// The number of bytes hashed so far across all events.
  final int bytesProcessed;

  /// The total number of bytes scheduled for hashing.
  final int totalBytes;

  /// The zero-based input event index currently being reported.
  final int eventIndex;

  /// The source byte range just read, or `null` for injected bytes.
  final ByteRange? sourceRange;

  /// The completed fraction in the inclusive range from `0` to `1`.
  double get fraction => totalBytes == 0 ? 1 : bytesProcessed / totalBytes;
}

/// One ordered input event in an asset hash stream.
sealed class AssetHashEvent {
  const AssetHashEvent();

  /// The number of bytes this event contributes to the hash stream.
  int get length;
}

/// Hashes bytes read from [range].
final class AssetHashRangeEvent extends AssetHashEvent {
  /// Creates an event that streams bytes from [range].
  const AssetHashRangeEvent(this.range);

  /// The source range to hash.
  final ByteRange range;

  @override
  int get length => range.length;
}

/// Hashes caller-provided bytes between source ranges.
///
/// This is suitable for future BMFF hard-binding fields such as encoded
/// 64-bit offsets without changing the source-range streaming machinery.
final class AssetHashInjectedBytesEvent extends AssetHashEvent {
  /// Creates an event that injects caller-provided [bytes] into the stream.
  ///
  /// Throws [ArgumentError] if [bytes] contains values outside `0..255`.
  AssetHashInjectedBytesEvent(List<int> bytes)
    : _bytes = Uint8List.fromList(_checkedBytes(bytes, 'bytes'));

  final Uint8List _bytes;

  /// A defensive copy of the injected bytes.
  Uint8List get bytes => Uint8List.fromList(_bytes);

  @override
  int get length => _bytes.length;
}

/// Digest associated with one independent source range.
final class AssetRangeDigest {
  /// Creates a digest result for an independent source [range].
  AssetRangeDigest(this.range, List<int> digest)
    : _digest = Uint8List.fromList(digest);

  /// The source range this digest covers.
  final ByteRange range;
  final Uint8List _digest;

  /// A defensive copy of the digest bytes.
  Uint8List get digest => Uint8List.fromList(_digest);
}

/// Base class for streaming asset-hash failures.
sealed class AssetHashException implements Exception {
  /// Creates an asset-hash exception with a human-readable [message].
  const AssetHashException(this.message);

  /// The human-readable failure detail.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// An exception raised when asset hashing is cancelled by the callback.
final class AssetHashCancelledException extends AssetHashException {
  /// Creates an exception raised when cancellation is requested.
  const AssetHashCancelledException() : super('Asset hashing was cancelled');
}

/// An exception raised when the source length changes during hashing.
final class AssetHashSourceLengthChangedException extends AssetHashException {
  /// Creates an exception for a source length mutation during hashing.
  const AssetHashSourceLengthChangedException(this.before, this.after)
    : super('Source length changed from $before to $after while hashing');

  /// The source length in bytes observed before hashing began.
  final int before;

  /// The source length in bytes observed after a read.
  final int after;
}

/// An exception raised when a source returns fewer bytes than requested.
final class AssetHashShortReadException extends AssetHashException {
  /// Creates an exception for a read shorter than the requested range.
  const AssetHashShortReadException({
    required this.range,
    required this.expectedLength,
    required this.actualLength,
  }) : super('Read $actualLength bytes for $range; expected $expectedLength');

  /// The source range requested from the byte source.
  final ByteRange range;

  /// The exact number of bytes expected for [range].
  final int expectedLength;

  /// The number of bytes actually returned by the source.
  final int actualLength;
}

/// Streaming asset hashing over random-access sources.
final class AssetHashEngine {
  /// Creates a streaming asset-hash engine.
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

  /// The maximum source bytes read per chunk.
  final int chunkSize;

  /// The optional cancellation hook checked before reads and finalization.
  final AssetHashCancellationCallback? isCancelled;

  /// The optional progress callback invoked after each hashed event chunk.
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
/// Compares [left] and [right] without data-dependent early exit.
///
/// The loop runs for the longer input length; unlike internal range
/// ordering helpers, it does not stop at the first differing byte.
bool constantTimeDigestEquals(List<int> left, List<int> right) =>
    constantTimeBytesEqual(left, right);

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

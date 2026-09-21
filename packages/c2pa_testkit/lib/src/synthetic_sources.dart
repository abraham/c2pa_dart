import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart' as io;

/// A concrete byte override inside a synthetic sparse asset.
final class SparseByteSegment {
  /// Creates a segment beginning at [offset] with copied [bytes].
  ///
  /// [offset] is a byte coordinate from zero through the C2PA I/O coordinate
  /// limit, and the segment must not extend past that limit.
  SparseByteSegment({required this.offset, required List<int> bytes})
    : _bytes = Uint8List.fromList(bytes) {
    RangeError.checkValueInInterval(
      offset,
      0,
      io.ByteRange.maxCoordinate,
      'offset',
    );
    if (_bytes.length > io.ByteRange.maxCoordinate - offset) {
      throw RangeError('Sparse segment exceeds the coordinate limit.');
    }
  }

  /// Zero-based byte coordinate where this segment starts.
  final int offset;
  final Uint8List _bytes;

  /// The number of bytes in this segment.
  int get length => _bytes.length;

  /// The exclusive byte coordinate immediately after this segment.
  int get end => io.ByteRange.checkedAdd(offset, length);

  /// A defensive copy of this segment's concrete bytes.
  Uint8List get bytes => Uint8List.fromList(_bytes);
}

/// A deterministic logical asset that allocates only requested ranges.
final class SparseRandomAccessAsset implements io.RandomAccessByteSource {
  /// Creates an in-memory asset with deterministic bytes and sparse patches.
  ///
  /// [logicalLength] is the exposed byte length. Reads synthesize bytes from
  /// [seed] except where non-overlapping [segments] provide concrete data.
  SparseRandomAccessAsset({
    required this.logicalLength,
    this.name = 'sparse',
    this.mediaType,
    this.seed = 0,
    Iterable<SparseByteSegment> segments = const [],
    Map<String, Object?> metadata = const {},
    this.maxReadBytes = 16 * 1024 * 1024,
  }) : segments = List.unmodifiable(
         <SparseByteSegment>[...segments]
           ..sort((left, right) => left.offset.compareTo(right.offset)),
       ),
       metadata = Map.unmodifiable(metadata) {
    if (name.trim().isEmpty) throw ArgumentError('name must not be empty');
    RangeError.checkValueInInterval(
      logicalLength,
      0,
      io.ByteRange.maxCoordinate,
      'logicalLength',
    );
    RangeError.checkValueInInterval(seed, 0, 0xffffffff, 'seed');
    RangeError.checkValueInInterval(
      maxReadBytes,
      1,
      io.ByteRange.maxCoordinate,
      'maxReadBytes',
    );
    SparseByteSegment? previous;
    for (final segment in this.segments) {
      if (segment.end > logicalLength) {
        throw ArgumentError('Sparse segment exceeds logicalLength.');
      }
      if (previous != null && previous.end > segment.offset) {
        throw ArgumentError('Sparse segments must not overlap.');
      }
      previous = segment;
    }
  }

  /// The byte length reported by [length], without allocating that many bytes.
  final int logicalLength;

  /// Test-facing asset name, which must not be blank.
  final String name;

  /// Optional MIME type associated with the synthetic asset.
  final String? mediaType;

  /// Deterministic pseudo-random seed in the unsigned 32-bit range.
  final int seed;

  /// Maximum bytes allowed in a single [read] call.
  final int maxReadBytes;

  /// Sorted immutable concrete byte segments overlaid on generated data.
  final List<SparseByteSegment> segments;

  /// Immutable test metadata carried alongside the synthetic source.
  final Map<String, Object?> metadata;

  /// The logical asset length in bytes.
  @override
  Future<int> get length async => logicalLength;

  /// Reads [range] by synthesizing bytes and applying overlapping segments.
  ///
  /// Throws `ByteRangeOutOfBoundsException` when [range] is outside the
  /// logical asset and [RangeError] when it exceeds [maxReadBytes].
  @override
  Future<Uint8List> read(io.ByteRange range) async {
    _validateRead(range, logicalLength, maxReadBytes);
    final result = Uint8List(range.length);
    for (var index = 0; index < result.length; index++) {
      result[index] = _syntheticByte(seed, range.start + index);
    }
    for (final segment in segments) {
      final start = segment.offset > range.start ? segment.offset : range.start;
      final end = segment.end < range.end ? segment.end : range.end;
      if (start >= end) continue;
      result.setRange(
        start - range.start,
        end - range.start,
        segment._bytes,
        start - segment.offset,
      );
    }
    return result;
  }
}

/// A logical source composed of fixed-size chunks with a repeating pattern.
final class PatternedChunkSource implements io.RandomAccessByteSource {
  /// Creates a source whose pattern restarts at every [chunkSize] boundary.
  ///
  /// [pattern] must contain byte values and at least one value; [chunkSize]
  /// and [maxReadBytes] are measured in bytes.
  PatternedChunkSource({
    required this.logicalLength,
    required List<int> pattern,
    required this.chunkSize,
    this.name = 'patterned',
    this.mediaType,
    Map<String, Object?> metadata = const {},
    this.maxReadBytes = 16 * 1024 * 1024,
  }) : _pattern = Uint8List.fromList(pattern),
       metadata = Map.unmodifiable(metadata) {
    if (name.trim().isEmpty) throw ArgumentError('name must not be empty');
    RangeError.checkValueInInterval(
      logicalLength,
      0,
      io.ByteRange.maxCoordinate,
      'logicalLength',
    );
    if (_pattern.isEmpty) throw ArgumentError('pattern must not be empty');
    RangeError.checkValueInInterval(
      chunkSize,
      1,
      io.ByteRange.maxCoordinate,
      'chunkSize',
    );
    RangeError.checkValueInInterval(
      maxReadBytes,
      1,
      io.ByteRange.maxCoordinate,
      'maxReadBytes',
    );
  }

  /// The byte length reported by [length].
  final int logicalLength;

  /// Test-facing asset name, which must not be blank.
  final String name;

  /// Optional MIME type associated with the patterned source.
  final String? mediaType;
  final Uint8List _pattern;

  /// The byte interval at which [pattern] restarts.
  final int chunkSize;

  /// Maximum bytes allowed in a single [read] call.
  final int maxReadBytes;

  /// Immutable test metadata carried alongside the patterned source.
  final Map<String, Object?> metadata;

  /// A defensive copy of the repeating byte pattern.
  Uint8List get pattern => Uint8List.fromList(_pattern);

  /// The logical source length in bytes.
  @override
  Future<int> get length async => logicalLength;

  /// Reads [range] from the chunk-restarted pattern.
  ///
  /// Throws `ByteRangeOutOfBoundsException` when [range] is outside the
  /// logical source and [RangeError] when it exceeds [maxReadBytes].
  @override
  Future<Uint8List> read(io.ByteRange range) async {
    _validateRead(range, logicalLength, maxReadBytes);
    final result = Uint8List(range.length);
    for (var index = 0; index < result.length; index++) {
      final chunkOffset = (range.start + index) % chunkSize;
      result[index] = _pattern[chunkOffset % _pattern.length];
    }
    return result;
  }
}

/// Hook invoked after a read is recorded and before it reaches the source.
///
/// Tests can return a [Future] to deliberately hold [range] reads open and
/// assert concurrent access behavior.
typedef BeforeInstrumentedRead = FutureOr<void> Function(io.ByteRange range);

/// A single recorded read attempt against an instrumented source.
final class InstrumentedReadRecord {
  /// Creates an immutable record for one read sequence number.
  const InstrumentedReadRecord({
    required this.sequence,
    required this.range,
    required this.concurrency,
    required this.succeeded,
  });

  /// Zero-based order in which the read was requested.
  final int sequence;

  /// The requested byte range.
  final io.ByteRange range;

  /// Number of active reads observed when this read started.
  final int concurrency;

  /// Whether the read completed successfully, failed, or is still pending.
  ///
  /// A `null` value means the wrapped [Future] has not completed yet.
  final bool? succeeded;
}

/// Records read shape without changing the wrapped source's byte semantics.
final class InstrumentedByteSource implements io.RandomAccessByteSource {
  /// Wraps [source] and optionally pauses each read with [beforeRead].
  InstrumentedByteSource(this.source, {this.beforeRead});

  /// The byte source whose data and errors are preserved.
  final io.RandomAccessByteSource source;

  /// Optional hook used by tests to coordinate read timing.
  final BeforeInstrumentedRead? beforeRead;
  final List<InstrumentedReadRecord> _reads = [];
  int _activeReads = 0;
  int _peakConcurrency = 0;
  int _totalRequestedBytes = 0;
  int _peakRequestedChunkSize = 0;

  /// Immutable snapshot of recorded reads in request order.
  List<InstrumentedReadRecord> get reads => List.unmodifiable(_reads);

  /// Number of reads requested since construction or the last [reset].
  int get readCount => _reads.length;

  /// Number of wrapped reads currently in flight.
  int get activeReads => _activeReads;

  /// Maximum simultaneous reads observed since the last [reset].
  int get peakConcurrency => _peakConcurrency;

  /// Sum of requested byte lengths since the last [reset].
  int get totalRequestedBytes => _totalRequestedBytes;

  /// Largest single requested byte length since the last [reset].
  int get peakRequestedChunkSize => _peakRequestedChunkSize;

  /// Clears accumulated read records and counters.
  ///
  /// Throws [StateError] if any wrapped read is still active.
  void reset() {
    if (_activeReads != 0) {
      throw StateError('Cannot reset while reads are active.');
    }
    _reads.clear();
    _peakConcurrency = 0;
    _totalRequestedBytes = 0;
    _peakRequestedChunkSize = 0;
  }

  /// The wrapped source length, forwarded without recording a read.
  @override
  Future<int> get length => source.length;

  /// Records [range], forwards the read, and preserves bytes or errors.
  @override
  Future<Uint8List> read(io.ByteRange range) async {
    final sequence = _reads.length;
    _activeReads++;
    if (_activeReads > _peakConcurrency) _peakConcurrency = _activeReads;
    _totalRequestedBytes += range.length;
    if (range.length > _peakRequestedChunkSize) {
      _peakRequestedChunkSize = range.length;
    }
    _reads.add(
      InstrumentedReadRecord(
        sequence: sequence,
        range: range,
        concurrency: _activeReads,
        succeeded: null,
      ),
    );
    try {
      await beforeRead?.call(range);
      final bytes = await source.read(range);
      _reads[sequence] = InstrumentedReadRecord(
        sequence: sequence,
        range: range,
        concurrency: _reads[sequence].concurrency,
        succeeded: true,
      );
      return bytes;
    } catch (_) {
      _reads[sequence] = InstrumentedReadRecord(
        sequence: sequence,
        range: range,
        concurrency: _reads[sequence].concurrency,
        succeeded: false,
      );
      rethrow;
    } finally {
      _activeReads--;
    }
  }
}

void _validateRead(io.ByteRange range, int length, int maxReadBytes) {
  final available = io.ByteRange(0, length);
  if (!available.containsRange(range)) {
    throw io.ByteRangeOutOfBoundsException(range, available);
  }
  if (range.length > maxReadBytes) {
    throw RangeError.range(
      range.length,
      0,
      maxReadBytes,
      'range.length',
      'exceeds maxReadBytes',
    );
  }
}

int _syntheticByte(int seed, int offset) {
  final low = offset & 0xffffffff;
  final high = (offset ~/ 0x100000000) & 0xffffffff;
  var state = (seed ^ low ^ high) & 0xffffffff;
  state = (1664525 * state + 1013904223) & 0xffffffff;
  state ^= state >>> 16;
  return state & 0xff;
}

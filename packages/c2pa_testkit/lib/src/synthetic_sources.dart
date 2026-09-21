import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart' as io;

final class SparseByteSegment {
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

  final int offset;
  final Uint8List _bytes;

  int get length => _bytes.length;
  int get end => io.ByteRange.checkedAdd(offset, length);
  Uint8List get bytes => Uint8List.fromList(_bytes);
}

/// A deterministic logical asset that allocates only requested ranges.
final class SparseRandomAccessAsset implements io.RandomAccessByteSource {
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

  final int logicalLength;
  final String name;
  final String? mediaType;
  final int seed;
  final int maxReadBytes;
  final List<SparseByteSegment> segments;
  final Map<String, Object?> metadata;

  @override
  Future<int> get length async => logicalLength;

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

  final int logicalLength;
  final String name;
  final String? mediaType;
  final Uint8List _pattern;
  final int chunkSize;
  final int maxReadBytes;
  final Map<String, Object?> metadata;

  Uint8List get pattern => Uint8List.fromList(_pattern);

  @override
  Future<int> get length async => logicalLength;

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

typedef BeforeInstrumentedRead = FutureOr<void> Function(io.ByteRange range);

final class InstrumentedReadRecord {
  const InstrumentedReadRecord({
    required this.sequence,
    required this.range,
    required this.concurrency,
    required this.succeeded,
  });

  final int sequence;
  final io.ByteRange range;
  final int concurrency;
  final bool? succeeded;
}

/// Records read shape without changing the wrapped source's byte semantics.
final class InstrumentedByteSource implements io.RandomAccessByteSource {
  InstrumentedByteSource(this.source, {this.beforeRead});

  final io.RandomAccessByteSource source;
  final BeforeInstrumentedRead? beforeRead;
  final List<InstrumentedReadRecord> _reads = [];
  int _activeReads = 0;
  int _peakConcurrency = 0;
  int _totalRequestedBytes = 0;
  int _peakRequestedChunkSize = 0;

  List<InstrumentedReadRecord> get reads => List.unmodifiable(_reads);
  int get readCount => _reads.length;
  int get activeReads => _activeReads;
  int get peakConcurrency => _peakConcurrency;
  int get totalRequestedBytes => _totalRequestedBytes;
  int get peakRequestedChunkSize => _peakRequestedChunkSize;

  void reset() {
    if (_activeReads != 0) {
      throw StateError('Cannot reset while reads are active.');
    }
    _reads.clear();
    _peakConcurrency = 0;
    _totalRequestedBytes = 0;
    _peakRequestedChunkSize = 0;
  }

  @override
  Future<int> get length => source.length;

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

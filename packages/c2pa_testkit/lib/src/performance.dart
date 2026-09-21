import 'dart:async';

import 'differential.dart';

/// A cooperative cancellation token for benchmark operations.
final class BenchmarkCancellationToken {
  final Completer<void> _cancelled = Completer<void>();

  /// Whether [cancel] has been called.
  bool get isCancelled => _cancelled.isCompleted;

  /// A future that completes when [cancel] is called.
  Future<void> get whenCancelled => _cancelled.future;

  /// Signals cancellation exactly once.
  void cancel() {
    if (!_cancelled.isCompleted) _cancelled.complete();
  }
}

/// One measured benchmark iteration.
final class BenchmarkSample {
  /// Creates a benchmark sample.
  ///
  /// [elapsed] is stored as a [Duration] and serialized in microseconds.
  /// [bytesProcessed], [readCount], and [peakRequestedChunkSize] are
  /// non-negative counts measured in bytes or operations.
  BenchmarkSample({
    required this.elapsed,
    required this.bytesProcessed,
    this.readCount = 0,
    this.peakRequestedChunkSize = 0,
  }) {
    if (elapsed.isNegative) {
      throw ArgumentError.value(elapsed, 'elapsed', 'must not be negative');
    }
    RangeError.checkNotNegative(bytesProcessed, 'bytesProcessed');
    RangeError.checkNotNegative(readCount, 'readCount');
    RangeError.checkNotNegative(
      peakRequestedChunkSize,
      'peakRequestedChunkSize',
    );
  }

  /// Parses a benchmark sample from a JSON-safe [json] map.
  ///
  /// The elapsed duration is read from `elapsedMicros` in microseconds.
  factory BenchmarkSample.fromJson(Map<String, Object?> json) =>
      BenchmarkSample(
        elapsed: Duration(microseconds: _int(json, 'elapsedMicros')),
        bytesProcessed: _int(json, 'bytesProcessed'),
        readCount: _int(json, 'readCount'),
        peakRequestedChunkSize: _int(json, 'peakRequestedChunkSize'),
      );

  /// The wall-clock duration for this sample.
  ///
  /// Serialized as microseconds by [toJson].
  final Duration elapsed;

  /// The number of payload bytes processed by this iteration.
  final int bytesProcessed;

  /// The number of read operations performed by this iteration.
  final int readCount;

  /// The largest requested read chunk size in bytes for this iteration.
  final int peakRequestedChunkSize;

  /// The processed byte rate in bytes per second.
  ///
  /// The value is 0 when [elapsed] is zero microseconds to avoid division by
  /// zero.
  double get throughputBytesPerSecond => elapsed.inMicroseconds == 0
      ? 0
      : bytesProcessed *
            Duration.microsecondsPerSecond /
            elapsed.inMicroseconds;

  /// Converts this sample to a JSON-safe map.
  ///
  /// The elapsed duration is written as `elapsedMicros` in microseconds.
  Map<String, Object?> toJson() => {
    'elapsedMicros': elapsed.inMicroseconds,
    'bytesProcessed': bytesProcessed,
    'readCount': readCount,
    'peakRequestedChunkSize': peakRequestedChunkSize,
  };
}

/// Aggregate statistics computed from benchmark samples.
final class BenchmarkStatistics {
  /// Creates aggregate benchmark statistics.
  ///
  /// [warmupCount] is the number of unmeasured warmup iterations completed.
  /// [samples] are measured repetitions and are defensively copied.
  BenchmarkStatistics({
    required this.warmupCount,
    required Iterable<BenchmarkSample> samples,
  }) : samples = List.unmodifiable(samples) {
    RangeError.checkNotNegative(warmupCount, 'warmupCount');
  }

  /// Parses benchmark statistics from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when the `samples` field is not an array.
  factory BenchmarkStatistics.fromJson(Map<String, Object?> json) {
    final rawSamples = json['samples'];
    if (rawSamples is! List<Object?>) {
      throw const FormatException('samples must be an array.');
    }
    return BenchmarkStatistics(
      warmupCount: _int(json, 'warmupCount'),
      samples: rawSamples.map(
        (sample) => BenchmarkSample.fromJson(_map(sample, 'sample')),
      ),
    );
  }

  /// The number of warmup iterations run before measured samples.
  final int warmupCount;

  /// The measured benchmark samples in execution order.
  final List<BenchmarkSample> samples;

  /// The number of measured repetitions.
  int get repetitionCount => samples.length;

  /// The fastest elapsed duration, or zero microseconds with no samples.
  Duration get minimum => _durationAt(0);

  /// The slowest elapsed duration, or zero microseconds with no samples.
  Duration get maximum => _durationAt(samples.length - 1);

  /// The 50th percentile elapsed duration in microseconds.
  Duration get median => percentile(50);

  /// The 90th percentile elapsed duration in microseconds.
  Duration get p90 => percentile(90);

  /// The 95th percentile elapsed duration in microseconds.
  Duration get p95 => percentile(95);

  /// The 99th percentile elapsed duration in microseconds.
  Duration get p99 => percentile(99);

  /// The arithmetic mean elapsed duration in microseconds.
  Duration get mean {
    if (samples.isEmpty) return Duration.zero;
    final total = samples.fold<int>(
      0,
      (sum, sample) => sum + sample.elapsed.inMicroseconds,
    );
    return Duration(microseconds: (total / samples.length).round());
  }

  /// The total number of payload bytes processed across all samples.
  int get totalBytesProcessed =>
      samples.fold(0, (sum, sample) => sum + sample.bytesProcessed);

  /// The total number of read operations across all samples.
  int get totalReadCount =>
      samples.fold(0, (sum, sample) => sum + sample.readCount);

  /// The largest requested read chunk size in bytes across all samples.
  int get peakRequestedChunkSize => samples.fold(
    0,
    (peak, sample) => sample.peakRequestedChunkSize > peak
        ? sample.peakRequestedChunkSize
        : peak,
  );

  /// The aggregate processed byte rate in bytes per second.
  ///
  /// The denominator is the sum of sample elapsed times in microseconds.
  double get throughputBytesPerSecond {
    final elapsedMicros = samples.fold<int>(
      0,
      (sum, sample) => sum + sample.elapsed.inMicroseconds,
    );
    return elapsedMicros == 0
        ? 0
        : totalBytesProcessed * Duration.microsecondsPerSecond / elapsedMicros;
  }

  List<int> get _sortedDurations =>
      samples.map((sample) => sample.elapsed.inMicroseconds).toList()..sort();

  Duration _durationAt(int index) => samples.isEmpty
      ? Duration.zero
      : Duration(microseconds: _sortedDurations[index]);

  /// Returns a linearly interpolated percentile in the inclusive 0-100 range.
  ///
  /// Calculates a linearly interpolated elapsed-time percentile.
  ///
  /// [percentile] must be in the inclusive range 0 to 100. The returned
  /// [Duration] has microsecond precision and is zero when there are no
  /// samples.
  Duration percentile(double percentile) {
    if (percentile < 0 || percentile > 100 || percentile.isNaN) {
      throw RangeError.range(percentile, 0, 100, 'percentile');
    }
    if (samples.isEmpty) return Duration.zero;
    final sorted = _sortedDurations;
    final position = (sorted.length - 1) * percentile / 100;
    final lower = position.floor();
    final upper = position.ceil();
    if (lower == upper) return Duration(microseconds: sorted[lower]);
    final interpolated =
        sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
    return Duration(microseconds: interpolated.round());
  }

  /// Converts these statistics to a JSON-safe map.
  ///
  /// Duration metrics are written as microsecond counts, and throughput is
  /// written as bytes per second.
  Map<String, Object?> toJson() => {
    'warmupCount': warmupCount,
    'repetitionCount': repetitionCount,
    'minimumMicros': minimum.inMicroseconds,
    'maximumMicros': maximum.inMicroseconds,
    'meanMicros': mean.inMicroseconds,
    'p50Micros': median.inMicroseconds,
    'p90Micros': p90.inMicroseconds,
    'p95Micros': p95.inMicroseconds,
    'p99Micros': p99.inMicroseconds,
    'throughputBytesPerSecond': throughputBytesPerSecond,
    'totalBytesProcessed': totalBytesProcessed,
    'totalReadCount': totalReadCount,
    'peakRequestedChunkSize': peakRequestedChunkSize,
    'samples': samples.map((sample) => sample.toJson()).toList(growable: false),
  };
}

/// The named result of a benchmark run.
final class BenchmarkResult {
  /// Creates a benchmark result with [name] and [statistics].
  ///
  /// [name] must contain non-whitespace characters. [metadata] is normalized
  /// when serialized so tests can persist fixture names and environment facts.
  BenchmarkResult({
    required this.name,
    required this.statistics,
    this.cancelled = false,
    Map<String, Object?> metadata = const {},
  }) : metadata = Map.unmodifiable(metadata) {
    if (name.trim().isEmpty) throw ArgumentError('name must not be empty');
  }

  /// Parses a benchmark result from a JSON-safe [json] map.
  ///
  /// Missing metadata is treated as an empty map.
  factory BenchmarkResult.fromJson(Map<String, Object?> json) =>
      BenchmarkResult(
        name: _string(json, 'name'),
        statistics: BenchmarkStatistics.fromJson(
          _map(json['statistics'], 'statistics'),
        ),
        cancelled: _bool(json, 'cancelled'),
        metadata: switch (json['metadata']) {
          null => const {},
          final Object value => _map(value, 'metadata'),
        },
      );

  /// The human-readable benchmark name.
  final String name;

  /// The measured sample statistics for this result.
  final BenchmarkStatistics statistics;

  /// Whether cooperative cancellation stopped the benchmark early.
  final bool cancelled;

  /// Additional JSON-safe benchmark context such as fixture names.
  final Map<String, Object?> metadata;

  /// Converts this benchmark result to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'name': name,
    'cancelled': cancelled,
    'metadata': normalizeJson(metadata),
    'statistics': statistics.toJson(),
  };
}

/// Thresholds used to detect benchmark regressions.
final class RegressionBudget {
  /// Creates a regression budget.
  ///
  /// Duration limits are compared in microseconds, byte limits are raw bytes,
  /// and throughput is measured in bytes per second. Null limits disable that
  /// metric.
  RegressionBudget({
    this.maximumMean,
    this.maximumP95,
    this.minimumThroughputBytesPerSecond,
    this.maximumPeakRequestedChunkSize,
    this.maximumReadCount,
  }) {
    if (maximumMean?.isNegative ?? false) {
      throw ArgumentError.value(maximumMean, 'maximumMean');
    }
    if (maximumP95?.isNegative ?? false) {
      throw ArgumentError.value(maximumP95, 'maximumP95');
    }
    final throughput = minimumThroughputBytesPerSecond;
    if (throughput != null && (!throughput.isFinite || throughput.isNegative)) {
      throw ArgumentError.value(throughput, 'minimumThroughputBytesPerSecond');
    }
    if ((maximumPeakRequestedChunkSize ?? 0) < 0) {
      throw ArgumentError.value(
        maximumPeakRequestedChunkSize,
        'maximumPeakRequestedChunkSize',
      );
    }
    if ((maximumReadCount ?? 0) < 0) {
      throw ArgumentError.value(maximumReadCount, 'maximumReadCount');
    }
  }

  /// The maximum allowed mean elapsed duration, or null to skip it.
  final Duration? maximumMean;

  /// The maximum allowed p95 elapsed duration, or null to skip it.
  final Duration? maximumP95;

  /// The minimum allowed throughput in bytes per second, or null to skip it.
  final double? minimumThroughputBytesPerSecond;

  /// The maximum allowed peak requested chunk size in bytes, or null.
  final int? maximumPeakRequestedChunkSize;

  /// The maximum allowed total read count, or null to skip it.
  final int? maximumReadCount;

  /// Evaluates [result] against this budget.
  ///
  /// The returned evaluation lists every metric that violates an enabled limit;
  /// this method performs no I/O and does not throw for failing benchmarks.
  RegressionBudgetEvaluation evaluate(BenchmarkResult result) {
    final violations = <RegressionBudgetViolation>[];
    void maximum(String metric, num actual, num? limit) {
      if (limit != null && actual > limit) {
        violations.add(
          RegressionBudgetViolation(
            metric: metric,
            actual: actual,
            limit: limit,
            expectation: 'maximum',
          ),
        );
      }
    }

    maximum(
      'meanMicros',
      result.statistics.mean.inMicroseconds,
      maximumMean?.inMicroseconds,
    );
    maximum(
      'p95Micros',
      result.statistics.p95.inMicroseconds,
      maximumP95?.inMicroseconds,
    );
    maximum(
      'peakRequestedChunkSize',
      result.statistics.peakRequestedChunkSize,
      maximumPeakRequestedChunkSize,
    );
    maximum('readCount', result.statistics.totalReadCount, maximumReadCount);
    final minimumThroughput = minimumThroughputBytesPerSecond;
    if (minimumThroughput != null &&
        result.statistics.throughputBytesPerSecond < minimumThroughput) {
      violations.add(
        RegressionBudgetViolation(
          metric: 'throughputBytesPerSecond',
          actual: result.statistics.throughputBytesPerSecond,
          limit: minimumThroughput,
          expectation: 'minimum',
        ),
      );
    }
    return RegressionBudgetEvaluation(violations);
  }
}

/// One metric that violated a [RegressionBudget].
final class RegressionBudgetViolation {
  /// Creates a budget violation record.
  ///
  /// [actual] and [limit] use the units named by [metric], such as
  /// microseconds for `meanMicros` or bytes per second for throughput.
  const RegressionBudgetViolation({
    required this.metric,
    required this.actual,
    required this.limit,
    required this.expectation,
  });

  /// The machine-readable metric name that failed.
  final String metric;

  /// The measured metric value.
  final num actual;

  /// The configured budget value.
  final num limit;

  /// The comparison direction, either `maximum` or `minimum`.
  final String expectation;
}

/// The outcome of evaluating a benchmark against a regression budget.
final class RegressionBudgetEvaluation {
  /// Creates an evaluation from the supplied [violations].
  RegressionBudgetEvaluation(Iterable<RegressionBudgetViolation> violations)
    : violations = List.unmodifiable(violations);

  /// The budget violations in evaluation order.
  final List<RegressionBudgetViolation> violations;

  /// Whether no budget limits were violated.
  bool get passed => violations.isEmpty;
}

Map<String, Object?> _map(Object? value, String name) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$name must be a JSON object.');
  }
  return value.map((key, value) => MapEntry(key.toString(), value));
}

int _int(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! int) throw FormatException('$key must be an integer.');
  return value;
}

String _string(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! String) throw FormatException('$key must be a string.');
  return value;
}

bool _bool(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is! bool) throw FormatException('$key must be a boolean.');
  return value;
}

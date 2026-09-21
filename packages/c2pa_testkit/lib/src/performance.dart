import 'dart:async';

import 'differential.dart';

final class BenchmarkCancellationToken {
  final Completer<void> _cancelled = Completer<void>();

  bool get isCancelled => _cancelled.isCompleted;
  Future<void> get whenCancelled => _cancelled.future;

  void cancel() {
    if (!_cancelled.isCompleted) _cancelled.complete();
  }
}

final class BenchmarkSample {
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

  factory BenchmarkSample.fromJson(Map<String, Object?> json) =>
      BenchmarkSample(
        elapsed: Duration(microseconds: _int(json, 'elapsedMicros')),
        bytesProcessed: _int(json, 'bytesProcessed'),
        readCount: _int(json, 'readCount'),
        peakRequestedChunkSize: _int(json, 'peakRequestedChunkSize'),
      );

  final Duration elapsed;
  final int bytesProcessed;
  final int readCount;
  final int peakRequestedChunkSize;

  double get throughputBytesPerSecond => elapsed.inMicroseconds == 0
      ? 0
      : bytesProcessed *
            Duration.microsecondsPerSecond /
            elapsed.inMicroseconds;

  Map<String, Object?> toJson() => {
    'elapsedMicros': elapsed.inMicroseconds,
    'bytesProcessed': bytesProcessed,
    'readCount': readCount,
    'peakRequestedChunkSize': peakRequestedChunkSize,
  };
}

final class BenchmarkStatistics {
  BenchmarkStatistics({
    required this.warmupCount,
    required Iterable<BenchmarkSample> samples,
  }) : samples = List.unmodifiable(samples) {
    RangeError.checkNotNegative(warmupCount, 'warmupCount');
  }

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

  final int warmupCount;
  final List<BenchmarkSample> samples;

  int get repetitionCount => samples.length;
  Duration get minimum => _durationAt(0);
  Duration get maximum => _durationAt(samples.length - 1);
  Duration get median => percentile(50);
  Duration get p90 => percentile(90);
  Duration get p95 => percentile(95);
  Duration get p99 => percentile(99);
  Duration get mean {
    if (samples.isEmpty) return Duration.zero;
    final total = samples.fold<int>(
      0,
      (sum, sample) => sum + sample.elapsed.inMicroseconds,
    );
    return Duration(microseconds: (total / samples.length).round());
  }

  int get totalBytesProcessed =>
      samples.fold(0, (sum, sample) => sum + sample.bytesProcessed);
  int get totalReadCount =>
      samples.fold(0, (sum, sample) => sum + sample.readCount);
  int get peakRequestedChunkSize => samples.fold(
    0,
    (peak, sample) => sample.peakRequestedChunkSize > peak
        ? sample.peakRequestedChunkSize
        : peak,
  );
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

final class BenchmarkResult {
  BenchmarkResult({
    required this.name,
    required this.statistics,
    this.cancelled = false,
    Map<String, Object?> metadata = const {},
  }) : metadata = Map.unmodifiable(metadata) {
    if (name.trim().isEmpty) throw ArgumentError('name must not be empty');
  }

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

  final String name;
  final BenchmarkStatistics statistics;
  final bool cancelled;
  final Map<String, Object?> metadata;

  Map<String, Object?> toJson() => {
    'name': name,
    'cancelled': cancelled,
    'metadata': normalizeJson(metadata),
    'statistics': statistics.toJson(),
  };
}

final class RegressionBudget {
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

  final Duration? maximumMean;
  final Duration? maximumP95;
  final double? minimumThroughputBytesPerSecond;
  final int? maximumPeakRequestedChunkSize;
  final int? maximumReadCount;

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

final class RegressionBudgetViolation {
  const RegressionBudgetViolation({
    required this.metric,
    required this.actual,
    required this.limit,
    required this.expectation,
  });

  final String metric;
  final num actual;
  final num limit;
  final String expectation;
}

final class RegressionBudgetEvaluation {
  RegressionBudgetEvaluation(Iterable<RegressionBudgetViolation> violations)
    : violations = List.unmodifiable(violations);

  final List<RegressionBudgetViolation> violations;
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

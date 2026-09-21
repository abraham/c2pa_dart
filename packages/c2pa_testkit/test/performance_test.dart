import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  BenchmarkResult result() => BenchmarkResult(
    name: 'synthetic-read',
    statistics: BenchmarkStatistics(
      warmupCount: 2,
      samples: [
        BenchmarkSample(
          elapsed: const Duration(microseconds: 10),
          bytesProcessed: 1000,
          readCount: 1,
          peakRequestedChunkSize: 100,
        ),
        BenchmarkSample(
          elapsed: const Duration(microseconds: 20),
          bytesProcessed: 1000,
          readCount: 2,
          peakRequestedChunkSize: 200,
        ),
        BenchmarkSample(
          elapsed: const Duration(microseconds: 30),
          bytesProcessed: 1000,
          readCount: 3,
          peakRequestedChunkSize: 300,
        ),
        BenchmarkSample(
          elapsed: const Duration(microseconds: 40),
          bytesProcessed: 1000,
          readCount: 4,
          peakRequestedChunkSize: 400,
        ),
      ],
    ),
    metadata: {'fixture': 'sparse-5gib'},
  );

  test('computes deterministic statistics and percentiles', () {
    final statistics = result().statistics;

    expect(statistics.warmupCount, 2);
    expect(statistics.repetitionCount, 4);
    expect(statistics.minimum, const Duration(microseconds: 10));
    expect(statistics.maximum, const Duration(microseconds: 40));
    expect(statistics.mean, const Duration(microseconds: 25));
    expect(statistics.median, const Duration(microseconds: 25));
    expect(statistics.p90, const Duration(microseconds: 37));
    expect(statistics.p95, const Duration(microseconds: 39));
    expect(statistics.p99, const Duration(microseconds: 40));
    expect(statistics.totalBytesProcessed, 4000);
    expect(statistics.totalReadCount, 10);
    expect(statistics.peakRequestedChunkSize, 400);
    expect(statistics.throughputBytesPerSecond, 40000000);
    expect(() => statistics.percentile(101), throwsRangeError);
  });

  test('evaluates budgets without asserting wall-clock behavior', () {
    final passing = RegressionBudget(
      maximumMean: Duration(microseconds: 30),
      maximumP95: Duration(microseconds: 40),
      minimumThroughputBytesPerSecond: 30000000,
      maximumPeakRequestedChunkSize: 512,
      maximumReadCount: 10,
    ).evaluate(result());
    final failing = RegressionBudget(
      maximumMean: Duration(microseconds: 20),
      maximumP95: Duration(microseconds: 30),
      minimumThroughputBytesPerSecond: 50000000,
      maximumPeakRequestedChunkSize: 256,
      maximumReadCount: 5,
    ).evaluate(result());

    expect(passing.passed, isTrue);
    expect(failing.passed, isFalse);
    expect(failing.violations.map((violation) => violation.metric), [
      'meanMicros',
      'p95Micros',
      'peakRequestedChunkSize',
      'readCount',
      'throughputBytesPerSecond',
    ]);
  });

  test('round-trips normalized JSON', () {
    final original = result();
    final restored = BenchmarkResult.fromJson(original.toJson());

    expect(restored.toJson(), original.toJson());
  });
}

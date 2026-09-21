import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../performance.dart';

/// Measurements produced by one VM-only benchmark iteration.
final class BenchmarkIteration {
  /// Creates iteration measurements in bytes and read counts.
  const BenchmarkIteration({
    required this.bytesProcessed,
    this.readCount = 0,
    this.peakRequestedChunkSize = 0,
  });

  /// Number of input or output bytes processed by the iteration.
  final int bytesProcessed;

  /// Number of random-access reads performed during the iteration.
  final int readCount;

  /// Largest single read request observed during the iteration, in bytes.
  final int peakRequestedChunkSize;
}

/// VM-only benchmark body invoked for warmups and measured repetitions.
///
/// The [BenchmarkCancellationToken] is cooperative; operations should check
/// it before starting expensive I/O or CPU work.
typedef VmBenchmarkOperation = FutureOr<BenchmarkIteration> Function(
  int iteration,
  BenchmarkCancellationToken cancellation,
);

/// Optional wall-clock runner for local benchmarking, not CI assertions.
///
/// This runner uses VM timing and file-friendly persistence helpers, so it is
/// not safe for web tests.
final class VmBenchmarkRunner {
  /// Creates a runner with warmups and measured repetitions.
  ///
  /// [warmupCount] may be zero; [repetitionCount] must be between 1 and
  /// 1,000,000.
  VmBenchmarkRunner({this.warmupCount = 1, this.repetitionCount = 10}) {
    RangeError.checkNotNegative(warmupCount, 'warmupCount');
    RangeError.checkValueInInterval(
      repetitionCount,
      1,
      1000000,
      'repetitionCount',
    );
  }

  /// Number of unmeasured setup iterations run before sampling.
  final int warmupCount;

  /// Maximum number of measured samples to collect.
  final int repetitionCount;

  /// Runs [operation] and returns timing statistics for completed samples.
  ///
  /// Cancellation stops before adding the cancelled sample; [metadata] is
  /// copied into the resulting report for test diagnostics.
  Future<BenchmarkResult> run({
    required String name,
    required VmBenchmarkOperation operation,
    BenchmarkCancellationToken? cancellation,
    Map<String, Object?> metadata = const {},
  }) async {
    final token = cancellation ?? BenchmarkCancellationToken();
    var completedWarmups = 0;
    for (var index = 0; index < warmupCount; index++) {
      if (token.isCancelled) break;
      final completed = await _runOne(index, operation, token);
      if (completed == null) break;
      completedWarmups++;
    }

    final samples = <BenchmarkSample>[];
    for (var index = 0; index < repetitionCount; index++) {
      if (token.isCancelled) break;
      final completed = await _runOne(index, operation, token);
      if (completed == null) break;
      samples.add(completed);
    }
    return BenchmarkResult(
      name: name,
      cancelled: token.isCancelled,
      metadata: metadata,
      statistics: BenchmarkStatistics(
        warmupCount: completedWarmups,
        samples: samples,
      ),
    );
  }

  Future<BenchmarkSample?> _runOne(
    int iteration,
    VmBenchmarkOperation operation,
    BenchmarkCancellationToken cancellation,
  ) async {
    final stopwatch = Stopwatch()..start();
    final operationFuture = Future<BenchmarkIteration>.sync(
      () => operation(iteration, cancellation),
    );
    final cancelledMarker = Object();
    final outcome = await Future.any<Object?>([
      operationFuture,
      cancellation.whenCancelled.then<Object?>((_) => cancelledMarker),
    ]);
    stopwatch.stop();
    if (identical(outcome, cancelledMarker)) return null;
    final measurement = outcome! as BenchmarkIteration;
    return BenchmarkSample(
      elapsed: stopwatch.elapsed,
      bytesProcessed: measurement.bytesProcessed,
      readCount: measurement.readCount,
      peakRequestedChunkSize: measurement.peakRequestedChunkSize,
    );
  }
}

/// Writes [result] as pretty JSON to an absolute VM file [path].
///
/// Creates parent directories as needed and throws [ArgumentError] for
/// relative paths.
Future<void> writeBenchmarkResultJson(
  String path,
  BenchmarkResult result,
) async {
  final file = _absoluteFile(path);
  await file.parent.create(recursive: true);
  await file.writeAsString(
    const JsonEncoder.withIndent(' ').convert(result.toJson()),
    flush: true,
  );
}

/// Reads a VM benchmark JSON report from an absolute file [path].
///
/// Throws [ArgumentError] for relative paths and [FormatException] if the
/// decoded root is not a JSON object.
Future<BenchmarkResult> readBenchmarkResultJson(String path) async {
  final decoded = jsonDecode(await _absoluteFile(path).readAsString());
  if (decoded is! Map<String, Object?>) {
    throw const FormatException('Benchmark report must be a JSON object.');
  }
  return BenchmarkResult.fromJson(decoded);
}

File _absoluteFile(String path) {
  final uri = Uri.file(path);
  if (!uri.isAbsolute) {
    throw ArgumentError.value(path, 'path', 'must be absolute');
  }
  return File.fromUri(uri);
}

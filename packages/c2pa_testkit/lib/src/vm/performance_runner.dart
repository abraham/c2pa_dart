import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../performance.dart';

final class BenchmarkIteration {
  const BenchmarkIteration({
    required this.bytesProcessed,
    this.readCount = 0,
    this.peakRequestedChunkSize = 0,
  });

  final int bytesProcessed;
  final int readCount;
  final int peakRequestedChunkSize;
}

typedef VmBenchmarkOperation = FutureOr<BenchmarkIteration> Function(
  int iteration,
  BenchmarkCancellationToken cancellation,
);

/// Optional wall-clock runner for local benchmarking, not CI assertions.
final class VmBenchmarkRunner {
  VmBenchmarkRunner({this.warmupCount = 1, this.repetitionCount = 10}) {
    RangeError.checkNotNegative(warmupCount, 'warmupCount');
    RangeError.checkValueInInterval(
      repetitionCount,
      1,
      1000000,
      'repetitionCount',
    );
  }

  final int warmupCount;
  final int repetitionCount;

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

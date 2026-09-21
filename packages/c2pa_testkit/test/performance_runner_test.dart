@TestOn('vm')
library;

import 'dart:io';
import 'dart:isolate';

import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  test('VM runner separates warmups and measured repetitions', () async {
    var invocations = 0;
    final result = await VmBenchmarkRunner(warmupCount: 2, repetitionCount: 3)
        .run(
          name: 'read',
          operation: (iteration, cancellation) {
            invocations++;
            return const BenchmarkIteration(
              bytesProcessed: 1024,
              readCount: 2,
              peakRequestedChunkSize: 512,
            );
          },
        );

    expect(invocations, 5);
    expect(result.cancelled, isFalse);
    expect(result.statistics.warmupCount, 2);
    expect(result.statistics.repetitionCount, 3);
    expect(result.statistics.totalBytesProcessed, 3072);
    expect(result.statistics.peakRequestedChunkSize, 512);
  });

  test('VM runner responds to cooperative cancellation', () async {
    final token = BenchmarkCancellationToken();
    final resultFuture = VmBenchmarkRunner(warmupCount: 0, repetitionCount: 10)
        .run(
          name: 'cancelled',
          cancellation: token,
          operation: (iteration, cancellation) async {
            await cancellation.whenCancelled;
            return const BenchmarkIteration(bytesProcessed: 1);
          },
        );
    token.cancel();
    final result = await resultFuture;

    expect(result.cancelled, isTrue);
    expect(result.statistics.repetitionCount, lessThanOrEqualTo(1));
  });

  test('VM persistence round-trips benchmark reports', () async {
    final library = await Isolate.resolvePackageUri(
      Uri.parse('package:c2pa_testkit/c2pa_testkit_vm.dart'),
    );
    final file = File.fromUri(
      library!.resolve('../.dart_tool/benchmark-persistence-$pid/report.json'),
    );
    final result = BenchmarkResult(
      name: 'persisted',
      statistics: BenchmarkStatistics(
        warmupCount: 1,
        samples: [
          BenchmarkSample(
            elapsed: const Duration(microseconds: 25),
            bytesProcessed: 100,
          ),
        ],
      ),
    );

    try {
      await writeBenchmarkResultJson(file.path, result);
      final restored = await readBenchmarkResultJson(file.path);
      expect(restored.toJson(), result.toJson());
    } finally {
      if (await file.parent.exists()) {
        await file.parent.delete(recursive: true);
      }
    }
  });
}

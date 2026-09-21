import 'package:c2pa_io/c2pa_io.dart' as io;
import 'package:c2pa_testkit/c2pa_testkit.dart';

Future<void> main() async {
  final fixture = FixtureAsset.deterministic(name: 'web', length: 8, seed: 1);
  final plan = MutationPlanGenerator(
    MutationGeneratorConfig(
      classifications: [MutationClassification.unprotectedBitFlip],
    ),
  ).generate(fixture.bytes, seed: 2);
  final result = plan.apply(fixture.bytes);
  if (result.length != fixture.length) throw StateError('Unexpected length.');

  final sparse = SparseRandomAccessAsset(
    logicalLength: 5 * 1024 * 1024 * 1024,
    seed: 3,
  );
  final bytes = await sparse.read(
    io.ByteRange(4 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024 + 4),
  );
  if (bytes.length != 4) throw StateError('Unexpected sparse read.');

  final statistics = BenchmarkStatistics(
    warmupCount: 0,
    samples: [
      BenchmarkSample(
        elapsed: const Duration(microseconds: 1),
        bytesProcessed: bytes.length,
      ),
    ],
  );
  if (statistics.repetitionCount != 1) {
    throw StateError('Unexpected statistics.');
  }
}

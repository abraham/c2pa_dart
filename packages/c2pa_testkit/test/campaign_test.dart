import 'dart:async';
import 'dart:io';
import 'dart:isolate';

import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  MutationCampaignRunner runner({
    int seed = 42,
    int cases = 4,
    Duration timeout = const Duration(seconds: 1),
    CampaignPersistenceHook? persistence,
  }) => MutationCampaignRunner(
    config: MutationCampaignConfig(
      seed: seed,
      maxCases: cases,
      maxCorpusBytes: 1024,
      caseTimeout: timeout,
    ),
    generator: MutationPlanGenerator(
      MutationGeneratorConfig(
        classifications: [MutationClassification.unprotectedBitFlip],
      ),
    ),
    corpus: [
      FixtureAsset(name: 'fixture.bin', bytes: [0, 1, 2, 3]),
    ],
    persistenceHook: persistence,
  );

  test('campaign replay and failure JSON are deterministic', () async {
    final observed = <int, List<int>>{};
    Future<CampaignCaseResult> property(MutationCampaignCase testCase) async {
      observed[testCase.index] = testCase.bytes;
      return CampaignCaseResult.failure(
        'expected failure',
        details: {
          'classification': testCase.plan.steps.single.classification.name,
        },
      );
    }

    final first = await runner().run(property);
    final second = await runner().run(property);

    expect(first.toJson(), second.toJson());
    expect(first.failures, hasLength(4));
    final failure = first.failures.first;
    expect(failure.kind, CampaignFailureKind.property);
    expect(failure.classifications, [
      MutationClassification.unprotectedBitFlip,
    ]);
    expect(
      failure.replay.apply(
        FixtureAsset(name: 'fixture.bin', bytes: [0, 1, 2, 3]),
      ),
      observed[0],
    );
    expect(
      MutationCampaignReport.fromJson(first.toJson()).toJson(),
      first.toJson(),
    );
  });

  test('enforces per-case timeout and signals case cancellation', () async {
    final cancellationObserved = Completer<void>();
    final report =
        await runner(cases: 1, timeout: const Duration(milliseconds: 20)).run((
          testCase,
        ) async {
          await testCase.cancellation.whenCancelled;
          cancellationObserved.complete();
          return const CampaignCaseResult.pass();
        });

    await cancellationObserved.future;
    expect(report.failures.single.kind, CampaignFailureKind.timeout);
  });

  test('stops on external cancellation', () async {
    final cancellation = CampaignCancellationToken();
    final report = await runner(cases: 10).run((testCase) {
      cancellation.cancel();
      return const CampaignCaseResult.pass();
    }, cancellation: cancellation);

    expect(report.cancelled, isTrue);
    expect(report.executedCases, 1);
  });

  test('bounds corpus bytes and invokes web-safe persistence hook', () async {
    expect(
      () => MutationCampaignRunner(
        config: MutationCampaignConfig(seed: 1, maxCases: 1, maxCorpusBytes: 2),
        generator: MutationPlanGenerator(MutationGeneratorConfig()),
        corpus: [
          FixtureAsset(name: 'large', bytes: [1, 2, 3]),
        ],
      ),
      throwsArgumentError,
    );

    Map<String, Object?>? persisted;
    final report = await runner(
      cases: 1,
      persistence: (json) => persisted = json,
    ).run((_) => const CampaignCaseResult.pass());
    expect(persisted, report.toJson());
  });

  test('persists and reloads reports with VM-only helpers', () async {
    final library = await Isolate.resolvePackageUri(
      Uri.parse('package:c2pa_testkit/c2pa_testkit_vm.dart'),
    );
    final file = File.fromUri(
      library!.resolve('../.dart_tool/campaign-persistence-$pid/report.json'),
    );
    try {
      final report = await runner(cases: 1)
          .run((_) => const CampaignCaseResult.failure('persist me'));
      await writeMutationCampaignReport(file.path, report);
      final restored = await readMutationCampaignReport(file.path);
      expect(restored.toJson(), report.toJson());
    } finally {
      if (await file.parent.exists()) {
        await file.parent.delete(recursive: true);
      }
    }
  });
}

import 'dart:async';
import 'dart:typed_data';

import 'differential.dart';
import 'fixture_asset.dart';
import 'mutation_plan.dart';

typedef CampaignCaseCallback = FutureOr<CampaignCaseResult> Function(
  MutationCampaignCase testCase,
);
typedef CampaignPersistenceHook = FutureOr<void> Function(
  Map<String, Object?> report,
);

final class CampaignCancellationToken {
  final Completer<void> _cancelled = Completer<void>();

  bool get isCancelled => _cancelled.isCompleted;
  Future<void> get whenCancelled => _cancelled.future;

  void cancel() {
    if (!_cancelled.isCompleted) _cancelled.complete();
  }
}

final class MutationCampaignCase {
  const MutationCampaignCase({
    required this.index,
    required this.fixture,
    required this.plan,
    required this.bytes,
    required this.cancellation,
  });

  final int index;
  final FixtureAsset fixture;
  final MutationPlan plan;
  final Uint8List bytes;
  final CampaignCancellationToken cancellation;
}

final class CampaignCaseResult {
  const CampaignCaseResult._({required this.passed, this.reason, this.details});

  const CampaignCaseResult.pass() : this._(passed: true);

  const CampaignCaseResult.failure(String reason, {Object? details})
    : this._(passed: false, reason: reason, details: details);

  final bool passed;
  final String? reason;
  final Object? details;
}

enum CampaignFailureKind { property, timeout, exception }

final class CampaignReplay {
  const CampaignReplay({
    required this.campaignSeed,
    required this.caseIndex,
    required this.caseSeed,
    required this.fixtureName,
    required this.plan,
  });

  factory CampaignReplay.fromJson(Map<String, Object?> json) => CampaignReplay(
    campaignSeed: _int(json, 'campaignSeed'),
    caseIndex: _int(json, 'caseIndex'),
    caseSeed: _int(json, 'caseSeed'),
    fixtureName: _string(json, 'fixtureName'),
    plan: MutationPlan.fromJson(_map(json['plan'], 'plan')),
  );

  final int campaignSeed;
  final int caseIndex;
  final int caseSeed;
  final String fixtureName;
  final MutationPlan plan;

  Uint8List apply(FixtureAsset fixture) {
    if (fixture.name != fixtureName) {
      throw ArgumentError.value(
        fixture.name,
        'fixture',
        'expected fixture "$fixtureName"',
      );
    }
    return plan.apply(fixture.bytes);
  }

  Map<String, Object?> toJson() => {
    'campaignSeed': campaignSeed,
    'caseIndex': caseIndex,
    'caseSeed': caseSeed,
    'fixtureName': fixtureName,
    'plan': plan.toJson(),
  };
}

final class CampaignFailure {
  CampaignFailure({
    required this.kind,
    required this.reason,
    required this.replay,
    required Iterable<MutationClassification> classifications,
    this.details,
  }) : classifications = List.unmodifiable(classifications);

  factory CampaignFailure.fromJson(Map<String, Object?> json) {
    final rawClassifications = json['classifications'];
    if (rawClassifications is! List<Object?>) {
      throw const FormatException('classifications must be an array.');
    }
    return CampaignFailure(
      kind: CampaignFailureKind.values.byName(_string(json, 'kind')),
      reason: _string(json, 'reason'),
      replay: CampaignReplay.fromJson(_map(json['replay'], 'replay')),
      classifications: rawClassifications.map(
        (value) => MutationClassification.values.byName(value.toString()),
      ),
      details: json['details'],
    );
  }

  final CampaignFailureKind kind;
  final String reason;
  final CampaignReplay replay;
  final List<MutationClassification> classifications;
  final Object? details;

  Map<String, Object?> toJson() => {
    'kind': kind.name,
    'reason': reason,
    'replay': replay.toJson(),
    'classifications': classifications
        .map((classification) => classification.name)
        .toList(growable: false),
    if (details != null) 'details': normalizeJson(details),
  };
}

final class MutationCampaignReport {
  MutationCampaignReport({
    required this.seed,
    required this.requestedCases,
    required this.executedCases,
    required this.cancelled,
    required Iterable<CampaignFailure> failures,
  }) : failures = List.unmodifiable(failures);

  factory MutationCampaignReport.fromJson(Map<String, Object?> json) {
    final rawFailures = json['failures'];
    if (rawFailures is! List<Object?>) {
      throw const FormatException('failures must be an array.');
    }
    return MutationCampaignReport(
      seed: _int(json, 'seed'),
      requestedCases: _int(json, 'requestedCases'),
      executedCases: _int(json, 'executedCases'),
      cancelled: _bool(json, 'cancelled'),
      failures: rawFailures.map(
        (failure) => CampaignFailure.fromJson(_map(failure, 'failure')),
      ),
    );
  }

  final int seed;
  final int requestedCases;
  final int executedCases;
  final bool cancelled;
  final List<CampaignFailure> failures;

  bool get passed => !cancelled && failures.isEmpty;

  Map<String, Object?> toJson() => {
    'seed': seed,
    'requestedCases': requestedCases,
    'executedCases': executedCases,
    'cancelled': cancelled,
    'failures': failures
        .map((failure) => failure.toJson())
        .toList(growable: false),
  };
}

final class MutationCampaignConfig {
  MutationCampaignConfig({
    required this.seed,
    this.maxCases = 100,
    this.maxCorpusBytes = 16 * 1024 * 1024,
    this.caseTimeout = const Duration(seconds: 2),
  }) {
    RangeError.checkValueInInterval(maxCases, 1, 1000000, 'maxCases');
    RangeError.checkValueInInterval(
      maxCorpusBytes,
      1,
      0x1fffffffffffff,
      'maxCorpusBytes',
    );
    if (caseTimeout <= Duration.zero) {
      throw ArgumentError.value(caseTimeout, 'caseTimeout', 'must be positive');
    }
  }

  final int seed;
  final int maxCases;
  final int maxCorpusBytes;
  final Duration caseTimeout;
}

final class MutationCampaignRunner {
  MutationCampaignRunner({
    required this.config,
    required this.generator,
    required Iterable<FixtureAsset> corpus,
    this.persistenceHook,
  }) : corpus = List.unmodifiable(corpus) {
    if (this.corpus.isEmpty) {
      throw ArgumentError('Campaign corpus must not be empty.');
    }
    final corpusBytes = this.corpus.fold<int>(
      0,
      (total, fixture) => total + fixture.length,
    );
    if (corpusBytes > config.maxCorpusBytes) {
      throw ArgumentError.value(
        corpusBytes,
        'corpus',
        'exceeds maxCorpusBytes ${config.maxCorpusBytes}',
      );
    }
  }

  final MutationCampaignConfig config;
  final MutationPlanGenerator generator;
  final List<FixtureAsset> corpus;
  final CampaignPersistenceHook? persistenceHook;

  Future<MutationCampaignReport> run(
    CampaignCaseCallback callback, {
    CampaignCancellationToken? cancellation,
  }) async {
    final campaignCancellation = cancellation ?? CampaignCancellationToken();
    final random = SeededByteGenerator(config.seed);
    final failures = <CampaignFailure>[];
    var executedCases = 0;

    for (var index = 0; index < config.maxCases; index++) {
      if (campaignCancellation.isCancelled) break;
      final fixture = corpus[index % corpus.length];
      final caseSeed = random.nextUint32();
      final plan = generator.generate(fixture.bytes, seed: caseSeed);
      final caseCancellation = CampaignCancellationToken();
      final testCase = MutationCampaignCase(
        index: index,
        fixture: fixture,
        plan: plan,
        bytes: plan.apply(fixture.bytes),
        cancellation: caseCancellation,
      );
      executedCases++;

      final callbackFuture = Future<CampaignCaseResult>.sync(
        () => callback(testCase),
      );
      final timeoutMarker = Object();
      final cancellationMarker = Object();
      Object? outcome;
      try {
        outcome = await Future.any<Object?>([
          callbackFuture,
          Future<Object?>.delayed(config.caseTimeout, () => timeoutMarker),
          campaignCancellation.whenCancelled.then<Object?>(
            (_) => cancellationMarker,
          ),
        ]);
      } catch (error) {
        failures.add(
          _failure(
            kind: CampaignFailureKind.exception,
            reason: error.toString(),
            testCase: testCase,
            caseSeed: caseSeed,
          ),
        );
        continue;
      }

      if (identical(outcome, cancellationMarker)) {
        caseCancellation.cancel();
        break;
      }
      if (identical(outcome, timeoutMarker)) {
        caseCancellation.cancel();
        failures.add(
          _failure(
            kind: CampaignFailureKind.timeout,
            reason: 'Case exceeded timeout of ${config.caseTimeout}.',
            testCase: testCase,
            caseSeed: caseSeed,
          ),
        );
        continue;
      }

      final result = outcome! as CampaignCaseResult;
      if (!result.passed) {
        failures.add(
          _failure(
            kind: CampaignFailureKind.property,
            reason: result.reason ?? 'Property failed.',
            details: result.details,
            testCase: testCase,
            caseSeed: caseSeed,
          ),
        );
      }
    }

    final report = MutationCampaignReport(
      seed: config.seed,
      requestedCases: config.maxCases,
      executedCases: executedCases,
      cancelled: campaignCancellation.isCancelled,
      failures: failures,
    );
    await persistenceHook?.call(report.toJson());
    return report;
  }

  CampaignFailure _failure({
    required CampaignFailureKind kind,
    required String reason,
    required MutationCampaignCase testCase,
    required int caseSeed,
    Object? details,
  }) => CampaignFailure(
    kind: kind,
    reason: reason,
    details: details,
    classifications: testCase.plan.classifications,
    replay: CampaignReplay(
      campaignSeed: config.seed,
      caseIndex: testCase.index,
      caseSeed: caseSeed,
      fixtureName: testCase.fixture.name,
      plan: testCase.plan,
    ),
  );
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

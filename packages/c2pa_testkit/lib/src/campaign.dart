import 'dart:async';
import 'dart:typed_data';

import 'differential.dart';
import 'fixture_asset.dart';
import 'mutation_plan.dart';

/// Handles one generated mutation case during a campaign run.
///
/// The callback receives already-mutated [MutationCampaignCase.bytes] and may
/// return synchronously or asynchronously. It should report property failures
/// with [CampaignCaseResult.failure] instead of throwing when possible.
typedef CampaignCaseCallback = FutureOr<CampaignCaseResult> Function(
  MutationCampaignCase testCase,
);

/// Persists a completed campaign report as a JSON-safe map.
///
/// The hook is called once after all cases finish or cancellation stops the
/// loop. Implementations may perform I/O and may be shared by VM or web tests.
typedef CampaignPersistenceHook = FutureOr<void> Function(
  Map<String, Object?> report,
);

/// A cooperative cancellation token for campaign runs and cases.
final class CampaignCancellationToken {
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

/// A generated mutation case passed to a campaign callback.
final class MutationCampaignCase {
  /// Creates a campaign case record.
  ///
  /// [bytes] must be the result of applying [plan] to [fixture]. The
  /// [cancellation] token is cancelled when this individual case times out.
  const MutationCampaignCase({
    required this.index,
    required this.fixture,
    required this.plan,
    required this.bytes,
    required this.cancellation,
  });

  /// The zero-based case index within the campaign run.
  final int index;

  /// The original fixture selected for this case.
  final FixtureAsset fixture;

  /// The deterministic mutation plan applied to [fixture].
  final MutationPlan plan;

  /// The mutated fixture bytes supplied to the test callback.
  final Uint8List bytes;

  /// The per-case cancellation token signalled on timeout.
  final CampaignCancellationToken cancellation;
}

/// The callback outcome for one mutation campaign case.
final class CampaignCaseResult {
  /// Creates a result with [passed], optional [reason], and [details].
  const CampaignCaseResult._({required this.passed, this.reason, this.details});

  /// Creates a passing case result.
  const CampaignCaseResult.pass() : this._(passed: true);

  /// Creates a property-failure case result with a human-readable [reason].
  ///
  /// [details] must be JSON-normalizable when campaign reports are persisted.
  const CampaignCaseResult.failure(String reason, {Object? details})
    : this._(passed: false, reason: reason, details: details);

  /// Whether the tested property accepted the mutated case.
  final bool passed;

  /// The failure reason for a non-passing result, or null for passes.
  final String? reason;

  /// Optional structured failure details supplied by the callback.
  final Object? details;
}

/// The source of a recorded campaign failure.
enum CampaignFailureKind {
  /// The callback returned a failing property result.
  property,

  /// The case exceeded its configured per-case timeout.
  timeout,

  /// The callback threw an exception.
  exception,
}

/// Replay data for reproducing one generated mutation case.
final class CampaignReplay {
  /// Creates replay data for a campaign case.
  ///
  /// [campaignSeed] and [caseSeed] identify the deterministic generation path,
  /// while [plan] is stored so replay does not depend on generator changes.
  const CampaignReplay({
    required this.campaignSeed,
    required this.caseIndex,
    required this.caseSeed,
    required this.fixtureName,
    required this.plan,
  });

  /// Parses replay data from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when required fields are absent or malformed.
  factory CampaignReplay.fromJson(Map<String, Object?> json) => CampaignReplay(
    campaignSeed: _int(json, 'campaignSeed'),
    caseIndex: _int(json, 'caseIndex'),
    caseSeed: _int(json, 'caseSeed'),
    fixtureName: _string(json, 'fixtureName'),
    plan: MutationPlan.fromJson(_map(json['plan'], 'plan')),
  );

  /// The seed used by the full campaign run.
  final int campaignSeed;

  /// The zero-based index of the case within the campaign.
  final int caseIndex;

  /// The per-case seed used to generate [plan].
  final int caseSeed;

  /// The fixture name required for replay safety.
  final String fixtureName;

  /// The exact mutation plan to replay.
  final MutationPlan plan;

  /// Applies the replayed plan to [fixture].
  ///
  /// Throws an [ArgumentError] when [fixture] does not match [fixtureName].
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

  /// Converts this replay record to a JSON-safe map.
  Map<String, Object?> toJson() => {
    'campaignSeed': campaignSeed,
    'caseIndex': caseIndex,
    'caseSeed': caseSeed,
    'fixtureName': fixtureName,
    'plan': plan.toJson(),
  };
}

/// A recorded failure from a mutation campaign run.
final class CampaignFailure {
  /// Creates a campaign failure record.
  ///
  /// [classifications] captures the mutation categories present in the failing
  /// plan. [details] should be JSON-normalizable when reports are persisted.
  CampaignFailure({
    required this.kind,
    required this.reason,
    required this.replay,
    required Iterable<MutationClassification> classifications,
    this.details,
  }) : classifications = List.unmodifiable(classifications);

  /// Parses a campaign failure from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when the classifications array or replay data
  /// is malformed.
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

  /// The failure source: property result, timeout, or thrown exception.
  final CampaignFailureKind kind;

  /// The human-readable failure reason.
  final String reason;

  /// Replay data that reproduces the failing mutation.
  final CampaignReplay replay;

  /// The mutation categories present in the failing plan.
  final List<MutationClassification> classifications;

  /// Optional structured details from the callback or runner.
  final Object? details;

  /// Converts this failure to a JSON-safe map.
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

/// The complete result of a mutation campaign run.
final class MutationCampaignReport {
  /// Creates a campaign report.
  ///
  /// [requestedCases] is the configured maximum, while [executedCases] is the
  /// number actually started before cancellation or completion.
  MutationCampaignReport({
    required this.seed,
    required this.requestedCases,
    required this.executedCases,
    required this.cancelled,
    required Iterable<CampaignFailure> failures,
  }) : failures = List.unmodifiable(failures);

  /// Parses a campaign report from a JSON-safe [json] map.
  ///
  /// Throws a [FormatException] when the failure array or required fields are
  /// malformed.
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

  /// The campaign seed used to derive deterministic case seeds.
  final int seed;

  /// The maximum number of cases requested by the configuration.
  final int requestedCases;

  /// The number of cases that were started during the run.
  final int executedCases;

  /// Whether campaign-level cancellation stopped the run.
  final bool cancelled;

  /// The failures recorded in execution order.
  final List<CampaignFailure> failures;

  /// Whether the run completed without cancellation or failures.
  bool get passed => !cancelled && failures.isEmpty;

  /// Converts this report to a JSON-safe map.
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

/// Configuration that bounds a mutation campaign run.
final class MutationCampaignConfig {
  /// Creates campaign configuration.
  ///
  /// [maxCases] must be 1 to 1,000,000, [maxCorpusBytes] is measured in bytes,
  /// and [caseTimeout] must be positive.
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

  /// The deterministic seed used to generate per-case seeds.
  final int seed;

  /// The maximum number of mutation cases to execute.
  final int maxCases;

  /// The maximum total fixture corpus size in bytes.
  final int maxCorpusBytes;

  /// The timeout for each callback invocation.
  final Duration caseTimeout;
}

/// Runs deterministic mutation campaigns over a fixture corpus.
final class MutationCampaignRunner {
  /// Creates a campaign runner for [corpus].
  ///
  /// Throws an [ArgumentError] when [corpus] is empty or its total byte size
  /// exceeds [MutationCampaignConfig.maxCorpusBytes].
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

  /// The campaign limits and deterministic seed.
  final MutationCampaignConfig config;

  /// The generator used to create one mutation plan per case.
  final MutationPlanGenerator generator;

  /// The immutable fixture corpus cycled by case index.
  final List<FixtureAsset> corpus;

  /// The optional hook invoked once with the completed report JSON.
  final CampaignPersistenceHook? persistenceHook;

  /// Executes the campaign by invoking [callback] for each generated case.
  ///
  /// Cases run sequentially in index order. The runner records property
  /// failures returned by [callback], exceptions thrown by [callback], and
  /// per-case timeouts. The [persistenceHook] is called once after the final
  /// report is built.
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

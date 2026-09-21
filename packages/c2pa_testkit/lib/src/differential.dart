import 'dart:convert';

import 'package:c2pa/c2pa.dart';

/// Projects Dart and oracle output into the same JSON-compatible shape.
abstract interface class NormalizedProjection<T> {
  Object? projectDart(T value);

  Object? projectOracleJson(Object? json);
}

/// Projects complete reports for differential testing.
abstract interface class ReportProjection<T>
    implements NormalizedProjection<T> {}

typedef DartReportProjector<T> = Object? Function(T report);
typedef OracleReportProjector = Object? Function(Object? json);

/// A callback-based projection for report types owned by a consuming package.
final class CallbackReportProjection<T> implements ReportProjection<T> {
  const CallbackReportProjection({
    required this.dartProjector,
    this.oracleProjector,
  });

  final DartReportProjector<T> dartProjector;
  final OracleReportProjector? oracleProjector;

  @override
  Object? projectDart(T value) => normalizeJson(dartProjector(value));

  @override
  Object? projectOracleJson(Object? json) =>
      normalizeJson(oracleProjector?.call(json) ?? json);
}

/// Normalizes [ValidationResults] and common c2pa-rs JSON field spellings.
final class ValidationResultsProjection
    implements ReportProjection<ValidationResults> {
  const ValidationResultsProjection();

  @override
  Object? projectDart(ValidationResults value) => _normalizedValidation(
    state: value.state.name,
    trusted: value.state == ValidationState.trusted,
    issues: value.issues.map(
      (issue) => {
        ...issue.toJson(),
        'severity': issue.severity.name,
        'ingredientUri': ?issue.ingredientUri,
      },
    ),
  );

  @override
  Object? projectOracleJson(Object? json) {
    final root = _stringMap(json, 'oracle JSON');
    final report = switch (root['validation']) {
      final Map<Object?, Object?> nested => _stringMap(nested, 'validation'),
      _ => root,
    };
    final rawIssues =
        report['issues'] ??
        report['validationStatus'] ??
        report['validation_status'] ??
        const <Object?>[];
    if (rawIssues is! List<Object?>) {
      throw const FormatException('Validation issues must be a JSON array.');
    }

    final trusted =
        report['isTrusted'] as bool? ??
        report['is_trusted'] as bool? ??
        report['trusted'] as bool? ??
        false;
    final explicitState = report['state']?.toString();
    return _normalizedValidation(
      state: explicitState ?? (trusted ? 'trusted' : 'valid'),
      trusted: trusted,
      issues: rawIssues.map((issue) => _stringMap(issue, 'validation issue')),
    );
  }

  static Map<String, Object?> _normalizedValidation({
    required String state,
    required bool trusted,
    required Iterable<Map<String, Object?>> issues,
  }) {
    final normalizedIssues = issues.map((issue) {
      final severity =
          issue['severity']?.toString() ?? issue['kind']?.toString() ?? 'error';
      return <String, Object?>{
        'code': issue['code'] ?? issue['status'],
        'severity': severity.toLowerCase(),
        if ((issue['url'] ?? issue['failureUrl'] ?? issue['failure_url'])
            case final Object url)
          'url': url,
        if (issue['explanation'] case final Object explanation)
          'explanation': explanation,
        if ((issue['ingredientUri'] ?? issue['ingredient_uri'])
            case final Object ingredientUri)
          'ingredientUri': ingredientUri,
      };
    }).toList();
    normalizedIssues.sort(
      (left, right) => jsonEncode(left).compareTo(jsonEncode(right)),
    );

    final hasErrors = normalizedIssues.any(
      (issue) => issue['severity'] == 'error' || issue['severity'] == 'failure',
    );
    return <String, Object?>{
      'state': hasErrors ? 'invalid' : state.toLowerCase(),
      'isTrusted': trusted,
      'issues': normalizedIssues,
    };
  }
}

final class DifferentialComparison {
  const DifferentialComparison({
    required this.dart,
    required this.oracle,
    required this.matches,
    this.differences = const [],
  });

  final Object? dart;
  final Object? oracle;
  final bool matches;
  final List<DifferentialDifference> differences;

  String get dartJson => const JsonEncoder.withIndent('  ').convert(dart);
  String get oracleJson => const JsonEncoder.withIndent('  ').convert(oracle);
}

final class DifferentialDifference {
  const DifferentialDifference({
    required this.path,
    required this.dart,
    required this.oracle,
  });

  final String path;
  final Object? dart;
  final Object? oracle;

  @override
  String toString() =>
      '$path: Dart=${jsonEncode(dart)}, oracle=${jsonEncode(oracle)}';
}

DifferentialComparison compareWithOracle<T>({
  required T dartResult,
  required Object? oracleJson,
  required NormalizedProjection<T> projection,
}) {
  final dart = normalizeJson(projection.projectDart(dartResult));
  final oracle = normalizeJson(projection.projectOracleJson(oracleJson));
  final differences = <DifferentialDifference>[];
  _collectDifferences(r'$', dart, oracle, differences);
  return DifferentialComparison(
    dart: dart,
    oracle: oracle,
    matches: differences.isEmpty,
    differences: List.unmodifiable(differences),
  );
}

/// Canonicalizes JSON-compatible data by sorting all map keys.
Object? normalizeJson(Object? value) {
  if (value is Map<Object?, Object?>) {
    final entries =
        value.entries
            .map(
              (entry) =>
                  MapEntry(entry.key.toString(), normalizeJson(entry.value)),
            )
            .toList()
          ..sort((left, right) => left.key.compareTo(right.key));
    return Map<String, Object?>.fromEntries(entries);
  }
  if (value is Iterable<Object?>) {
    return value.map(normalizeJson).toList(growable: false);
  }
  if (value == null || value is String || value is num || value is bool) {
    return value;
  }
  if (value is Uri) {
    return value.toString();
  }
  throw ArgumentError.value(value, 'value', 'must be JSON-compatible');
}

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$name must be a JSON object.');
  }
  return value.map((key, value) => MapEntry(key.toString(), value));
}

void _collectDifferences(
  String path,
  Object? left,
  Object? right,
  List<DifferentialDifference> differences,
) {
  if (identical(left, right) || left == right) return;
  if (left is List<Object?> && right is List<Object?>) {
    final commonLength = left.length < right.length
        ? left.length
        : right.length;
    for (var index = 0; index < commonLength; index++) {
      _collectDifferences(
        '$path[$index]',
        left[index],
        right[index],
        differences,
      );
    }
    for (var index = commonLength; index < left.length; index++) {
      differences.add(
        DifferentialDifference(
          path: '$path[$index]',
          dart: left[index],
          oracle: null,
        ),
      );
    }
    for (var index = commonLength; index < right.length; index++) {
      differences.add(
        DifferentialDifference(
          path: '$path[$index]',
          dart: null,
          oracle: right[index],
        ),
      );
    }
    return;
  }
  if (left is Map<String, Object?> && right is Map<String, Object?>) {
    final keys = {...left.keys, ...right.keys}.toList()..sort();
    for (final key in keys) {
      if (!left.containsKey(key) || !right.containsKey(key)) {
        differences.add(
          DifferentialDifference(
            path: '$path.$key',
            dart: left[key],
            oracle: right[key],
          ),
        );
        continue;
      }
      _collectDifferences('$path.$key', left[key], right[key], differences);
    }
    return;
  }
  differences.add(
    DifferentialDifference(path: path, dart: left, oracle: right),
  );
}

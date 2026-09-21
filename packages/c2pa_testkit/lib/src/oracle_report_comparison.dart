/// Semantic comparison of two c2patool-shaped validation reports.
///
/// This backs the corpus conformance gate: it takes the JSON this SDK produces
/// for an asset and the JSON the reference `c2patool` build produces for the
/// same asset, and reports only the differences that are interoperability
/// defects. Representation choices that both implementations are free to make
/// differently — JUMBF URI form, status ordering, the wording of an error —
/// are normalized away so the signal is not buried.
library;

import 'dart:convert';

/// A single semantic disagreement between the two reports.
final class OracleReportDifference {
  const OracleReportDifference({
    required this.kind,
    this.items = const [],
    this.oracle,
    this.dart,
  });

  /// Stable machine-readable category, e.g. `status.failure.extra-in-dart`.
  ///
  /// Suffixed `-in-dart` kinds are oriented from this SDK's point of view:
  /// `extra-in-dart` means this SDK reported something the reference did not.
  final String kind;

  /// Offending entries, for the set-shaped kinds.
  final List<String> items;

  final Object? oracle;
  final Object? dart;

  @override
  String toString() {
    if (items.isNotEmpty) return '$kind: ${items.join(', ')}';
    return '$kind: oracle=${jsonEncode(oracle)}, dart=${jsonEncode(dart)}';
  }
}

/// Outcome of comparing one asset.
final class OracleReportComparison {
  const OracleReportComparison({
    required this.differences,
    required this.bothRejected,
  });

  final List<OracleReportDifference> differences;

  /// Both implementations refused to produce a report.
  ///
  /// The wording of the two rejections is not a conformance property, so this
  /// counts as agreement.
  final bool bothRejected;

  bool get agrees => differences.isEmpty;
}

/// Status codes whose value is decided by trust-store configuration rather
/// than by the implementation under test.
///
/// `c2patool` ships a default trust store (DigiCert timestamp roots, the C2PA
/// test signer list); the `c2pa-rs` SDK defaults to none. The same build
/// therefore reports these differently depending only on the entry point, so
/// comparing them measures configuration, not conformance. Pass
/// `ignoreTrustConfiguration: false` to include them anyway.
const trustConfigurationCodes = <String>{
  'timeStamp.trusted',
  'timeStamp.untrusted',
  'signingCredential.trusted',
  'signingCredential.untrusted',
};

const _buckets = ['success', 'informational', 'failure'];

/// Compares one asset's reports.
///
/// Pass `null` for [oracleReport] or [dartReport] when that implementation
/// failed to produce a report at all.
OracleReportComparison compareOracleReports({
  required Map<String, Object?>? oracleReport,
  required Map<String, Object?>? dartReport,
  bool ignoreTrustConfiguration = true,
}) {
  if (oracleReport == null && dartReport == null) {
    return const OracleReportComparison(differences: [], bothRejected: true);
  }
  if (oracleReport == null) {
    return const OracleReportComparison(
      differences: [
        OracleReportDifference(kind: 'oracle-rejects-dart-accepts'),
      ],
      bothRejected: false,
    );
  }
  if (dartReport == null) {
    return const OracleReportComparison(
      differences: [
        OracleReportDifference(kind: 'dart-rejects-oracle-accepts'),
      ],
      bothRejected: false,
    );
  }

  final differences = <OracleReportDifference>[];

  final oracleState = oracleReport['validation_state']?.toString();
  final dartState = dartReport['validation_state']?.toString();
  if (oracleState?.toLowerCase() != dartState?.toLowerCase()) {
    differences.add(
      OracleReportDifference(
        kind: 'validation_state',
        oracle: oracleState,
        dart: dartState,
      ),
    );
  } else if (oracleState != dartState) {
    // Same verdict, different spelling. Upstream serializes `Valid` /
    // `Invalid` / `Trusted`.
    differences.add(
      OracleReportDifference(
        kind: 'validation_state-case',
        oracle: oracleState,
        dart: dartState,
      ),
    );
  }

  final oracleShape = _manifestShape(oracleReport);
  final dartShape = _manifestShape(dartReport);
  for (final field in oracleShape.keys) {
    if (!_deepEquals(oracleShape[field], dartShape[field])) {
      differences.add(
        OracleReportDifference(
          kind: 'manifest.$field',
          oracle: oracleShape[field],
          dart: dartShape[field],
        ),
      );
    }
  }

  differences.addAll(
    _diffStatuses(
      oracle: _activeStatuses(oracleReport, ignoreTrustConfiguration),
      dart: _activeStatuses(dartReport, ignoreTrustConfiguration),
      label: 'status',
    ),
  );

  differences.addAll(
    _diffIngredientDeltas(
      oracle: _ingredientDeltas(oracleReport, ignoreTrustConfiguration),
      dart: _ingredientDeltas(dartReport, ignoreTrustConfiguration),
    ),
  );

  final oracleForms = _urlForms(oracleReport, ignoreTrustConfiguration);
  final dartForms = _urlForms(dartReport, ignoreTrustConfiguration);
  if (!_deepEquals(oracleForms, dartForms)) {
    differences.add(
      OracleReportDifference(
        kind: 'status-uri-form',
        oracle: oracleForms,
        dart: dartForms,
      ),
    );
  }

  return OracleReportComparison(
    differences: List.unmodifiable(differences),
    bothRejected: false,
  );
}

/// Structural fields that must agree regardless of report formatting.
Map<String, Object?> _manifestShape(Map<String, Object?> report) {
  final manifests = _map(report['manifests']) ?? const {};
  final activeLabel = report['active_manifest']?.toString();
  final active = _map(manifests[activeLabel]) ?? const {};
  final signature = _map(active['signature_info']) ?? const {};
  return {
    'active_manifest': activeLabel,
    'manifest_labels': manifests.keys.map((key) => key.toString()).toList()
      ..sort(),
    'assertion_labels': [
      for (final assertion in _list(active['assertions']))
        if (_map(assertion)?['label'] case final Object label) label.toString(),
    ]..sort(),
    'title': active['title'],
    'format': active['format'],
    'instance_id': active['instance_id'],
    'claim_generator': active['claim_generator'],
    'signature_alg': signature['alg'],
    'cert_serial': signature['cert_serial_number'],
    'ingredient_titles': [
      for (final ingredient in _list(active['ingredients']))
        _map(ingredient)?['title']?.toString() ?? '',
    ]..sort(),
  };
}

/// Strips `self#jumbf=` and the manifest-label segment so that absolute and
/// relative JUMBF URIs become comparable.
///
/// The URI *form* is tracked separately as `status-uri-form`, so collapsing it
/// here loses no signal.
String normalizeJumbfUri(String? uri) {
  if (uri == null) return '';
  var value = uri.replaceFirst('self#jumbf=', '');
  if (value.startsWith('/c2pa/')) {
    final parts = value.split('/');
    value = parts.length > 3 ? parts.sublist(3).join('/') : '';
  }
  return _trimSlashes(value);
}

Map<String, Map<String, int>> _activeStatuses(
  Map<String, Object?> report,
  bool ignoreTrust,
) {
  final active =
      _map(_map(report['validation_results'])?['activeManifest']) ?? const {};
  return {
    for (final bucket in _buckets)
      bucket: _countStatuses(_list(active[bucket]), ignoreTrust),
  };
}

Map<String, int> _countStatuses(List<Object?> entries, bool ignoreTrust) {
  final counts = <String, int>{};
  for (final entry in entries) {
    final status = _map(entry);
    if (status == null) continue;
    final code = status['code']?.toString() ?? '';
    if (ignoreTrust && trustConfigurationCodes.contains(code)) continue;
    final key = '$code @ ${normalizeJumbfUri(status['url']?.toString())}';
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

/// Ingredient deltas keyed by assertion URI.
///
/// The manifest-label segment is deliberately *kept* here: nested ingredients
/// in different manifests share the same assertion tail, so collapsing it makes
/// later entries silently overwrite earlier ones.
Map<String, Map<String, List<String>>> _ingredientDeltas(
  Map<String, Object?> report,
  bool ignoreTrust,
) {
  final deltas = _list(_map(report['validation_results'])?['ingredientDeltas']);
  final result = <String, Map<String, List<String>>>{};
  for (final entry in deltas) {
    final delta = _map(entry);
    if (delta == null) continue;
    final key = _trimSlashes(
      (delta['ingredientAssertionURI']?.toString() ?? '').replaceFirst(
        'self#jumbf=',
        '',
      ),
    );
    final buckets = _map(delta['validationDeltas']) ?? const {};
    result[key] = {
      for (final bucket in _buckets)
        bucket: [
          for (final item in _list(buckets[bucket]))
            if (_map(item)?['code']?.toString() case final String code)
              if (!(ignoreTrust && trustConfigurationCodes.contains(code)))
                code,
        ]..sort(),
    };
  }
  return result;
}

List<OracleReportDifference> _diffStatuses({
  required Map<String, Map<String, int>> oracle,
  required Map<String, Map<String, int>> dart,
  required String label,
}) {
  final differences = <OracleReportDifference>[];
  for (final bucket in _buckets) {
    final onlyOracle = _subtract(oracle[bucket]!, dart[bucket]!);
    final onlyDart = _subtract(dart[bucket]!, oracle[bucket]!);
    if (onlyOracle.isNotEmpty) {
      differences.add(
        OracleReportDifference(
          kind: '$label.$bucket.missing-in-dart',
          items: onlyOracle,
        ),
      );
    }
    if (onlyDart.isNotEmpty) {
      differences.add(
        OracleReportDifference(
          kind: '$label.$bucket.extra-in-dart',
          items: onlyDart,
        ),
      );
    }
  }
  return differences;
}

List<OracleReportDifference> _diffIngredientDeltas({
  required Map<String, Map<String, List<String>>> oracle,
  required Map<String, Map<String, List<String>>> dart,
}) {
  final differences = <OracleReportDifference>[];
  final keys = {...oracle.keys, ...dart.keys}.toList()..sort();
  for (final key in keys) {
    final oracleDelta = oracle[key];
    final dartDelta = dart[key];
    if (dartDelta == null) {
      differences.add(
        OracleReportDifference(
          kind: 'ingredient.delta.missing-in-dart',
          items: [key],
        ),
      );
      continue;
    }
    if (oracleDelta == null) {
      differences.add(
        OracleReportDifference(
          kind: 'ingredient.delta.extra-in-dart',
          items: [key],
        ),
      );
      continue;
    }
    for (final bucket in _buckets) {
      final onlyOracle = _subtract(
        _tally(oracleDelta[bucket]!),
        _tally(dartDelta[bucket]!),
      );
      final onlyDart = _subtract(
        _tally(dartDelta[bucket]!),
        _tally(oracleDelta[bucket]!),
      );
      if (onlyOracle.isNotEmpty) {
        differences.add(
          OracleReportDifference(
            kind: 'ingredient.$bucket.missing-in-dart',
            items: [for (final code in onlyOracle) '$code @ $key'],
          ),
        );
      }
      if (onlyDart.isNotEmpty) {
        differences.add(
          OracleReportDifference(
            kind: 'ingredient.$bucket.extra-in-dart',
            items: [for (final code in onlyDart) '$code @ $key'],
          ),
        );
      }
    }
  }
  return differences;
}

/// Which JUMBF URI forms the report uses.
///
/// Deliberately presence, not counts: a count would also fire whenever the
/// number of statuses differs, double-reporting something
/// `status.*.missing-in-dart` already says. c2pa-rs writes every status URL in
/// absolute form, so a `relative` entry here is the finding.
List<String> _urlForms(Map<String, Object?> report, bool ignoreTrust) {
  final active =
      _map(_map(report['validation_results'])?['activeManifest']) ?? const {};
  final forms = <String>{};
  for (final bucket in _buckets) {
    for (final entry in _list(active[bucket])) {
      final status = _map(entry);
      if (status == null) continue;
      final code = status['code']?.toString() ?? '';
      if (ignoreTrust && trustConfigurationCodes.contains(code)) continue;
      final url = status['url']?.toString() ?? '';
      forms.add(url.contains('/c2pa/') ? 'absolute' : 'relative');
    }
  }
  return forms.toList()..sort();
}

Map<String, int> _tally(List<String> values) {
  final counts = <String, int>{};
  for (final value in values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return counts;
}

/// Multiset difference, expanded back into a sorted list of entries.
List<String> _subtract(Map<String, int> left, Map<String, int> right) {
  final result = <String>[];
  for (final entry in left.entries) {
    final surplus = entry.value - (right[entry.key] ?? 0);
    for (var index = 0; index < surplus; index++) {
      result.add(entry.key);
    }
  }
  return result..sort();
}

String _trimSlashes(String value) {
  var start = 0;
  var end = value.length;
  while (start < end && value[start] == '/') {
    start++;
  }
  while (end > start && value[end - 1] == '/') {
    end--;
  }
  return value.substring(start, end);
}

Map<String, Object?>? _map(Object? value) => switch (value) {
  final Map<String, Object?> map => map,
  final Map<Object?, Object?> map => map.map(
    (key, value) => MapEntry(key.toString(), value),
  ),
  _ => null,
};

List<Object?> _list(Object? value) =>
    value is List<Object?> ? value : const <Object?>[];

bool _deepEquals(Object? left, Object? right) =>
    jsonEncode(left) == jsonEncode(right);

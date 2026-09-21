import 'dart:convert';

import 'differential.dart';

enum ConformanceField {
  activeManifest,
  manifestLabels,
  assertionLabels,
  assertionHashes,
  validationCategories,
  validationCodes,
  validationUrls,
  state,
  signatureAlgorithm,
  ingredientDeltas,
  identityAssertions,
}

final class ConformanceIgnore {
  const ConformanceIgnore([this.fields = const {}]);

  final Set<ConformanceField> fields;

  bool ignores(ConformanceField field) => fields.contains(field);
}

typedef ConformanceProjector<T> = Map<String, Object?> Function(T value);

/// Normalizes the conformance-relevant subset of Dart and c2pa-rs reports.
///
/// Validation timestamps and human-readable explanations are intentionally
/// excluded because they are nondeterministic or diagnostic rather than
/// conformance identifiers. Validation codes, categories, and URLs remain in
/// the projection so interoperability failures cannot be hidden by wording
/// differences.
final class ConformanceReportProjection<T> implements ReportProjection<T> {
  const ConformanceReportProjection({
    required this.dartProjector,
    this.oracleProjector,
    this.ignore = const ConformanceIgnore(),
  });

  final ConformanceProjector<T> dartProjector;
  final ConformanceProjector<Object?>? oracleProjector;
  final ConformanceIgnore ignore;

  @override
  Object? projectDart(T value) => _project(dartProjector(value));

  @override
  Object? projectOracleJson(Object? json) =>
      _project(oracleProjector?.call(json) ?? _asMap(json, 'oracle report'));

  Map<String, Object?> _project(Map<String, Object?> report) {
    final activeManifest =
        report['activeManifest'] ??
        report['active_manifest'] ??
        report['active_manifest_label'];
    final manifests = _optionalMap(report['manifests']);
    final activeManifestReport = activeManifest == null
        ? null
        : _optionalMap(manifests?[activeManifest.toString()]);
    final validation = _optionalMap(
      report['validation'] ?? report['validation_results'],
    );
    final statuses = _validationStatuses(
      validation,
      report,
      activeManifest.toString(),
    );
    final assertions = _assertionMaps(report, activeManifestReport);
    final result = <String, Object?>{};

    if (!ignore.ignores(ConformanceField.activeManifest)) {
      result['activeManifest'] = activeManifest;
    }
    if (!ignore.ignores(ConformanceField.manifestLabels)) {
      result['manifestLabels'] = _sortedStrings(
        report['manifestLabels'] ??
            report['manifest_labels'] ??
            _mapKeys(report['manifests']),
      );
    }
    if (!ignore.ignores(ConformanceField.assertionLabels)) {
      result['assertionLabels'] = _sortedStrings(
        report['assertionLabels'] ??
            report['assertion_labels'] ??
            assertions.map((assertion) => assertion['label']),
      );
    }
    if (!ignore.ignores(ConformanceField.assertionHashes)) {
      result['assertionHashes'] = _normalizedAssertionHashes(
        report['assertionHashes'] ?? report['assertion_hashes'],
        assertions,
        includeLabels: !ignore.ignores(ConformanceField.assertionLabels),
      );
    }
    if (!ignore.ignores(ConformanceField.validationCategories)) {
      result['validationCategories'] = _sortedStrings(
        validation?['categories'] ??
            report['validationCategories'] ??
            report['validation_categories'] ??
            statuses.map(
              (status) =>
                  status['category'] ?? status['severity'] ?? status['kind'],
            ),
        lowerCase: true,
      );
    }
    if (!ignore.ignores(ConformanceField.validationCodes)) {
      result['validationCodes'] = _sortedStrings(
        validation?['codes'] ??
            report['validationCodes'] ??
            report['validation_codes'] ??
            statuses.map((status) => status['code'] ?? status['status']),
      );
    }
    if (!ignore.ignores(ConformanceField.validationUrls)) {
      result['validationUrls'] = _sortedStrings(
        validation?['urls'] ??
            report['validationUrls'] ??
            report['validation_urls'] ??
            statuses.map(
              (status) =>
                  status['url'] ??
                  status['failureUrl'] ??
                  status['failure_url'],
            ),
      ).map(_normalizeJumbfUrl).toList()..sort();
    }
    if (!ignore.ignores(ConformanceField.state)) {
      result['state'] =
          (validation?['state'] ??
                  report['state'] ??
                  report['validationState'] ??
                  report['validation_state'])
              ?.toString()
              .toLowerCase() ??
          _derivedState(statuses);
    }
    if (!ignore.ignores(ConformanceField.signatureAlgorithm)) {
      final signature = _optionalMap(
        report['signature'] ??
            report['signature_info'] ??
            activeManifestReport?['signature'] ??
            activeManifestReport?['signature_info'],
      );
      result['signatureAlgorithm'] =
          (report['signatureAlgorithm'] ??
                  report['signature_algorithm'] ??
                  signature?['algorithm'] ??
                  signature?['alg'])
              ?.toString()
              .toLowerCase();
    }
    if (!ignore.ignores(ConformanceField.ingredientDeltas)) {
      final deltas =
          report['ingredientDeltas'] ??
          report['ingredient_deltas'] ??
          validation?['ingredientDeltas'] ??
          validation?['ingredient_deltas'] ??
          const <Object?>[];
      result['ingredientDeltas'] = _normalizedDeltas(deltas);
    }
    if (!ignore.ignores(ConformanceField.identityAssertions)) {
      result['identityAssertions'] = _normalizedIdentityAssertions(
        report['identityAssertions'] ??
            report['identity_assertions'] ??
            activeManifestReport?['identityAssertions'] ??
            activeManifestReport?['identity_assertions'] ??
            const <Object?>[],
      );
    }
    return normalizeJson(result) as Map<String, Object?>;
  }
}

final class ConformanceFixtureSource {
  const ConformanceFixtureSource({
    required this.url,
    required this.license,
    this.attribution,
  });

  factory ConformanceFixtureSource.fromJson(Map<String, Object?> json) {
    return ConformanceFixtureSource(
      url: _requiredString(json, 'url'),
      license: _requiredString(json, 'license'),
      attribution: _optionalString(json['attribution'], 'attribution'),
    );
  }

  final String url;
  final String license;
  final String? attribution;
}

final class ConformanceFixture {
  ConformanceFixture({
    required this.id,
    required this.asset,
    required this.source,
    this.skipReason,
    Map<String, Object?> metadata = const {},
  }) : metadata = Map.unmodifiable(metadata);

  factory ConformanceFixture.fromJson(Map<String, Object?> json) {
    return ConformanceFixture(
      id: _requiredString(json, 'id'),
      asset: _validatedAssetPath(_requiredString(json, 'asset')),
      source: ConformanceFixtureSource.fromJson(
        _asMap(json['source'], 'fixture source'),
      ),
      skipReason: _optionalString(json['skipReason'], 'skipReason'),
      metadata: switch (json['metadata']) {
        null => const {},
        final Object value => _asMap(value, 'fixture metadata'),
      },
    );
  }

  final String id;
  final String asset;
  final ConformanceFixtureSource source;
  final String? skipReason;
  final Map<String, Object?> metadata;

  bool get isSkipped => skipReason != null;
}

final class ConformanceFixtureIndex {
  ConformanceFixtureIndex({
    required this.schemaVersion,
    required Iterable<ConformanceFixture> fixtures,
  }) : fixtures = List.unmodifiable(fixtures) {
    if (schemaVersion < 1) {
      throw ArgumentError.value(schemaVersion, 'schemaVersion', 'must be >= 1');
    }
    final ids = <String>{};
    for (final fixture in this.fixtures) {
      if (!ids.add(fixture.id)) {
        throw FormatException('Duplicate fixture id "${fixture.id}".');
      }
    }
  }

  factory ConformanceFixtureIndex.fromJson(Map<String, Object?> json) {
    final schemaVersion = json['schemaVersion'] ?? json['schema_version'];
    if (schemaVersion is! int) {
      throw const FormatException('schemaVersion must be an integer.');
    }
    final fixtures = json['fixtures'];
    if (fixtures is! List<Object?>) {
      throw const FormatException('fixtures must be a JSON array.');
    }
    return ConformanceFixtureIndex(
      schemaVersion: schemaVersion,
      fixtures: fixtures.map(
        (fixture) =>
            ConformanceFixture.fromJson(_asMap(fixture, 'fixture entry')),
      ),
    );
  }

  final int schemaVersion;
  final List<ConformanceFixture> fixtures;
}

Map<String, Object?> _asMap(Object? value, String name) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$name must be a JSON object.');
  }
  return value.map((key, value) => MapEntry(key.toString(), value));
}

Map<String, Object?>? _optionalMap(Object? value) =>
    value == null ? null : _asMap(value, 'report field');

Iterable<String> _mapKeys(Object? value) => value is Map<Object?, Object?>
    ? value.keys.map((key) => key.toString())
    : [];

List<Map<String, Object?>> _statusMaps(Object? value, {String? category}) {
  if (value == null) return const [];
  if (value is! Iterable<Object?>) {
    throw const FormatException('Validation statuses must be an array.');
  }
  return value.map((status) {
    final mapped = _asMap(status, 'validation status');
    if (category != null &&
        mapped['category'] == null &&
        mapped['severity'] == null &&
        mapped['kind'] == null) {
      mapped['category'] = category;
    }
    return mapped;
  }).toList();
}

List<Map<String, Object?>> _validationStatuses(
  Map<String, Object?>? validation,
  Map<String, Object?> report,
  String activeManifest,
) {
  final direct =
      validation?['issues'] ??
      validation?['statuses'] ??
      validation?['validation_status'];
  if (direct != null) return _statusMaps(direct);

  final active =
      _optionalMap(validation?['activeManifest']) ??
      _optionalMap(validation?['active_manifest']) ??
      _optionalMap(validation?[activeManifest]);
  if (active == null) {
    return _statusMaps(
      report['validationStatus'] ?? report['validation_status'],
    );
  }

  final statuses = <Map<String, Object?>>[];
  for (final category in const [
    'success',
    'informational',
    'warning',
    'failure',
  ]) {
    statuses.addAll(_statusMaps(active[category], category: category));
  }
  return statuses;
}

List<Map<String, Object?>> _assertionMaps(
  Map<String, Object?> report,
  Map<String, Object?>? activeManifest,
) {
  final direct = report['assertions'] ?? activeManifest?['assertions'];
  if (direct is Iterable<Object?>) {
    return direct.map((value) => _asMap(value, 'assertion')).toList();
  }
  return const [];
}

List<String> _sortedStrings(Object? values, {bool lowerCase = false}) {
  final iterable = values is Iterable<Object?> ? values : const <Object?>[];
  final result = iterable
      .where((value) => value != null)
      .map(
        (value) =>
            lowerCase ? value.toString().toLowerCase() : value.toString(),
      )
      .toList();
  result.sort();
  return result;
}

List<Object?> _normalizedDeltas(Object? value) {
  if (value is! Iterable<Object?>) {
    throw const FormatException('Ingredient deltas must be an array.');
  }
  final result = value
      .map((entry) {
        final delta = _asMap(entry, 'ingredient delta');
        final statuses = _optionalMap(
          delta['validationDeltas'] ?? delta['validation_deltas'],
        );
        return <String, Object?>{
          if ((delta['ingredientAssertionURI'] ??
                  delta['ingredient_assertion_uri'])
              case final Object uri)
            'ingredientAssertionURI': _normalizeJumbfUrl(uri.toString()),
          if (statuses != null)
            'validationDeltas': {
              for (final category in const [
                'success',
                'informational',
                'warning',
                'failure',
              ])
                if (statuses[category] != null)
                  category: _statusMaps(statuses[category])
                      .map(
                        (status) => {
                          if ((status['code'] ?? status['status'])
                              case final Object code)
                            'code': code.toString(),
                          if ((status['url'] ??
                                  status['failureUrl'] ??
                                  status['failure_url'])
                              case final Object url)
                            'url': _normalizeJumbfUrl(url.toString()),
                        },
                      )
                      .toList(growable: false),
            },
        };
      })
      .map(normalizeJson)
      .toList();
  result.sort((left, right) => jsonEncode(left).compareTo(jsonEncode(right)));
  return result;
}

String _normalizeJumbfUrl(String value) {
  const prefix = 'self#jumbf=/c2pa/';
  if (!value.startsWith(prefix)) return value;
  final relativeStart = value.indexOf('/', prefix.length);
  if (relativeStart < 0 || relativeStart == value.length - 1) return value;
  return 'self#jumbf=${value.substring(relativeStart + 1)}';
}

List<Object?> _normalizedIdentityAssertions(Object? value) {
  if (value is! Iterable<Object?>) {
    throw const FormatException('Identity assertions must be an array.');
  }
  return value
      .map((entry) {
        final identity = _asMap(entry, 'identity assertion');
        final signerPayload = _optionalMap(
          identity['signerPayload'] ?? identity['signer_payload'],
        );
        final statuses = _statusMaps(identity['statuses']);
        return normalizeJson({
          'assertionLabel':
              identity['assertionLabel'] ?? identity['assertion_label'],
          'signatureType':
              signerPayload?['sig_type'] ??
              signerPayload?['signatureType'] ??
              identity['sig_type'],
          'referencedAssertions':
              signerPayload?['referenced_assertions'] ??
              signerPayload?['referencedAssertions'] ??
              identity['referenced_assertions'] ??
              const <Object?>[],
          'statuses': statuses
              .map(
                (status) => {
                  'code': status['code'] ?? status['status'],
                  'severity':
                      status['severity'] ??
                      status['category'] ??
                      status['kind'],
                  if ((status['url'] ??
                          status['failureUrl'] ??
                          status['failure_url'])
                      case final Object url)
                    'url': _normalizeJumbfUrl(url.toString()),
                },
              )
              .toList(growable: false),
          if ((identity['credential'] ?? identity['credentialSummary'])
              case final Object credential)
            'credential': credential,
        });
      })
      .toList(growable: false);
}

List<Object?> _normalizedAssertionHashes(
  Object? explicitHashes,
  List<Map<String, Object?>> assertions, {
  required bool includeLabels,
}) {
  if (explicitHashes != null) {
    return _sortedStrings(explicitHashes, lowerCase: true);
  }
  final result = <Object?>[];
  for (final assertion in assertions) {
    final hash =
        assertion['hash'] ?? assertion['digest'] ?? assertion['sha256'];
    if (hash == null) continue;
    if (includeLabels) {
      result.add({
        'label': assertion['label']?.toString(),
        'hash': hash.toString().toLowerCase(),
      });
    } else {
      result.add(hash.toString().toLowerCase());
    }
  }
  result.sort((left, right) => jsonEncode(left).compareTo(jsonEncode(right)));
  return result;
}

String _requiredString(Map<String, Object?> json, String key) {
  final value = _optionalString(json[key], key);
  if (value == null) throw FormatException('$key must be a non-empty string.');
  return value;
}

String? _optionalString(Object? value, String name) {
  if (value == null) return null;
  if (value is! String || value.trim().isEmpty) {
    throw FormatException('$name must be a non-empty string.');
  }
  return value;
}

String? _derivedState(List<Map<String, Object?>> statuses) {
  final categories = statuses
      .map(
        (status) => (status['category'] ?? status['severity'] ?? status['kind'])
            ?.toString()
            .toLowerCase(),
      )
      .toSet();
  if (categories.contains('failure') || categories.contains('error')) {
    return 'invalid';
  }
  if (statuses.isEmpty) return null;
  final trusted = statuses.any(
    (status) =>
        (status['code'] ?? status['status'])?.toString() ==
        'signingCredential.trusted',
  );
  return trusted ? 'trusted' : 'valid';
}

String _validatedAssetPath(String asset) {
  final uri = Uri.parse(asset.replaceAll(r'\', '/'));
  if (uri.isAbsolute || uri.pathSegments.contains('..')) {
    throw FormatException(
      'asset must be a relative path within the fixture set.',
    );
  }
  return asset;
}

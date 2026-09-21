import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  Map<String, Object?> dartReport() => {
    'activeManifest': 'urn:manifest:one',
    'manifestLabels': ['urn:manifest:two', 'urn:manifest:one'],
    'assertions': [
      {'label': 'c2pa.actions', 'hash': 'bbb'},
      {'label': 'c2pa.hash.data', 'hash': 'aaa'},
    ],
    'validation': {
      'state': 'VALID',
      'issues': [
        {
          'code': 'claimSignature.validated',
          'category': 'success',
          'url': 'self#jumbf=/c2pa',
        },
      ],
    },
    'signatureAlgorithm': 'ES256',
    'ingredientDeltas': [
      {'added': 'one'},
      {'removed': 'two'},
    ],
    'identityAssertions': [
      {
        'assertionLabel': 'cawg.identity',
        'signerPayload': {
          'sig_type': 'cawg.identity_claims_aggregation',
          'referenced_assertions': [
            {'url': 'self#jumbf=c2pa.assertions/c2pa.hash.data'},
          ],
        },
        'statuses': [
          {
            'code': 'cawg.ica.credential_valid',
            'severity': 'success',
            'explanation': 'implementation-specific wording',
          },
        ],
        'credential': {'issuer': 'did:jwk:example'},
      },
    ],
  };

  Map<String, Object?> oracleReport() => {
    'active_manifest': 'urn:manifest:one',
    'manifest_labels': ['urn:manifest:one', 'urn:manifest:two'],
    'assertions': [
      {'label': 'c2pa.hash.data', 'digest': 'aaa'},
      {'label': 'c2pa.actions', 'sha256': 'bbb'},
    ],
    'validation_results': {
      'state': 'valid',
      'validation_status': [
        {
          'status': 'claimSignature.validated',
          'kind': 'success',
          'url': 'self#jumbf=/c2pa',
        },
      ],
    },
    'signature_info': {'alg': 'ES256'},
    'ingredient_deltas': [
      {'removed': 'two'},
      {'added': 'one'},
    ],
    'identity_assertions': [
      {
        'assertion_label': 'cawg.identity',
        'signer_payload': {
          'sig_type': 'cawg.identity_claims_aggregation',
          'referenced_assertions': [
            {'url': 'self#jumbf=c2pa.assertions/c2pa.hash.data'},
          ],
        },
        'statuses': [
          {
            'status': 'cawg.ica.credential_valid',
            'kind': 'success',
            'explanation': 'different wording is intentionally ignored',
          },
        ],
        'credentialSummary': {'issuer': 'did:jwk:example'},
      },
    ],
  };

  test('compares all normalized conformance fields', () {
    final comparison = compareWithOracle(
      dartResult: dartReport(),
      oracleJson: oracleReport(),
      projection: ConformanceReportProjection<Map<String, Object?>>(
        dartProjector: (report) => report,
      ),
    );

    expect(comparison.matches, isTrue);
    expect(comparison.differences, isEmpty);
  });

  test('ignored fields are explicitly omitted', () {
    final oracle = oracleReport()
      ..['signature_info'] = {'alg': 'PS256'}
      ..['active_manifest'] = 'different';
    final comparison = compareWithOracle(
      dartResult: dartReport(),
      oracleJson: oracle,
      projection: ConformanceReportProjection<Map<String, Object?>>(
        dartProjector: (report) => report,
        ignore: const ConformanceIgnore({
          ConformanceField.activeManifest,
          ConformanceField.signatureAlgorithm,
        }),
      ),
    );

    expect(comparison.matches, isTrue);
    expect(
      comparison.dart as Map<String, Object?>,
      isNot(contains('signatureAlgorithm')),
    );
  });

  test('produces stable path-sorted differences', () {
    final oracle = oracleReport()
      ..['active_manifest'] = 'urn:manifest:other'
      ..['manifest_labels'] = ['urn:manifest:three'];
    final projection = ConformanceReportProjection<Map<String, Object?>>(
      dartProjector: (report) => report,
    );

    final first = compareWithOracle(
      dartResult: dartReport(),
      oracleJson: oracle,
      projection: projection,
    );
    final second = compareWithOracle(
      dartResult: dartReport(),
      oracleJson: oracle,
      projection: projection,
    );

    expect(first.matches, isFalse);
    expect(
      first.differences.map((difference) => difference.path),
      second.differences.map((difference) => difference.path),
    );
    expect(first.differences.first.path, r'$.activeManifest');
    expect(first.differences.map((difference) => difference.toString()), [
      r'$.activeManifest: Dart="urn:manifest:one", oracle="urn:manifest:other"',
      r'$.manifestLabels[0]: Dart="urn:manifest:one", oracle="urn:manifest:three"',
      r'$.manifestLabels[1]: Dart="urn:manifest:two", oracle=null',
    ]);
  });

  test('understands categorized c2pa-rs validation results', () {
    final dart = dartReport()
      ..['validation'] = {
        'state': 'invalid',
        'issues': [
          {
            'code': 'claimSignature.mismatch',
            'category': 'failure',
            'url': 'self#jumbf=/c2pa',
          },
        ],
      }
      ..['signatureAlgorithm'] = 'es256';
    final oracle = {
      'active_manifest': 'urn:manifest:one',
      'manifests': {
        'urn:manifest:one': {
          'assertions': [
            {'label': 'c2pa.actions', 'hash': 'bbb'},
            {'label': 'c2pa.hash.data', 'hash': 'aaa'},
          ],
          'signature_info': {'alg': 'ES256'},
        },
        'urn:manifest:two': <String, Object?>{},
      },
      'validation_results': {
        'activeManifest': {
          'failure': [
            {'code': 'claimSignature.mismatch', 'url': 'self#jumbf=/c2pa'},
          ],
        },
      },
      'ingredient_deltas': [
        {'removed': 'two'},
        {'added': 'one'},
      ],
      'identity_assertions': oracleReport()['identity_assertions'],
    };

    final comparison = compareWithOracle(
      dartResult: dart,
      oracleJson: oracle,
      projection: ConformanceReportProjection<Map<String, Object?>>(
        dartProjector: (report) => report,
      ),
    );

    expect(comparison.matches, isTrue);
  });

  test('keeps assertion hashes associated with their labels', () {
    final oracle = oracleReport()
      ..['assertions'] = [
        {'label': 'c2pa.actions', 'hash': 'aaa'},
        {'label': 'c2pa.hash.data', 'hash': 'bbb'},
      ];
    final comparison = compareWithOracle(
      dartResult: dartReport(),
      oracleJson: oracle,
      projection: ConformanceReportProjection<Map<String, Object?>>(
        dartProjector: (report) => report,
      ),
    );

    expect(comparison.matches, isFalse);
    expect(
      comparison.differences.any(
        (difference) => difference.path.startsWith(r'$.assertionHashes'),
      ),
      isTrue,
    );
  });
}

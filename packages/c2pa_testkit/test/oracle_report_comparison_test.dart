import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

Map<String, Object?> _report({
  String state = 'Valid',
  List<Map<String, Object?>> success = const [],
  List<Map<String, Object?>> informational = const [],
  List<Map<String, Object?>> failure = const [],
  List<Map<String, Object?>> ingredientDeltas = const [],
  Map<String, Object?>? activeManifest,
}) => {
  'active_manifest': 'urn:c2pa:active',
  'manifests': {
    'urn:c2pa:active': {
      'title': 'asset.jpg',
      'format': 'image/jpeg',
      'assertions': [
        {'label': 'c2pa.actions.v2'},
      ],
      'signature_info': {'alg': 'Ps256', 'cert_serial_number': '42'},
      ...?activeManifest,
    },
  },
  'validation_state': state,
  'validation_results': {
    'activeManifest': {
      'success': success,
      'informational': informational,
      'failure': failure,
    },
    'ingredientDeltas': ingredientDeltas,
  },
};

Map<String, Object?> _status(String code, [String? url]) => {
  'code': code,
  'url': ?url,
  'explanation': 'wording that is not a conformance property',
};

List<String> _kinds(OracleReportComparison comparison) =>
    comparison.differences.map((difference) => difference.kind).toList();

void main() {
  group('compareOracleReports', () {
    test('identical reports agree', () {
      final report = _report(
        success: [
          _status(
            'claimSignature.validated',
            'self#jumbf=/c2pa/x/c2pa.signature',
          ),
        ],
      );
      final comparison = compareOracleReports(
        oracleReport: report,
        dartReport: report,
      );

      expect(comparison.agrees, isTrue);
      expect(comparison.bothRejected, isFalse);
    });

    test('mutual rejection is agreement, not a difference', () {
      // The wording of two rejections is not a conformance property, so an
      // asset both implementations refuse is a match.
      final comparison = compareOracleReports(
        oracleReport: null,
        dartReport: null,
      );

      expect(comparison.agrees, isTrue);
      expect(comparison.bothRejected, isTrue);
    });

    test('one-sided rejection is reported with its direction', () {
      expect(
        _kinds(compareOracleReports(oracleReport: null, dartReport: _report())),
        ['oracle-rejects-dart-accepts'],
      );
      expect(
        _kinds(compareOracleReports(oracleReport: _report(), dartReport: null)),
        ['dart-rejects-oracle-accepts'],
      );
    });

    test('separates a different verdict from a differently spelled one', () {
      expect(
        _kinds(
          compareOracleReports(
            oracleReport: _report(state: 'Valid'),
            dartReport: _report(state: 'Invalid'),
          ),
        ),
        contains('validation_state'),
      );
      expect(
        _kinds(
          compareOracleReports(
            oracleReport: _report(state: 'Valid'),
            dartReport: _report(state: 'valid'),
          ),
        ),
        contains('validation_state-case'),
      );
    });

    test('reports structural manifest fields', () {
      final comparison = compareOracleReports(
        oracleReport: _report(),
        dartReport: _report(
          activeManifest: {
            'signature_info': {'alg': 'Es256', 'cert_serial_number': '42'},
          },
        ),
      );

      expect(_kinds(comparison), contains('manifest.signature_alg'));
    });

    test('orients extra and missing statuses from the SDK point of view', () {
      final comparison = compareOracleReports(
        oracleReport: _report(
          failure: [_status('assertion.dataHash.mismatch')],
        ),
        dartReport: _report(failure: [_status('claimSignature.mismatch')]),
      );

      expect(
        _kinds(comparison),
        containsAll([
          'status.failure.missing-in-dart',
          'status.failure.extra-in-dart',
        ]),
      );
      expect(
        comparison.differences
            .firstWhere((d) => d.kind == 'status.failure.extra-in-dart')
            .items
            .single,
        startsWith('claimSignature.mismatch'),
      );
    });

    test('counts repeated statuses as a multiset', () {
      final match = _status('assertion.hashedURI.match', 'self#jumbf=a');
      final comparison = compareOracleReports(
        oracleReport: _report(success: [match, match, match]),
        dartReport: _report(success: [match, match]),
      );

      expect(_kinds(comparison), ['status.success.missing-in-dart']);
      expect(
        comparison.differences.single.items,
        hasLength(1),
        reason: 'only the surplus copy should be reported',
      );
    });

    test('treats absolute and relative JUMBF URIs as the same status', () {
      // The URI form is tracked as its own finding, so it must not also
      // masquerade as a missing/extra status.
      final comparison = compareOracleReports(
        oracleReport: _report(
          success: [
            _status(
              'assertion.hashedURI.match',
              'self#jumbf=/c2pa/label/c2pa.assertions/x',
            ),
          ],
        ),
        dartReport: _report(
          success: [
            _status(
              'assertion.hashedURI.match',
              'self#jumbf=c2pa.assertions/x',
            ),
          ],
        ),
      );

      expect(_kinds(comparison), ['status-uri-form']);
    });

    test('distinguishes statuses on different assertions', () {
      final comparison = compareOracleReports(
        oracleReport: _report(
          success: [
            _status(
              'assertion.hashedURI.match',
              'self#jumbf=/c2pa/l/c2pa.assertions/a',
            ),
          ],
        ),
        dartReport: _report(
          success: [
            _status(
              'assertion.hashedURI.match',
              'self#jumbf=/c2pa/l/c2pa.assertions/b',
            ),
          ],
        ),
      );

      expect(
        _kinds(comparison),
        containsAll([
          'status.success.missing-in-dart',
          'status.success.extra-in-dart',
        ]),
      );
    });

    group('trust-store configuration', () {
      final oracle = _report(
        success: [
          _status(
            'signingCredential.trusted',
            'self#jumbf=/c2pa/l/c2pa.signature',
          ),
        ],
      );
      final dart = _report(
        failure: [
          _status(
            'signingCredential.untrusted',
            'self#jumbf=/c2pa/l/c2pa.signature',
          ),
        ],
      );

      test('is excluded from scoring by default', () {
        // c2patool ships a trust store and the c2pa-rs SDK does not, so these
        // statuses measure configuration rather than conformance.
        expect(
          compareOracleReports(oracleReport: oracle, dartReport: dart).agrees,
          isTrue,
        );
      });

      test('is scored under --strict-trust', () {
        expect(
          _kinds(
            compareOracleReports(
              oracleReport: oracle,
              dartReport: dart,
              ignoreTrustConfiguration: false,
            ),
          ),
          isNotEmpty,
        );
      });
    });

    group('ingredient deltas', () {
      Map<String, Object?> delta(
        String uri, {
        List<Map<String, Object?>> failure = const [],
      }) => {
        'ingredientAssertionURI': uri,
        'validationDeltas': {
          'success': <Object?>[],
          'informational': <Object?>[],
          'failure': failure,
        },
      };

      test('compares per code rather than whole-map', () {
        final comparison = compareOracleReports(
          oracleReport: _report(
            ingredientDeltas: [
              delta('self#jumbf=/c2pa/a/c2pa.assertions/c2pa.ingredient'),
            ],
          ),
          dartReport: _report(
            ingredientDeltas: [
              delta(
                'self#jumbf=/c2pa/a/c2pa.assertions/c2pa.ingredient',
                failure: [_status('claimSignature.mismatch')],
              ),
            ],
          ),
        );

        expect(_kinds(comparison), ['ingredient.failure.extra-in-dart']);
      });

      test('keeps the manifest label so sibling ingredients stay distinct', () {
        // Nested ingredients in different manifests share the same assertion
        // tail; collapsing the label would let one silently overwrite another.
        final comparison = compareOracleReports(
          oracleReport: _report(
            ingredientDeltas: [
              delta('self#jumbf=/c2pa/a/c2pa.assertions/c2pa.ingredient'),
              delta('self#jumbf=/c2pa/b/c2pa.assertions/c2pa.ingredient'),
            ],
          ),
          dartReport: _report(
            ingredientDeltas: [
              delta('self#jumbf=/c2pa/a/c2pa.assertions/c2pa.ingredient'),
            ],
          ),
        );

        expect(_kinds(comparison), ['ingredient.delta.missing-in-dart']);
      });
    });
  });

  group('normalizeJumbfUri', () {
    test('collapses absolute and relative forms onto one another', () {
      expect(
        normalizeJumbfUri('self#jumbf=/c2pa/urn:c2pa:x/c2pa.assertions/a'),
        'c2pa.assertions/a',
      );
      expect(
        normalizeJumbfUri('self#jumbf=c2pa.assertions/a'),
        'c2pa.assertions/a',
      );
    });

    test('passes through labels that are not JUMBF URIs', () {
      expect(normalizeJumbfUri('Cose_Sign1'), 'Cose_Sign1');
      expect(normalizeJumbfUri(null), '');
    });
  });
}

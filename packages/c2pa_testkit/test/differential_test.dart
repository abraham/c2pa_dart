import 'package:c2pa/c2pa.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('validation projection matches common c2pa-rs JSON', () {
    final dartResult = ValidationResults.fromIssues([
      ValidationIssue.known(code: ValidationCode.claimSignatureValidated),
      ValidationIssue.known(code: ValidationCode.claimSignatureInsideValidity),
      ValidationIssue.known(code: ValidationCode.signingCredentialTrusted),
      ValidationIssue.known(
        code: ValidationCode.timestampUntrusted,
        explanation: 'Timestamp is outside the trust list.',
      ),
      ValidationIssue.known(
        code: ValidationCode.assertionDataHashMatch,
        ingredientUri: 'self#jumbf=/c2pa/ingredient',
      ),
    ]);
    final oracle = {
      'validation': {
        'trusted': true,
        'validation_status': [
          {
            'status': 'assertion.dataHash.match',
            'kind': 'success',
            'ingredient_uri': 'self#jumbf=/c2pa/ingredient',
          },
          {
            'code': 'timeStamp.untrusted',
            'severity': 'informational',
            'explanation': 'Timestamp is outside the trust list.',
          },
          {'code': 'claimSignature.validated', 'severity': 'success'},
          {'code': 'claimSignature.insideValidity', 'severity': 'success'},
          {'code': 'signingCredential.trusted', 'severity': 'success'},
        ],
      },
    };

    final comparison = compareWithOracle(
      dartResult: dartResult,
      oracleJson: oracle,
      projection: const ValidationResultsProjection(),
    );

    expect(comparison.matches, isTrue);
    expect(comparison.dart, comparison.oracle);
    expect(comparison.dartJson, contains('"isTrusted": true'));
  });

  test('errors normalize state to invalid and differences are retained', () {
    final result = ValidationResults.fromIssues([
      ValidationIssue.known(code: ValidationCode.claimSignatureMismatch),
    ]);
    final comparison = compareWithOracle(
      dartResult: result,
      oracleJson: {
        'state': 'valid',
        'issues': [
          {'code': 'different', 'severity': 'failure'},
        ],
      },
      projection: const ValidationResultsProjection(),
    );

    expect(comparison.matches, isFalse);
    expect(comparison.oracleJson, contains('"state": "invalid"'));
  });

  test('callback report projection canonicalizes nested maps', () {
    final projection = CallbackReportProjection<int>(
      dartProjector: (value) => {
        'nested': {'value': value, 'enabled': true},
      },
      oracleProjector: (json) => (json as Map<String, Object?>)['report'],
    );
    final comparison = compareWithOracle(
      dartResult: 7,
      oracleJson: {
        'report': {
          'nested': {'enabled': true, 'value': 7},
        },
      },
      projection: projection,
    );

    expect(comparison.matches, isTrue);
  });

  test('rejects malformed oracle and non-JSON projections', () {
    expect(
      () => const ValidationResultsProjection().projectOracleJson([]),
      throwsFormatException,
    );
    expect(() => normalizeJson(DateTime(2020)), throwsArgumentError);
  });

  test('normalizes URI values emitted by SDK reports', () {
    expect(normalizeJson({'issuer': Uri.parse('https://example.com/id')}), {
      'issuer': 'https://example.com/id',
    });
  });

  test('distinguishes a missing property from an explicit null', () {
    final comparison = compareWithOracle(
      dartResult: const <String, Object?>{'value': null},
      oracleJson: const <String, Object?>{},
      projection: CallbackReportProjection<Map<String, Object?>>(
        dartProjector: (value) => value,
      ),
    );

    expect(comparison.matches, isFalse);
    expect(comparison.differences.single.path, r'$.value');
  });
}

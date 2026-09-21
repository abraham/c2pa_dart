import 'dart:convert';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

import 'support/json_schema_validator.dart';

const _fixtureRoot = 'test/fixtures/vendor/c2pa-rs-0.90.22/media';
const _schemaPath =
    'test/fixtures/vendor/c2pa-rs-0.90.22/crjson/crJSON-schema.json';

void main() {
  group('upstream SDK report conformance', () {
    for (final fixture in const [
      (
        name: 'CA.jpg',
        asset: 'claim-v2/CA.jpg',
        expected: 'claim-v2/CA.expected.json',
        dataHashCode: 'assertion.dataHash.match',
        state: 'valid',
      ),
      (
        name: 'XCA.jpg',
        asset: 'invalid/XCA.jpg',
        expected: 'invalid/XCA.expected.json',
        dataHashCode: 'assertion.dataHash.mismatch',
        state: 'invalid',
      ),
    ]) {
      test(
        '${fixture.name} reproduces the upstream SDK report exactly',
        () async {
          final reader = await _read(fixture.asset);
          final oracle = await loadGoldenJsonObject(
            '$_fixtureRoot/${fixture.expected}',
          );
          final comparison = compareWithOracle(
            dartResult: reader.toSdkJson(),
            oracleJson: oracle,
            projection: ConformanceReportProjection<Map<String, Object?>>(
              dartProjector: (report) => report,
            ),
          );
          final dart = comparison.dart! as Map<String, Object?>;
          final expected = comparison.oracle! as Map<String, Object?>;

          for (final field in const [
            'activeManifest',
            'manifestLabels',
            'assertionLabels',
            'assertionHashes',
            'state',
            'signatureAlgorithm',
          ]) {
            expect(
              dart[field],
              expected[field],
              reason: '${fixture.name}: $field',
            );
          }
          expect(dart['state'], fixture.state);
          expect(
            dart['validationCodes'] as List<Object?>,
            contains(fixture.dataHashCode),
          );
          expect(
            expected['validationCodes'] as List<Object?>,
            contains(fixture.dataHashCode),
          );

          // The golden files are byte-exact copies of the c2pa-rs v0.90.22
          // `sdk/tests/known_good` fixtures. This SDK now reproduces them
          // exactly — same codes, same buckets, same URLs, same ingredient
          // deltas — so the comparison is asserted whole rather than
          // field-by-field. Any future divergence fails here with a diff.
          expect(
            comparison.matches,
            isTrue,
            reason:
                '${fixture.name} diverges from the upstream golden at: '
                '${comparison.differences.map((d) => d.path).join(', ')}',
          );

          // Spot-checks for the conditions that used to diverge, kept so a
          // regression names the cause instead of only the path.
          expect(
            dart['validationCodes'] as List<Object?>,
            containsAll(['timeStamp.validated', 'timeStamp.untrusted']),
          );
          expect(
            dart['validationCodes'] as List<Object?>,
            isNot(contains('timeStamp.malformed')),
          );
          // The goldens were produced with trust verification off, where
          // c2pa-rs selects `Verifier::VerifyCertificateProfileOnly` and logs
          // no trust status at all.
          expect(
            dart['validationCodes'] as List<Object?>,
            isNot(
              anyOf(
                contains('signingCredential.untrusted'),
                contains('signingCredential.trusted'),
              ),
            ),
          );
          expect(
            jsonEncode(dart['ingredientDeltas']),
            contains('ingredient.unknownProvenance'),
          );
        },
      );
    }
  });

  group('crJSON 2.3.0 structural conformance', () {
    late Map<String, Object?> schema;

    setUpAll(() async {
      schema = await loadGoldenJsonObject(_schemaPath);
    });

    for (final asset in const ['claim-v2/CA.jpg', 'invalid/XCA.jpg']) {
      test('$asset satisfies the complete vendored schema', () async {
        final report = (await _read(asset)).toCrJson(
          options: const C2paJsonOptions(binaryOutput: C2paBinaryOutput.base64),
        );
        final schemaValidation = JsonSchemaValidator(schema).validate(report);
        expect(
          schemaValidation.errors,
          isEmpty,
          reason: schemaValidation.errors.join('\n'),
        );
        final definitions = schema['definitions']! as Map<String, Object?>;
        final manifestSchema = definitions['manifest']! as Map<String, Object?>;

        expect(
          report.keys,
          containsAll((schema['required']! as List<Object?>).cast<String>()),
        );
        expect(report['@context'], isA<Map<String, Object?>>());
        expect(
          (report['@context']! as Map<String, Object?>)['@vocab'],
          'https://c2pa.org/crjson',
        );

        final generator = report['jsonGenerator']! as Map<String, Object?>;
        expect(generator['name'], 'c2pa-dart');
        expect(
          generator['version'],
          matches(RegExp(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$')),
        );

        final manifests = report['manifests']! as List<Object?>;
        expect(manifests, hasLength(1));
        final manifest = manifests.single as Map<String, Object?>;
        expect(
          manifest.keys,
          containsAll(
            (manifestSchema['required']! as List<Object?>).cast<String>(),
          ),
        );
        expect(
          [
            manifest.containsKey('claim'),
            manifest.containsKey('claim.v2'),
          ].where((present) => present),
          hasLength(1),
        );
        expect(manifest, contains('claim'));

        final validation =
            manifest['validationResults']! as Map<String, Object?>;
        expect(validation['specVersion'], '2.3.0');
        expect(
          validation.keys,
          containsAll([
            'success',
            'informational',
            'failure',
            'validationTime',
          ]),
        );
        for (final section in const ['success', 'informational', 'failure']) {
          expect(validation[section], isA<List<Object?>>());
        }
        expect(
          DateTime.parse(validation['validationTime']! as String).isUtc,
          isTrue,
        );

        final hashes = <String>[];
        _collectHashes(report, hashes);
        expect(hashes, isNotEmpty);
        for (final hash in hashes) {
          final match = RegExp(r"^b64'([A-Za-z0-9+/]*={0,2})'$")
              .firstMatch(hash);
          expect(match, isNotNull, reason: hash);
          expect(
            () => base64.decode(match!.group(1)!),
            returnsNormally,
            reason: hash,
          );
        }
      });
    }
  });
}

Future<C2paReader> _read(String relativePath) async => C2paReader.fromSource(
  source: MemoryByteSource(
    await loadFixtureBytes('$_fixtureRoot/$relativePath'),
  ),
  fileName: relativePath,
);

void _collectHashes(Object? value, List<String> hashes) {
  if (value is Map<Object?, Object?>) {
    for (final entry in value.entries) {
      if (entry.key == 'hash') {
        expect(entry.value, isA<String>());
        hashes.add(entry.value! as String);
      }
      _collectHashes(entry.value, hashes);
    }
  } else if (value is Iterable<Object?>) {
    for (final item in value) {
      _collectHashes(item, hashes);
    }
  }
}

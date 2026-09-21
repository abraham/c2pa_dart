@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _indexPath = 'test/fixtures/vendor/conformance_index.json';
const _provenancePath = 'test/fixtures/vendor/provenance.json';
const _message = 'some sample content to sign';
const _evaluationTime = '2025-04-24T00:00:00Z';

void main() {
  late ConformanceFixtureIndex index;
  late Map<String, Object?> provenance;
  late Uint8List connectedDid;
  late C2paTrustConfiguration x509Trust;

  setUpAll(() async {
    index = await loadConformanceFixtureIndex(_indexPath);
    provenance = await loadGoldenJsonObject(_provenancePath);
    connectedDid = await loadFixtureBytes(
      'test/fixtures/vendor/c2pa-rs-0.90.22/identity/'
      'claim_aggregation/connected_identities_did.json',
    );
    final chain = _certificates(
      await loadFixtureString(
        'test/fixtures/vendor/c2pa-rs-0.90.22/'
        'crypto/raw-signature/ed25519.pub',
      ),
    );
    x509Trust = C2paTrustConfiguration(
      verifyTrust: true,
      trustAnchors: [chain.last.der],
      intermediates: [chain[1].der],
      evaluationTime: DateTime.parse(_evaluationTime),
    );
  });

  test(
    'every vendored file has verified provenance and classification',
    () async {
      final referenced = <String>{
        for (final fixture in index.fixtures) fixture.asset,
        for (final fixture in index.fixtures)
          ..._relatedAssets(fixture.metadata),
      };
      final files = (provenance['files']! as List<Object?>)
          .cast<Map<Object?, Object?>>();
      var fixtureCount = 0;
      for (final record in files) {
        final path = record['localPath']! as String;
        final bytes = await loadFixtureBytes('test/fixtures/vendor/$path');
        expect(bytes.length, record['size'], reason: path);
        expect(
          _hex(await HashAlgorithm.sha256.digest(bytes)),
          record['sha256'],
          reason: path,
        );
        if (_isDocumentation(path)) continue;
        fixtureCount++;
        expect(
          referenced,
          contains(path),
          reason: 'unclassified fixture: $path',
        );
      }
      expect(fixtureCount, 80);
      expect(index.fixtures, hasLength(58));
    },
  );

  test('every index entry declares an executable outcome or explicit skip', () {
    for (final fixture in index.fixtures) {
      final classified =
          fixture.metadata['expected'] != null ||
          fixture.metadata['c2paRsExpectedStatuses'] is List<Object?>;
      expect(classified, isTrue, reason: fixture.id);
      if (fixture.isSkipped) {
        expect(fixture.skipReason, isNotEmpty, reason: fixture.id);
        expect(
          fixture.metadata['issueCategory'],
          isNotEmpty,
          reason: fixture.id,
        );
      }
    }
    expect(index.fixtures.where((fixture) => fixture.isSkipped), hasLength(3));
  });

  test(
    'executes every indexed fixture according to its classification',
    () async {
      final exercised = <String>{};
      for (final fixture in index.fixtures) {
        final bytes = await loadConformanceFixtureAsset(_indexPath, fixture);
        if (fixture.isSkipped) {
          exercised.add(fixture.id);
          continue;
        }
        final suite = fixture.metadata['suite'];
        if (suite == 'raw-signature') {
          await _verifySignatureVector(fixture);
        } else if (suite == 'trust-list') {
          expect(
            _certificates(utf8.decode(bytes)),
            isNotEmpty,
            reason: fixture.id,
          );
        } else if (suite == 'crjson-envelope') {
          await _verifyEnvelopeCases(fixture);
        } else if (suite == 'cawg-did-document') {
          final document = json.decode(utf8.decode(bytes));
          expect(document, isA<Map<String, Object?>>(), reason: fixture.id);
        } else if (suite == 'cawg-x509-validation') {
          final result = _singleIdentity(
            await _reader(
              fixture,
              context: C2paContext(
                cawgTrust: x509Trust,
                cawgValidationPolicy: CawgValidationPolicy.continueWhenPossible,
                cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
              ),
            ),
          );
          expect(
            _codes(result),
            fixture.metadata['c2paRsExpectedStatuses'],
            reason: fixture.id,
          );
        } else if (suite == 'cawg-ica-validation' ||
            suite == 'cawg-ica-interop') {
          final resolver = _resolverFor(fixture, connectedDid);
          final result = _singleIdentity(
            await _reader(fixture, context: _icaContext(resolver)),
          );
          final expected =
              fixture.metadata['c2paRsExpectedStatuses']! as List<Object?>;
          if (fixture.id == 'rust-cawg-ica-did-doc-without-assertion-method') {
            expect(_codes(result), hasLength(1));
            expect(
              _codes(result).single,
              anyOf(
                CawgStatusCodes.icaInvalidDidDocument,
                CawgStatusCodes.icaDidResolutionFailed,
              ),
            );
          } else {
            expect(_codes(result), expected, reason: fixture.id);
          }
        } else {
          await _verifyGeneralFixture(fixture, bytes);
        }
        exercised.add(fixture.id);
      }
      expect(exercised, hasLength(index.fixtures.length));
    },
  );
}

Future<void> _verifyGeneralFixture(
  ConformanceFixture fixture,
  Uint8List bytes,
) async {
  switch (fixture.metadata['expected']) {
    case 'parse-success-claim-v1-one-parent-ingredient':
      final reader = await _reader(fixture);
      expect(reader.activeManifest, isNotNull);
      expect(reader.activeManifest!.ingredients, hasLength(1));
    case 'parse-claim-v1-valid-signature-untrusted-default':
      final reader = await _reader(fixture);
      expect(reader.activeManifest, isNotNull);
      expect(
        reader.validationResults.activeManifest?.success.map(
          (status) => status.code,
        ),
        contains('claimSignature.validated'),
      );
    case 'assertion.dataHash.mismatch':
      final reader = await _reader(fixture);
      expect(reader.validationResults.state, ValidationState.invalid);
      expect(
        reader.validationResults.errors.map((status) => status.code),
        contains('assertion.dataHash.mismatch'),
      );
    case 'timestamp.malformed-informational':
      final reader = await _reader(fixture);
      expect(
        reader.validationResults.activeManifest?.informational.map(
          (status) => status.code,
        ),
        contains('timeStamp.malformed'),
      );
    case 'extract-nonempty-manifest':
      final reader = await _reader(fixture);
      expect(reader.manifestBytes, isNotEmpty);
      expect(reader.activeManifest, isNotNull);
    case 'controlled-parse-error':
      await expectLater(_reader(fixture), throwsA(isA<C2paException>()));
    case 'no-crash-manifest-not-found':
      await expectLater(_reader(fixture), throwsA(isA<C2paException>()));
    case 'signingCredential.ocsp.notRevoked':
      expect(
        OcspResponse.parse(bytes).responses.single.status,
        OcspCertStatus.good,
      );
    case 'signingCredential.revoked':
      expect(
        OcspResponse.parse(bytes).responses.single.status,
        OcspCertStatus.revoked,
      );
    case 'signingCredential.ocsp.unknown':
      expect(
        OcspResponse.parse(bytes).responses.single.status,
        OcspCertStatus.unknown,
      );
    default:
      fail(
        'Unimplemented fixture outcome for ${fixture.id}: '
        '${fixture.metadata['expected']}',
      );
  }
}

Future<void> _verifySignatureVector(ConformanceFixture fixture) async {
  final algorithm = SigningAlgorithm.values.singleWhere(
    (candidate) => candidate.name == fixture.metadata['algorithm'],
  );
  final related = _relatedAssets(fixture.metadata);
  final certificatePath = related.singleWhere((path) => path.endsWith('.pub'));
  final keyPath = related.singleWhere((path) => path.endsWith('.pub_key'));
  final certificate = _certificates(
    await loadFixtureString('test/fixtures/vendor/$certificatePath'),
  ).first;
  final key = await loadFixtureBytes('test/fixtures/vendor/$keyPath');
  final signature = await loadConformanceFixtureAsset(_indexPath, fixture);
  expect(certificate.subjectPublicKeyInfoDer, key, reason: fixture.id);
  final message = utf8.encode(_message);
  final valid = switch (algorithm) {
    SigningAlgorithm.ps256 ||
    SigningAlgorithm.ps384 ||
    SigningAlgorithm.ps512 => WebCryptoRsaPssVerificationBackend(
      algorithm,
      await importRsaPssPublicKeySpki(algorithm, key),
    ).verify(algorithm, message, signature),
    SigningAlgorithm.es256 ||
    SigningAlgorithm.es384 ||
    SigningAlgorithm.es512 => WebCryptoEcdsaVerificationBackend(
      algorithm,
      await importEcdsaPublicKeySpki(algorithm, key),
    ).verify(algorithm, message, signature),
    SigningAlgorithm.ed25519 => verifySignatureWithCertificatePublicKey(
      certificate: certificate,
      signatureAlgorithm: X509AlgorithmIdentifier('1.3.101.112', null),
      data: message,
      signature: signature,
    ),
  };
  expect(await valid, isTrue, reason: fixture.id);
}

Future<void> _verifyEnvelopeCases(ConformanceFixture fixture) async {
  final schema = json.decode(
    utf8.decode(await loadConformanceFixtureAsset(_indexPath, fixture)),
  );
  expect(schema, isA<Map<String, Object?>>());
  for (final path in _relatedAssets(fixture.metadata)) {
    final value = json.decode(
      await loadFixtureString('test/fixtures/vendor/$path'),
    );
    final errors = _validateEnvelope(value);
    expect(
      errors,
      path.endsWith('valid_minimal.json') ? isEmpty : isNotEmpty,
      reason: path,
    );
  }
}

List<String> _validateEnvelope(Object? value) {
  if (value is! Map<Object?, Object?>) return const ['must be an object'];
  final errors = <String>[];
  if (value['schema'] != 'crjson') errors.add('schema');
  if (value['schema_version'] is! String) errors.add('schema_version');
  if (value['results'] is! List<Object?>) errors.add('results');
  return errors;
}

Future<C2paReader> _reader(
  ConformanceFixture fixture, {
  C2paContext? context,
}) async {
  final reader = await C2paReader.fromSource(
    source: MemoryByteSource(
      await loadConformanceFixtureAsset(_indexPath, fixture),
    ),
    fileName: fixture.asset,
    context: context,
  );
  final normalized = const ConformanceReportProjection<C2paReader>(
    dartProjector: _sdkReport,
  ).projectDart(reader) as Map<String, Object?>;
  expect(
    normalized['manifestLabels'],
    isA<List<Object?>>(),
    reason: fixture.id,
  );
  expect(
    normalized['assertionLabels'],
    isA<List<Object?>>(),
    reason: fixture.id,
  );
  expect(
    normalized['validationCodes'],
    isA<List<Object?>>(),
    reason: fixture.id,
  );
  expect(
    normalized['validationUrls'],
    isA<List<Object?>>(),
    reason: fixture.id,
  );
  expect(normalized['state'], isA<String>(), reason: fixture.id);
  return reader;
}

Map<String, Object?> _sdkReport(C2paReader reader) => reader.toSdkJson();

C2paContext _icaContext(C2paRemoteResolver? resolver) => C2paContext(
  cawgTrust: C2paTrustConfiguration(
    evaluationTime: DateTime.parse(_evaluationTime),
  ),
  cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
  didWebResolver: resolver,
  didWebPolicy: RemoteManifestPolicy(
    enabled: resolver != null,
    allowedHosts: const {'connected-identities.identity-stage.adobe.com'},
    maxBytes: 64 * 1024,
  ),
);

C2paRemoteResolver? _resolverFor(
  ConformanceFixture fixture,
  Uint8List connectedDid,
) {
  if (fixture.id == 'rust-cawg-ica-did-doc-without-assertion-method') {
    return _BytesResolver(Uint8List.fromList(utf8.encode('{}')));
  }
  if (fixture.metadata['suite'] == 'cawg-ica-interop') {
    return _BytesResolver(connectedDid);
  }
  return null;
}

CawgIdentityValidationResult _singleIdentity(C2paReader reader) =>
    reader.activeManifest!.identityAssertions.single;

List<String> _codes(CawgIdentityValidationResult result) =>
    result.statuses.map((status) => status.code).toList(growable: false);

List<String> _relatedAssets(Map<String, Object?> metadata) =>
    switch (metadata['relatedAssets']) {
      final List<Object?> values => values.cast<String>(),
      _ => const [],
    };

bool _isDocumentation(String path) =>
    path.endsWith('.md') ||
    path.endsWith('/LICENSE') ||
    path.endsWith('/LICENSE-MIT') ||
    path.endsWith('/LICENSE-APACHE');

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

List<X509Certificate> _certificates(String pem) =>
    RegExp(
          r'-----BEGIN CERTIFICATE-----\s*'
          r'([A-Za-z0-9+/=\s]+?)'
          r'\s*-----END CERTIFICATE-----',
          multiLine: true,
        )
        .allMatches(pem)
        .map((match) {
          return X509Certificate.parse(
            base64Decode(match.group(1)!.replaceAll(RegExp(r'\s'), '')),
          );
        })
        .toList(growable: false);

final class _BytesResolver implements C2paRemoteResolver {
  _BytesResolver(this.bytes);

  final Uint8List bytes;

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async =>
      C2paRemoteResponse.bytes(
        bytes: bytes,
        resolvedAddresses: const ['93.184.216.34'],
      );
}

@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

// ignore: implementation_imports
import 'package:c2pa/src/cawg_identity.dart';
// ignore: implementation_imports
import 'package:c2pa/src/context.dart';
// ignore: implementation_imports
import 'package:c2pa/src/reader.dart';
// ignore: implementation_imports
import 'package:c2pa/src/remote_manifest.dart';
// ignore: implementation_imports
import 'package:c2pa/src/report.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _indexPath = 'test/fixtures/vendor/conformance_index.json';
const _identityRoot = 'test/fixtures/vendor/c2pa-rs-0.90.22/identity';
const _evaluationTime = '2025-04-24T00:00:00Z';

void main() {
  late ConformanceFixtureIndex index;
  late C2paTrustConfiguration trustedX509;
  late Uint8List connectedDid;

  setUpAll(() async {
    index = await loadConformanceFixtureIndex(_indexPath);
    final chain = _parsePemCertificates(
      await loadFixtureString(
        'test/fixtures/vendor/c2pa-rs-0.90.22/'
        'crypto/raw-signature/ed25519.pub',
      ),
    );
    trustedX509 = C2paTrustConfiguration(
      verifyTrust: true,
      trustAnchors: [chain.last.der],
      intermediates: [chain[1].der],
      evaluationTime: DateTime.parse(_evaluationTime),
    );
    connectedDid = await loadFixtureBytes(
      '$_identityRoot/claim_aggregation/connected_identities_did.json',
    );
  });

  group('upstream X.509 identity fixtures', () {
    const expected = {
      'rust-cawg-x509-duplicate-assertion-reference': [
        CawgStatusCodes.assertionDuplicate,
        'signingCredential.trusted',
      ],
      'rust-cawg-x509-extra-assertion-claim-v1': [
        CawgStatusCodes.assertionMismatch,
        'signingCredential.trusted',
      ],
      'rust-cawg-x509-invalid-sig-type': [CawgStatusCodes.signatureTypeUnknown],
      'rust-cawg-x509-malformed-cbor': [CawgStatusCodes.cborInvalid],
      'rust-cawg-x509-no-hard-binding': [
        CawgStatusCodes.hardBindingMissing,
        'signingCredential.trusted',
      ],
      'rust-cawg-x509-pad1-invalid': [
        CawgStatusCodes.padInvalid,
        'signingCredential.trusted',
      ],
      'rust-cawg-x509-pad2-invalid': [
        CawgStatusCodes.padInvalid,
        'signingCredential.trusted',
      ],
    };

    for (final entry in expected.entries) {
      test('${entry.key} emits exact ordered statuses', () async {
        final result = _singleIdentity(
          await _read(
            _fixture(index, entry.key),
            context: C2paContext(
              cawgTrust: trustedX509,
              cawgValidationPolicy: CawgValidationPolicy.continueWhenPossible,
              cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
            ),
          ),
        );
        expect(_codes(result), entry.value, reason: entry.key);
      });
    }

    const stoppingExpected = {
      'rust-cawg-x509-duplicate-assertion-reference':
          CawgStatusCodes.assertionDuplicate,
      'rust-cawg-x509-extra-assertion-claim-v1':
          CawgStatusCodes.assertionMismatch,
      'rust-cawg-x509-invalid-sig-type': CawgStatusCodes.signatureTypeUnknown,
      'rust-cawg-x509-malformed-cbor': CawgStatusCodes.cborInvalid,
      'rust-cawg-x509-no-hard-binding': CawgStatusCodes.hardBindingMissing,
      'rust-cawg-x509-pad1-invalid': CawgStatusCodes.padInvalid,
      'rust-cawg-x509-pad2-invalid': CawgStatusCodes.padInvalid,
    };
    for (final entry in stoppingExpected.entries) {
      test('${entry.key} honors stop-on-first-error ordering', () async {
        final result = _singleIdentity(
          await _read(
            _fixture(index, entry.key),
            context: C2paContext(
              cawgTrust: trustedX509,
              cawgValidationPolicy: CawgValidationPolicy.stopOnFirstFailure,
              cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
            ),
          ),
        );
        expect(_codes(result), [entry.value]);
      });
    }

    test('extra field emits the upstream empty tracker sequence', () async {
      final fixture = _fixture(index, 'rust-cawg-x509-extra-field');
      expect(fixture.metadata['c2paRsExpectedStatuses'], <String>[]);
      for (final policy in CawgValidationPolicy.values) {
        final result = _singleIdentity(
          await _read(
            fixture,
            context: C2paContext(
              cawgTrust: trustedX509,
              cawgValidationPolicy: policy,
              cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
            ),
          ),
        );
        expect(_codes(result), <String>[]);
      }
    });

    test('separates well-formed identity from X.509 trust', () async {
      final fixture = _fixture(index, 'rust-cawg-x509-extra-field');
      final untrusted = _singleIdentity(await _read(fixture));
      final trusted = _singleIdentity(
        await _read(fixture, context: C2paContext(cawgTrust: trustedX509)),
      );

      expect(_codes(untrusted), [
        CawgStatusCodes.certificateUntrusted,
        CawgStatusCodes.wellFormed,
      ]);
      expect(untrusted.isWellFormed, isTrue);
      expect(untrusted.isTrusted, isFalse);
      expect(_codes(trusted), [
        CawgStatusCodes.trusted,
        CawgStatusCodes.wellFormed,
      ]);
      expect(trusted.isTrusted, isTrue);
    });
  });

  group('upstream ICA validation fixtures', () {
    const expected = {
      'rust-cawg-ica-invalid-content-type': [
        CawgStatusCodes.icaInvalidContentType,
      ],
      'rust-cawg-ica-invalid-content-type-assigned': [
        CawgStatusCodes.icaInvalidContentType,
      ],
      'rust-cawg-ica-invalid-cose-sign1': [CawgStatusCodes.icaInvalidCose],
      'rust-cawg-ica-invalid-cose-sign-alg': [
        CawgStatusCodes.icaInvalidAlgorithm,
      ],
      'rust-cawg-ica-invalid-issuer-did': [
        CawgStatusCodes.icaIssuerUnsupported,
      ],
      'rust-cawg-ica-invalid-vc': [CawgStatusCodes.icaInvalidCredential],
      'rust-cawg-ica-missing-content-type': [
        CawgStatusCodes.icaInvalidContentType,
      ],
      'rust-cawg-ica-missing-cose-sign-alg': [
        CawgStatusCodes.icaInvalidAlgorithm,
      ],
      'rust-cawg-ica-missing-vc': [CawgStatusCodes.icaInvalidCredential],
      'rust-cawg-ica-signature-mismatch': [
        CawgStatusCodes.icaSignatureMismatch,
      ],
      'rust-cawg-ica-signer-payload-mismatch': [
        CawgStatusCodes.icaAssetMismatch,
      ],
      'rust-cawg-ica-success': [CawgStatusCodes.icaCredentialValid],
      'rust-cawg-ica-unsupported-did-method': [
        CawgStatusCodes.icaIssuerUnsupported,
      ],
      'rust-cawg-ica-valid-from-in-future': [
        CawgStatusCodes.icaValidFromInvalid,
      ],
      'rust-cawg-ica-valid-from-missing': [CawgStatusCodes.icaValidFromMissing],
      'rust-cawg-ica-valid-until-in-future': [
        CawgStatusCodes.icaCredentialValid,
      ],
      'rust-cawg-ica-valid-until-in-past': [
        CawgStatusCodes.icaValidUntilInvalid,
      ],
    };

    for (final entry in expected.entries) {
      test('${entry.key} emits exact ordered statuses', () async {
        final result = _singleIdentity(
          await _read(_fixture(index, entry.key), context: _icaContext()),
        );
        expect(_codes(result), entry.value, reason: entry.key);
      });
    }

    test(
      'success and mismatch distinguish the ICA c2paAsset binding',
      () async {
        final success = _singleIdentity(
          await _read(
            _fixture(index, 'rust-cawg-ica-success'),
            context: _icaContext(),
          ),
        );
        final mismatch = _singleIdentity(
          await _read(
            _fixture(index, 'rust-cawg-ica-signer-payload-mismatch'),
            context: _icaContext(),
          ),
        );

        expect(
          success.statuses.map((status) => status.code),
          contains(CawgStatusCodes.icaCredentialValid),
        );
        expect(
          mismatch.statuses.map((status) => status.code),
          contains(CawgStatusCodes.icaAssetMismatch),
        );
        expect(
          success.signerPayload!.referencedAssertions.single.url,
          'self#jumbf=c2pa.assertions/c2pa.hash.data',
        );
      },
    );

    test(
      'stable and c2pa-rs modes expose profile-specific success statuses',
      () async {
        final reader = await _read(
          _fixture(index, 'rust-cawg-ica-success'),
          context: _icaContext(),
        );
        final assertion = _decodeIdentityAssertion(reader);
        final stable = await const CawgIcaVerifier().verify(
          assertion,
          _icaContext(compatibility: CawgIcaCompatibility.stable11),
        );
        final compatible = await const CawgIcaVerifier(
          compatibility: CawgIcaCompatibility.c2paRs09022,
        ).verify(assertion, _icaContext());

        expect(_verificationCodes(stable), [
          CawgStatusCodes.icaCredentialValid,
          CawgStatusCodes.trusted,
        ]);
        expect(_verificationCodes(compatible), [
          CawgStatusCodes.icaCredentialValid,
        ]);
      },
    );
  });

  group('connected identity interoperability', () {
    test(
      'c2pa-rs Reader uses only the injected resolver and tracker statuses',
      () async {
        final resolver = _FixtureDidResolver(connectedDid);
        final result = _singleIdentity(
          await _read(
            _fixture(index, 'rust-cawg-adobe-connected-identities'),
            context: _icaContext(resolver: resolver),
          ),
        );

        expect(resolver.requests, [
          Uri.parse(
            'https://connected-identities.identity-stage.adobe.com/'
            '.well-known/did.json',
          ),
        ]);
        expect(_codes(result), [CawgStatusCodes.icaCredentialValid]);
        final credential = result.credentialSummary!;
        expect(
          credential['issuer'],
          'did:web:connected-identities.identity-stage.adobe.com',
        );
        final identities = credential['verifiedIdentities']! as List<Object?>;
        expect(identities, hasLength(1));
        expect(identities.single, {
          'type': 'cawg.social_media',
          'username': 'testuser23',
          'uri': 'https://net.s2stagehance.com/testuser23',
          'verifiedAt': '2025-04-09T22:45:26.000Z',
          'provider': {'id': 'https://behance.net', 'name': 'behance'},
        });
      },
    );

    test('stable Reader rejects the connected omitted alg', () async {
      final resolver = _FixtureDidResolver(
        connectedDid,
        resolvedAddresses: const ['93.184.216.34'],
      );
      final result = _singleIdentity(
        await _read(
          _fixture(index, 'rust-cawg-adobe-connected-identities'),
          context: _icaContext(
            resolver: resolver,
            compatibility: CawgIcaCompatibility.stable11,
          ),
        ),
      );

      expect(_codes(result), [CawgStatusCodes.icaAssetMismatch]);
      expect(resolver.requests, hasLength(1));
      expect(result.credentialSummary, isNotNull);
    });

    test(
      'projects identities for every manifest without network access',
      () async {
        final resolver = _FixtureDidResolver(connectedDid);
        final reader = await _read(
          _fixture(index, 'rust-cawg-ims-multiple-manifests'),
          context: _icaContext(resolver: resolver),
        );
        final projected = const ConformanceReportProjection<C2paReader>(
          dartProjector: _sdkReport,
          ignore: ConformanceIgnore({
            ConformanceField.validationCategories,
            ConformanceField.validationCodes,
            ConformanceField.validationUrls,
            ConformanceField.ingredientDeltas,
          }),
        ).projectDart(reader) as Map<String, Object?>;

        expect(reader.manifests, hasLength(2));
        expect(
          (projected['identityAssertions']! as List<Object?>).single,
          containsPair(
            'signatureType',
            CawgIdentityLabels.identityClaimsAggregation,
          ),
        );
        expect(resolver.requests, hasLength(1));
      },
    );
  });

  group('c2pa-rs compatibility edge cases', () {
    test('timestamp vectors emit exact upstream status sequences', () async {
      const expected = {
        'rust-cawg-ica-valid-time-stamp': [
          CawgStatusCodes.icaTimestampValidated,
          CawgStatusCodes.icaCredentialValid,
        ],
        'rust-cawg-ica-invalid-time-stamp': [
          CawgStatusCodes.icaTimestampInvalid,
        ],
        'rust-cawg-ica-valid-from-after-time-stamp': [
          CawgStatusCodes.icaTimestampValidated,
          CawgStatusCodes.icaValidFromInvalid,
        ],
      };
      for (final entry in expected.entries) {
        final fixture = _fixture(index, entry.key);
        final result = _singleIdentity(
          await _read(fixture, context: _icaContext()),
        );
        expect(
          fixture.metadata['c2paRsExpectedStatuses'],
          entry.value,
          reason: entry.key,
        );
        expect(_codes(result), entry.value, reason: entry.key);
      }
    });

    test('DID failure fixtures retain exact upstream expectations', () async {
      expect(
        _fixture(
          index,
          'rust-cawg-ica-did-doc-without-assertion-method',
        ).metadata['c2paRsExpectedStatuses'],
        [CawgStatusCodes.icaInvalidDidDocument],
      );
      expect(
        _fixture(
          index,
          'rust-cawg-ica-unresolvable-did',
        ).metadata['c2paRsExpectedStatuses'],
        [CawgStatusCodes.icaDidResolutionFailed],
      );
      final unavailable = _singleIdentity(
        await _read(
          _fixture(index, 'rust-cawg-ica-unresolvable-did'),
          context: _icaContext(),
        ),
      );
      expect(_codes(unavailable), [CawgStatusCodes.icaDidResolutionFailed]);

      final malformed = _singleIdentity(
        await _read(
          _fixture(index, 'rust-cawg-ica-did-doc-without-assertion-method'),
          context: _icaContext(
            resolver: _FixtureDidResolver(
              Uint8List.fromList(utf8.encode('{}')),
            ),
          ),
        ),
      );
      expect(_codes(malformed), hasLength(1));
      expect(
        _codes(malformed).single,
        anyOf(
          CawgStatusCodes.icaInvalidDidDocument,
          CawgStatusCodes.icaDidResolutionFailed,
        ),
      );
    });
  });
}

Map<String, Object?> _sdkReport(C2paReader reader) => reader.toSdkJson();

C2paContext _icaContext({
  C2paRemoteResolver? resolver,
  CawgIcaCompatibility compatibility = CawgIcaCompatibility.c2paRs09022,
}) => C2paContext(
  cawgTrust: C2paTrustConfiguration(
    evaluationTime: DateTime.parse(_evaluationTime),
  ),
  didWebResolver: resolver,
  didWebPolicy: RemoteManifestPolicy(
    enabled: resolver != null,
    allowedHosts: const {'connected-identities.identity-stage.adobe.com'},
    maxBytes: 64 * 1024,
  ),
  cawgIcaCompatibility: compatibility,
);

Future<C2paReader> _read(
  ConformanceFixture fixture, {
  C2paContext? context,
}) async => C2paReader.fromSource(
  source: MemoryByteSource(
    await loadConformanceFixtureAsset(_indexPath, fixture),
  ),
  fileName: fixture.asset,
  context: context,
);

ConformanceFixture _fixture(ConformanceFixtureIndex index, String id) =>
    index.fixtures.singleWhere((fixture) => fixture.id == id);

CawgIdentityValidationResult _singleIdentity(C2paReader reader) =>
    reader.activeManifest!.identityAssertions.single;

List<String> _codes(CawgIdentityValidationResult result) =>
    result.statuses.map((status) => status.code).toList(growable: false);

List<String> _verificationCodes(CawgX509Verification result) =>
    result.statuses.map((status) => status.code).toList(growable: false);

CawgIdentityAssertion _decodeIdentityAssertion(C2paReader reader) {
  final raw = reader.activeManifest!.assertions.singleWhere(
    (assertion) => assertion.label == CawgIdentityLabels.identity,
  );
  final box = parseJumbf(raw.bytes);
  final payload = box.children.whereType<JumbfCborNode>().single.payload;
  return CawgIdentityAssertion.decode(payload);
}

List<X509Certificate> _parsePemCertificates(String pem) {
  final matches = RegExp(
    r'-----BEGIN CERTIFICATE-----\s*'
    r'([A-Za-z0-9+/=\s]+?)'
    r'\s*-----END CERTIFICATE-----',
    multiLine: true,
  ).allMatches(pem);
  return matches
      .map(
        (match) => X509Certificate.parse(
          base64Decode(match.group(1)!.replaceAll(RegExp(r'\s'), '')),
        ),
      )
      .toList(growable: false);
}

final class _FixtureDidResolver implements C2paRemoteResolver {
  _FixtureDidResolver(
    this.bytes, {
    this.resolvedAddresses = const ['93.184.216.34'],
  });

  final Uint8List bytes;
  final List<String> resolvedAddresses;
  final List<Uri> requests = [];

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    requests.add(request.uri);
    return C2paRemoteResponse.bytes(
      bytes: bytes,
      resolvedAddresses: resolvedAddresses,
    );
  }
}

import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

import 'x509_test_support.dart';

late TestCertificateChain _certificates;

void main() {
  setUpAll(() async {
    _certificates = await loadTestCertificateChain();
  });

  group('C2paReader cryptographic validation', () {
    test('verifies v1 assertion hashes and callback COSE signature', () async {
      final fixture = await _signedManifest('urn:c2pa:v1');
      final verifier = _DigestVerifier(fixture.publicKey);
      final phases = <C2paProgressPhase>[];

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_store([fixture.manifest]).encode()),
        context: C2paContext(
          verifier: verifier,
          trust: _trust(),
          onProgress: (event) => phases.add(event.phase),
        ),
      );
      final statuses = reader.validationResults.activeManifest!;

      expect(
        statuses.success.map((issue) => issue.code),
        containsAll({
          ValidationCode.assertionHashedUriMatch.value,
          ValidationCode.claimSignatureValidated.value,
        }),
      );
      expect(
        statuses.failure.map((issue) => issue.code),
        contains(ValidationCode.hardBindingsMissing.value),
      );
      expect(reader.validationResults.state, ValidationState.invalid);
      expect(verifier.algorithms, ['ps256']);
      expect(verifier.keys.single, fixture.publicKey);
      expect(phases, contains(C2paProgressPhase.verifying));
    });

    test('detects assertion and signature tampering', () async {
      final assertionTampered = await _signedManifest(
        'urn:c2pa:assertion-tamper',
        tamperAssertion: true,
      );
      final signatureTampered = await _signedManifest(
        'urn:c2pa:signature-tamper',
        tamperSignature: true,
      );

      final first = await C2paReader.fromSource(
        source: MemoryByteSource(_store([assertionTampered.manifest]).encode()),
        context: C2paContext(
          verifier: _DigestVerifier(assertionTampered.publicKey),
          trust: _trust(),
        ),
      );
      final second = await C2paReader.fromSource(
        source: MemoryByteSource(_store([signatureTampered.manifest]).encode()),
        context: C2paContext(
          verifier: _DigestVerifier(signatureTampered.publicKey),
          trust: _trust(),
        ),
      );

      expect(
        first.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.assertionHashedUriMismatch.value),
      );
      expect(
        second.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.claimSignatureMismatch.value),
      );
    });

    test('accepts SHA-256, SHA-384, and SHA-512 hashed URIs', () async {
      for (final algorithm in HashAlgorithm.values) {
        final fixture = await _signedManifest(
          'urn:c2pa:${algorithm.name}',
          hashAlgorithm: algorithm,
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(_store([fixture.manifest]).encode()),
        );

        expect(
          reader.validationResults.activeManifest!.success.map(
            (issue) => issue.code,
          ),
          contains(ValidationCode.assertionHashedUriMatch.value),
        );
      }
    });

    test(
      'reports inaccessible, outside, duplicate, and unsupported refs',
      () async {
        final fixture = await _signedManifest(
          'urn:c2pa:bad-refs',
          references: (hash) => [
            _reference('missing', hash),
            _reference('test.assertion', hash),
            _reference('test.assertion', hash),
            {
              ..._reference('test.assertion', hash),
              'url': 'self#jumbf=/c2pa/urn:c2pa:other/c2pa.assertions/test.assertion',
            },
            {
              ..._reference('test.assertion', hash),
              'url': 'self#jumbf=c2pa.assertions/other',
              'alg': 'sha3-256',
            },
          ],
          extraAssertions: const ['other'],
        );

        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(_store([fixture.manifest]).encode()),
        );
        final codes = reader.validationResults.activeManifest!.failure
            .map((issue) => issue.code)
            .toList();

        expect(codes, contains(ValidationCode.assertionInaccessible.value));
        expect(codes, contains(ValidationCode.assertionMissing.value));
        expect(codes, contains(ValidationCode.hashedUriMismatch.value));
        expect(codes, contains(ValidationCode.assertionOutsideManifest.value));
        expect(codes, contains(ValidationCode.algorithmUnsupported.value));
      },
    );

    test('reports assertion-store entries not declared by the claim', () async {
      final fixture = await _signedManifest(
        'urn:c2pa:undeclared',
        extraAssertions: const ['undeclared.assertion'],
      );

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_store([fixture.manifest]).encode()),
      );

      expect(
        reader.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.assertionUndeclared.value),
      );
    });

    test(
      'verifies v2 created and gathered references and skips orphan manifests',
      () async {
        final old = await _signedManifest('urn:c2pa:old');
        final active = await _signedManifest('urn:c2pa:active', version: 2);
        final verifier = _DigestVerifier(active.publicKey);

        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(
            _store([old.manifest, active.manifest]).encode(),
          ),
          context: C2paContext(verifier: verifier, trust: _trust()),
        );

        expect(reader.activeManifestLabel, 'urn:c2pa:active');
        expect(
          reader.validationResults.activeManifest!.success
              .where(
                (issue) =>
                    issue.code == ValidationCode.assertionHashedUriMatch.value,
              )
              .length,
          2,
        );
        // `urn:c2pa:old` is present in the store but nothing in the active
        // claim's ingredient graph references it. c2pa-rs validates only the
        // manifests reachable through `StoreValidationInfo::
        // ingredient_references`, so an orphaned manifest is never visited and
        // contributes no ingredient delta.
        expect(reader.validationResults.ingredientDeltas, isEmpty);
      },
    );

    group('ingredient delta de-duplication', () {
      // c2pa-rs computes ingredient *deltas*: `ValidationResults::from_store`
      // drops a runtime status when an ingredient assertion already attests an
      // identical one, because re-discovering a known fact is not a delta.
      // Equality is code + URL + log kind, deliberately ignoring the
      // explanation (`impl PartialEq for ValidationStatus`).
      const childLabel = 'urn:c2pa:child';
      const signatureUri = 'self#jumbf=/c2pa/$childLabel/c2pa.signature';

      Future<C2paReader> read(String? attestedUrl) async {
        final child = await _signedManifest(childLabel, tamperSignature: true);
        final parent = await _signedManifest(
          'urn:c2pa:parent',
          ingredients: [
            {
              'dc:title': 'child.jpg',
              'dc:format': 'image/jpeg',
              'instanceID': 'xmp:iid:child',
              'relationship': 'parentOf',
              'c2pa_manifest': {
                'url': 'self#jumbf=/c2pa/$childLabel',
                'alg': 'sha256',
                'hash': Uint8List(32),
              },
              if (attestedUrl != null)
                'validationStatus': [
                  {
                    'code': ValidationCode.claimSignatureMismatch.value,
                    'url': attestedUrl,
                    'explanation': 'an explanation the validator never writes',
                  },
                ],
            },
          ],
        );
        return C2paReader.fromSource(
          source: MemoryByteSource(
            _store([child.manifest, parent.manifest]).encode(),
          ),
          context: C2paContext(
            verifier: _DigestVerifier(parent.publicKey),
            trust: _trust(),
          ),
        );
      }

      List<String> deltaFailures(C2paReader reader) => reader
          .validationResults
          .ingredientDeltas!
          .single
          .validationDeltas
          .failure
          .map((status) => status.code)
          .toList(growable: false);

      test('keeps a status no ingredient assertion attests', () async {
        expect(
          deltaFailures(await read(null)),
          contains(ValidationCode.claimSignatureMismatch.value),
        );
      });

      test('drops a status the ingredient already attested', () async {
        expect(
          deltaFailures(await read(signatureUri)),
          isNot(contains(ValidationCode.claimSignatureMismatch.value)),
        );
      });

      test('matches attested URLs only after resolving them', () async {
        // The attested URL is relative to the manifest the ingredient points
        // at, so it must be made absolute against `c2pa_manifest` before it can
        // match the validator's absolute URL.
        expect(
          deltaFailures(await read('self#jumbf=c2pa.signature')),
          isNot(contains(ValidationCode.claimSignatureMismatch.value)),
        );
      });

      test('keeps a status attested against a different URL', () async {
        expect(
          deltaFailures(await read('Cose_Sign1')),
          contains(ValidationCode.claimSignatureMismatch.value),
        );
      });
    });

    test('reports unsupported and malformed COSE signatures', () async {
      final unsupported = await _signedManifest(
        'urn:c2pa:unsupported',
        unsupportedCoseAlgorithm: true,
      );
      final malformed = await _signedManifest(
        'urn:c2pa:malformed',
        malformedSignature: true,
      );

      final first = await C2paReader.fromSource(
        source: MemoryByteSource(_store([unsupported.manifest]).encode()),
      );
      final second = await C2paReader.fromSource(
        source: MemoryByteSource(_store([malformed.manifest]).encode()),
        context: C2paContext(verifier: _DigestVerifier(malformed.publicKey)),
      );

      expect(
        first.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.algorithmUnsupported.value),
      );
      expect(
        second.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.claimSignatureMismatch.value),
      );
    });
  });
}

final class _Fixture {
  const _Fixture(this.manifest, this.publicKey);

  final JumbfSuperBoxNode manifest;
  final Uint8List publicKey;
}

Future<_Fixture> _signedManifest(
  String label, {
  int version = 1,
  bool tamperAssertion = false,
  bool tamperSignature = false,
  bool unsupportedCoseAlgorithm = false,
  bool malformedSignature = false,
  HashAlgorithm hashAlgorithm = HashAlgorithm.sha256,
  List<Map<String, Object?>> Function(Uint8List hash)? references,
  List<String> extraAssertions = const [],
  List<Map<String, Object?>> ingredients = const [],
}) async {
  final ingredientBoxes = [
    for (var index = 0; index < ingredients.length; index++)
      _cborAssertionBox(
        index == 0 ? 'c2pa.ingredient' : 'c2pa.ingredient__$index',
        ingredients[index],
      ),
  ];
  final ingredientReferences = [
    for (final box in ingredientBoxes)
      _reference(
        box.description.label!,
        Uint8List.fromList(await hashAlgorithm.digest(_payload(box.rawBytes))),
        _hashName(hashAlgorithm),
      ),
  ];
  final assertion = _assertionBox(
    'test.assertion',
    value: tamperAssertion ? 'tampered' : 'original',
  );
  final expectedAssertion = _assertionBox('test.assertion', value: 'original');
  final assertionHash = Uint8List.fromList(
    await hashAlgorithm.digest(_payload(expectedAssertion.rawBytes)),
  );
  final gathered = _assertionBox('gathered.assertion', value: 'gathered');
  final gatheredHash = Uint8List.fromList(
    await hashAlgorithm.digest(_payload(gathered.rawBytes)),
  );
  final hashName = _hashName(hashAlgorithm);

  final claim = version == 1
      ? <String, Object?>{
          'claim_generator': 'test/1.0',
          'claim_generator_info': [
            {'name': 'generator', 'version': '1.0'},
          ],
          'signature': 'self#jumbf=c2pa.signature',
          'assertions':
              references?.call(assertionHash) ??
              [
                _reference('test.assertion', assertionHash, hashName),
                ...ingredientReferences,
              ],
          'dc:format': 'image/jpeg',
          'instanceID': 'xmp:iid:v1',
          'alg': hashName,
        }
      : <String, Object?>{
          'instanceID': 'xmp:iid:v2',
          'claim_generator_info': {'name': 'generator', 'version': '2.0'},
          'signature': 'self#jumbf=c2pa.signature',
          'created_assertions': [
            _reference('test.assertion', assertionHash, hashName),
          ],
          'gathered_assertions': [
            _reference('gathered.assertion', gatheredHash, hashName),
            ...ingredientReferences,
          ],
          'alg': hashName,
        };
  final claimBytes = encodeCbor(claim);
  final publicKey = _certificates.leafSpki;
  final certificateChain = [_certificates.leaf, _certificates.intermediate];

  Uint8List signatureBytes;
  if (malformedSignature) {
    signatureBytes = Uint8List.fromList([0x84]);
  } else if (unsupportedCoseAlgorithm) {
    signatureBytes = CoseSign1(
      protectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -999}),
      unprotectedHeaders: CoseHeaders({
        CoseHeaderLabel.x509Chain: certificateChain,
      }),
      payload: null,
      signature: Uint8List(64),
    ).encode();
  } else {
    signatureBytes =
        await CoseSigner(
          backends: const {SigningAlgorithm.ps256: _DigestSigningBackend()},
        ).sign(
          algorithm: SigningAlgorithm.ps256,
          payload: claimBytes,
          detached: true,
          unprotectedHeaders: CoseHeaders({
            CoseHeaderLabel.x509Chain: certificateChain,
          }),
        );
    if (tamperSignature) {
      signatureBytes[signatureBytes.length - 1] ^= 1;
    }
  }

  return _Fixture(
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: label,
      ),
      children: [
        _claimBox(claimBytes),
        _signatureBox(signatureBytes),
        _assertionStore([
          assertion,
          if (version == 2) gathered,
          for (final extra in extraAssertions)
            _assertionBox(extra, value: extra),
          ...ingredientBoxes,
        ]),
      ],
    ),
    publicKey,
  );
}

Map<String, Object?> _reference(
  String label,
  Uint8List hash, [
  String algorithm = 'sha256',
]) => {
  'url': 'self#jumbf=c2pa.assertions/$label',
  'alg': algorithm,
  'hash': hash,
};

JumbfSuperBoxNode _store(List<JumbfSuperBoxNode> manifests) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ),
      children: manifests,
    );

JumbfSuperBoxNode _claimBox(Uint8List bytes) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paClaim,
    label: 'c2pa.claim',
  ),
  children: [JumbfCborNode(bytes)],
);

JumbfSuperBoxNode _signatureBox(Uint8List bytes) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paSignature,
    label: 'c2pa.signature',
  ),
  children: [JumbfCborNode(bytes)],
);

JumbfSuperBoxNode _assertionStore(List<JumbfSuperBoxNode> assertions) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paAssertionStore,
        label: 'c2pa.assertions',
      ),
      children: assertions,
    );

String _hashName(HashAlgorithm algorithm) => switch (algorithm) {
  HashAlgorithm.sha256 => 'sha256',
  HashAlgorithm.sha384 => 'SHA-384',
  HashAlgorithm.sha512 => 'sha_512',
};

JumbfSuperBoxNode _cborAssertionBox(String label, Map<String, Object?> value) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.cbor,
        label: label,
      ),
      children: [JumbfCborNode(encodeCbor(value))],
    );

JumbfSuperBoxNode _assertionBox(String label, {required String value}) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.cbor,
        label: label,
      ),
      children: [
        JumbfCborNode(encodeCbor({'value': value})),
      ],
    );

Uint8List _payload(Uint8List bytes) => Uint8List.sublistView(bytes, 8);

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

final class _DigestSigningBackend implements CoseSigningBackend {
  const _DigestSigningBackend();

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) =>
      HashAlgorithm.sha512.digest(data);
}

final class _DigestVerifier implements C2paVerifier {
  _DigestVerifier(this.expectedKey);

  final Uint8List expectedKey;
  final List<String> algorithms = [];
  final List<Uint8List> keys = [];

  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async {
    algorithms.add(algorithm);
    keys.add(Uint8List.fromList(publicKey));
    final expectedSignature = await HashAlgorithm.sha512.digest(data);
    return algorithm == 'ps256' &&
        _equalBytes(publicKey, expectedKey) &&
        _equalBytes(signature, expectedSignature);
  }
}

C2paTrustConfiguration _trust() => C2paTrustConfiguration(
  trustAnchors: [_certificates.root],
  evaluationTime: DateTime.utc(2027),
);

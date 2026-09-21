import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  final hardBinding = ClaimHashedUri(
    url: 'self#jumbf=/c2pa.assertions/c2pa.hash.data',
    algorithm: 'sha256',
    hash: Uint8List.fromList([1, 2, 3]),
  );

  group('CAWG identity models', () {
    test('round-trips expected, unknown, and padding fields losslessly', () {
      final value = CawgIdentityAssertion(
        signerPayload: CawgSignerPayload(
          referencedAssertions: [hardBinding],
          signatureType: 'example.signature',
          role: 'editor',
          expected: const {'expected_channel': 'news'},
          unknownFields: const {'future_payload': 4},
        ),
        signature: Uint8List.fromList([4, 5, 6]),
        pad1: Uint8List(4),
        pad2: Uint8List(2),
        unknownFields: const {'future_assertion': true},
      );

      final decoded = CawgIdentityAssertion.decode(value.encode());
      expect(decoded, value);
      expect(decoded.hasValidPadding, isTrue);
      expect(decoded.signerPayload.expected['expected_channel'], 'news');
      expect(decoded.signerPayload.roles, ['editor']);
      expect(decoded.unknownFields['future_assertion'], isTrue);
      expect(value.encode(), orderedEquals(decoded.encode()));
    });

    test('accepts upstream role arrays and preserves legacy strings', () {
      final upstream = CawgSignerPayload.fromCbor({
        'referenced_assertions': [hardBinding.toCborMap()],
        'sig_type': CawgIdentityLabels.x509Cose,
        'role': <String>[],
      });
      expect(upstream.roles, isEmpty);
      expect(upstream.toCborMap()['role'], isA<List<String>>());

      final legacy = CawgSignerPayload.fromCbor({
        'referenced_assertions': [hardBinding.toCborMap()],
        'sig_type': CawgIdentityLabels.x509Cose,
        'role': 'editor',
      });
      expect(legacy.roles, ['editor']);
      expect(legacy.toCborMap()['role'], 'editor');
    });

    test('owns byte inputs and returns immutable collections', () {
      final signature = Uint8List.fromList([1, 2]);
      final assertion = CawgIdentityAssertion(
        signerPayload: CawgSignerPayload(
          referencedAssertions: [hardBinding],
          signatureType: 'unknown',
        ),
        signature: signature,
      );
      signature[0] = 9;
      expect(assertion.signature, [1, 2]);
      expect(
        () => assertion.signerPayload.referencedAssertions.add(hardBinding),
        throwsUnsupportedError,
      );
    });

    test('repeated instance labels are deterministic and strict', () {
      expect(CawgIdentityLabels.instance(0), 'cawg.identity');
      expect(CawgIdentityLabels.instance(3), 'cawg.identity__3');
      expect(CawgIdentityLabels.isIdentity('cawg.identity__3'), isTrue);
      expect(CawgIdentityLabels.isIdentity('cawg.identity__0'), isFalse);
      expect(() => CawgIdentityLabels.instance(-1), throwsArgumentError);
    });
  });

  group('CAWG structural validation', () {
    test(
      'reports duplicate, cycle, mismatch, and missing hard binding',
      () async {
        final identityReference = ClaimHashedUri(
          url: 'self#jumbf=/c2pa.assertions/cawg.identity__1',
          hash: Uint8List.fromList([9]),
        );
        final assertion = CawgIdentityAssertion(
          signerPayload: CawgSignerPayload(
            referencedAssertions: [identityReference, identityReference],
            signatureType: 'unknown',
          ),
          signature: Uint8List.fromList([1]),
        );
        final linkedAssertion = CawgIdentityAssertion(
          signerPayload: CawgSignerPayload(
            referencedAssertions: [
              ClaimHashedUri(
                url: 'self#jumbf=/c2pa.assertions/cawg.identity',
                hash: Uint8List.fromList([8]),
              ),
            ],
            signatureType: 'unknown',
          ),
          signature: Uint8List.fromList([2]),
        );
        final result = await const CawgIdentityValidator().validate(
          assertionLabel: 'cawg.identity',
          assertion: assertion,
          claimAssertions: const [],
          context: C2paContext(),
          identityAssertions: {'cawg.identity__1': linkedAssertion},
        );
        final codes = result.statuses.map((status) => status.code);
        expect(codes, contains(CawgStatusCodes.assertionDuplicate));
        expect(codes, contains(CawgStatusCodes.assertionCycle));
        expect(codes, contains(CawgStatusCodes.assertionMismatch));
        expect(codes, contains(CawgStatusCodes.hardBindingMissing));
        expect(codes, contains(CawgStatusCodes.signatureTypeUnknown));
      },
    );

    test(
      'stop-first policy returns only the first structural failure',
      () async {
        final assertion = CawgIdentityAssertion(
          signerPayload: CawgSignerPayload(
            referencedAssertions: [hardBinding],
            signatureType: 'unknown',
          ),
          signature: Uint8List.fromList([1]),
          pad1: Uint8List.fromList([1]),
        );
        final result = await const CawgIdentityValidator().validate(
          assertionLabel: 'cawg.identity',
          assertion: assertion,
          claimAssertions: const [],
          context: C2paContext(
            cawgValidationPolicy: CawgValidationPolicy.stopOnFirstFailure,
          ),
        );
        expect(result.statuses, hasLength(1));
        expect(result.statuses.single.code, CawgStatusCodes.padInvalid);
      },
    );

    test('allows acyclic references between identity assertions', () async {
      final childReference = ClaimHashedUri(
        url: 'self#jumbf=/c2pa.assertions/cawg.identity__1',
        hash: Uint8List.fromList([7]),
      );
      final child = CawgIdentityAssertion(
        signerPayload: CawgSignerPayload(
          referencedAssertions: [hardBinding],
          signatureType: 'unknown',
        ),
        signature: Uint8List.fromList([2]),
      );
      final assertion = CawgIdentityAssertion(
        signerPayload: CawgSignerPayload(
          referencedAssertions: [hardBinding, childReference],
          signatureType: 'unknown',
        ),
        signature: Uint8List.fromList([1]),
      );
      final result = await const CawgIdentityValidator().validate(
        assertionLabel: 'cawg.identity',
        assertion: assertion,
        claimAssertions: [hardBinding, childReference],
        identityAssertions: {'cawg.identity__1': child},
        context: C2paContext(),
      );
      expect(
        result.statuses.map((status) => status.code),
        isNot(contains(CawgStatusCodes.assertionCycle)),
      );
    });
  });

  group('ICA', () {
    test('accepts a signed VC 1.1 did:jwk credential', () async {
      final algorithm = Ed25519();
      final keyPair = await algorithm.newKeyPair();
      final pairData = await keyPair.extract();
      final publicKey = await keyPair.extractPublicKey();
      final jwk = {
        'kty': 'OKP',
        'crv': 'Ed25519',
        'x': base64Url.encode(publicKey.bytes).replaceAll('=', ''),
      };
      final did =
          'did:jwk:${base64Url.encode(utf8.encode(jsonEncode(jwk))).replaceAll('=', '')}';
      final signerPayload = CawgSignerPayload(
        referencedAssertions: [hardBinding],
        signatureType: CawgIdentityLabels.identityClaimsAggregation,
      );
      final credential = CawgIdentityClaimsCredential(
        context: const [
          'https://www.w3.org/2018/credentials/v1',
          'https://cawg.io/identity/1.1/ica/context/',
        ],
        types: const [
          'VerifiableCredential',
          'IdentityClaimsAggregationCredential',
        ],
        issuer: CawgIssuer(id: did),
        issuanceDate: DateTime.utc(2024),
        verifiedIdentities: [
          CawgVerifiedIdentity(
            type: 'cawg.person',
            name: 'Ada',
            verifiedAt: DateTime.utc(2025),
            provider: CawgIdentityProvider(
              id: Uri.parse('https://provider.example'),
              name: 'Provider',
            ),
          ),
        ],
        c2paAsset: signerPayload.toJson(),
      );
      final payload = Uint8List.fromList(
        utf8.encode(jsonEncode(credential.toJson())),
      );
      final cose =
          await CoseSigner(
            backends: {
              SigningAlgorithm.ed25519: Ed25519SigningBackend(pairData),
            },
          ).sign(
            algorithm: SigningAlgorithm.ed25519,
            payload: payload,
            protectedHeaders: CoseHeaders({
              CoseHeaderLabel.contentType: 'application/vc',
            }),
          );
      final assertion = CawgIdentityAssertion(
        signerPayload: signerPayload,
        signature: cose,
      );

      final result = await const CawgIdentityValidator().validate(
        assertionLabel: 'cawg.identity',
        assertion: assertion,
        claimAssertions: [hardBinding],
        context: C2paContext(),
      );
      expect(result.isTrusted, isTrue);
      expect(
        result.statuses.map((status) => status.code),
        containsAll([
          CawgStatusCodes.icaCredentialValid,
          CawgStatusCodes.trusted,
          CawgStatusCodes.wellFormed,
        ]),
      );
    });

    test('Reader context exposes Rust compatibility mode', () {
      final context = C2paContext(
        cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
      );
      expect(context.cawgIcaCompatibility, CawgIcaCompatibility.c2paRs09022);

      final credential = CawgIdentityClaimsCredential(
        context: const [
          'https://www.w3.org/2018/credentials/v1',
          'https://cawg.io/identity/1.1/ica/context/',
        ],
        types: const [
          'VerifiableCredential',
          'IdentityClaimsAggregationCredential',
        ],
        issuer: CawgIssuer(id: 'did:jwk:e30'),
        issuanceDate: DateTime.utc(2024),
        verifiedIdentities: [
          CawgVerifiedIdentity(
            type: 'person',
            verifiedAt: DateTime.utc(2025),
            provider: CawgIdentityProvider(
              id: Uri.parse('https://provider.example'),
              name: 'Provider',
            ),
          ),
        ],
        c2paAsset: const {'sig_type': 'test'},
      );
      expect(credential.isVc11, isTrue);
      expect(credential.isVc20, isFalse);
    });

    test('preserves original VC JSON bytes and string provider ids', () {
      final bytes = Uint8List.fromList(
        utf8.encode(
          '{"type":["VerifiableCredential",'
          '"IdentityClaimsAggregationCredential"],'
          '"@context":["https://www.w3.org/ns/credentials/v2",'
          '"https://cawg.io/identity/1.1/ica/context/"],'
          '"issuer":"did:jwk:e30","validFrom":"2024-01-01T00:00:00Z",'
          '"credentialSubject":{"verifiedIdentities":[{'
          '"type":"person","verifiedAt":"2025-01-01T00:00:00Z",'
          '"provider":{"id":"provider-id","name":"Provider"}}],'
          '"c2paAsset":{"sig_type":"test"}}}',
        ),
      );
      final credential = CawgIdentityClaimsCredential.decode(bytes);
      expect(credential.rawJsonBytes, bytes);
      expect(credential.encodeJson(), bytes);
      expect(
        credential.verifiedIdentities.single.provider.id.toString(),
        'provider-id',
      );
      bytes.fillRange(0, bytes.length, 0);
      expect(credential.encodeJson().first, '{'.codeUnitAt(0));
    });

    test(
      'normalizes equivalent hash arrays in both compatibility modes',
      () async {
        final signed = await _signedIca(
          issuer: 'did:jwk',
          hardBinding: hardBinding,
          rustHashEncoding: true,
        );
        final stable = await const CawgIcaVerifier().verify(
          signed.assertion,
          C2paContext(),
        );
        final compatible = await const CawgIcaVerifier(
          compatibility: CawgIcaCompatibility.c2paRs09022,
        ).verify(signed.assertion, C2paContext());
        expect(stable.statuses.map((status) => status.code), [
          CawgStatusCodes.icaCredentialValid,
          CawgStatusCodes.trusted,
        ]);
        expect(compatible.statuses.map((status) => status.code), [
          CawgStatusCodes.icaCredentialValid,
        ]);
        final readerStyle = await const CawgIdentityValidator().validate(
          assertionLabel: CawgIdentityLabels.identity,
          assertion: signed.assertion,
          claimAssertions: [hardBinding],
          context: C2paContext(
            cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
          ),
        );
        expect(readerStyle.statuses.map((status) => status.code), [
          CawgStatusCodes.icaCredentialValid,
        ]);
      },
    );

    test('limits missing algorithm synthesis to c2pa-rs mode', () async {
      final signed = await _signedIca(
        issuer: 'did:jwk',
        hardBinding: hardBinding,
        vcAssetAlgorithmOnly: true,
      );
      final stable = await const CawgIdentityValidator().validate(
        assertionLabel: CawgIdentityLabels.identity,
        assertion: signed.assertion,
        claimAssertions: [hardBinding],
        context: C2paContext(),
      );
      final compatible = await const CawgIdentityValidator().validate(
        assertionLabel: CawgIdentityLabels.identity,
        assertion: signed.assertion,
        claimAssertions: [hardBinding],
        context: C2paContext(
          cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022,
        ),
      );

      expect(stable.statuses.map((status) => status.code), [
        CawgStatusCodes.icaAssetMismatch,
      ]);
      expect(compatible.statuses.map((status) => status.code), [
        CawgStatusCodes.icaCredentialValid,
      ]);
    });

    test(
      'resolves did:web with exact document id and network policy',
      () async {
        final signed = await _signedIca(
          issuer: 'did:web:identity.example',
          hardBinding: hardBinding,
        );
        final resolver = _FakeResolver(
          C2paRemoteResponse.bytes(
            bytes: utf8.encode(
              jsonEncode({
                'id': 'did:web:identity.example',
                'assertionMethod': [
                  {
                    'id': 'did:web:identity.example#key-1',
                    'publicKeyJwk': signed.jwk,
                  },
                ],
              }),
            ),
            resolvedAddresses: const ['8.8.8.8'],
          ),
        );
        final result = await const CawgIdentityValidator().validate(
          assertionLabel: 'cawg.identity',
          assertion: signed.assertion,
          claimAssertions: [hardBinding],
          context: C2paContext(
            didWebResolver: resolver,
            didWebPolicy: RemoteManifestPolicy(
              enabled: true,
              allowedHosts: const {'identity.example'},
              maxBytes: 1024 * 1024,
            ),
          ),
        );
        expect(result.isTrusted, isTrue);
        expect(
          resolver.lastUri,
          Uri.parse('https://identity.example/.well-known/did.json'),
        );
      },
    );

    test('rejects a did:web document with a different id', () async {
      final signed = await _signedIca(
        issuer: 'did:web:identity.example',
        hardBinding: hardBinding,
      );
      final result = await const CawgIdentityValidator().validate(
        assertionLabel: 'cawg.identity',
        assertion: signed.assertion,
        claimAssertions: [hardBinding],
        context: C2paContext(
          didWebResolver: _FakeResolver(
            C2paRemoteResponse.bytes(
              bytes: utf8.encode(
                jsonEncode({
                  'id': 'did:web:attacker.example',
                  'verificationMethod': const <Object?>[],
                }),
              ),
              resolvedAddresses: const ['8.8.8.8'],
            ),
          ),
          didWebPolicy: RemoteManifestPolicy(
            enabled: true,
            allowedHosts: const {'identity.example'},
            maxBytes: 1024 * 1024,
          ),
        ),
      );
      expect(
        result.statuses.map((status) => status.code),
        contains(CawgStatusCodes.icaInvalidDidDocument),
      );
    });

    test('maps a missing did:web resolver to did_unavailable', () async {
      final signed = await _signedIca(
        issuer: 'did:web:identity.example',
        hardBinding: hardBinding,
      );
      final result =
          await const CawgIcaVerifier(
            compatibility: CawgIcaCompatibility.c2paRs09022,
          ).verify(
            signed.assertion,
            C2paContext(cawgIcaCompatibility: CawgIcaCompatibility.c2paRs09022),
          );
      expect(result.statuses.map((status) => status.code), [
        CawgStatusCodes.icaDidResolutionFailed,
      ]);
    });

    test('rejects private resolved addresses for did:web', () async {
      final signed = await _signedIca(
        issuer: 'did:web:identity.example',
        hardBinding: hardBinding,
      );
      final result = await const CawgIdentityValidator().validate(
        assertionLabel: 'cawg.identity',
        assertion: signed.assertion,
        claimAssertions: [hardBinding],
        context: C2paContext(
          didWebResolver: _FakeResolver(
            C2paRemoteResponse.bytes(
              bytes: const [123, 125],
              resolvedAddresses: const ['127.0.0.1'],
            ),
          ),
          didWebPolicy: RemoteManifestPolicy(
            enabled: true,
            allowedHosts: const {'identity.example'},
            maxBytes: 1024 * 1024,
          ),
        ),
      );
      expect(
        result.statuses.map((status) => status.code),
        contains(CawgStatusCodes.icaDidResolutionFailed),
      );
    });
  });

  test('X.509 holder reserves an exactly sized dynamic assertion', () async {
    final holder = CawgX509CredentialHolder(
      signer: CallbackC2paSigner(
        algorithm: 'es256',
        callback: (_) async => Uint8List(64),
      ),
      certificateChain: [
        Uint8List.fromList([1, 2, 3]),
      ],
      reservedAssertionSize: 1024,
    );
    final dynamic = holder.toDynamicAssertion();
    final output = await dynamic.callback(
      C2paDynamicAssertionRequest(
        label: dynamic.label,
        reservedSize: dynamic.reservedSize,
        claim: C2paDynamicClaimContext(
          manifestLabel: 'm',
          instanceId: 'xmp:iid:1',
          format: 'image/jpeg',
          hashAlgorithm: 'sha256',
          assertions: [hardBinding],
        ),
      ),
    );
    expect(encodeCbor(output.data).length, 1024);
    expect(CawgIdentityAssertion.fromCbor(output.data).hasValidPadding, isTrue);
  });

  test('ICA holder binds c2paAsset and reserves an exact assertion', () async {
    final holder = CawgIcaCredentialHolder(
      signer: CallbackC2paSigner(
        algorithm: 'ed25519',
        callback: (_) async => Uint8List(64),
      ),
      reservedAssertionSize: 1400,
      credentialFactory: (payload) => CawgIdentityClaimsCredential(
        context: const [
          'https://www.w3.org/ns/credentials/v2',
          'https://cawg.io/identity/1.1/ica/context/',
        ],
        types: const [
          'VerifiableCredential',
          'IdentityClaimsAggregationCredential',
        ],
        issuer: CawgIssuer(id: 'did:jwk:e30'),
        validFrom: DateTime.utc(2024),
        verifiedIdentities: [
          CawgVerifiedIdentity(
            type: 'person',
            verifiedAt: DateTime.utc(2025),
            provider: CawgIdentityProvider(
              id: Uri.parse('https://provider.example'),
              name: 'Provider',
            ),
          ),
        ],
        c2paAsset: payload.toJson(),
      ),
    );
    final dynamic = holder.toDynamicAssertion(instance: 1);
    final output = await dynamic.callback(
      C2paDynamicAssertionRequest(
        label: dynamic.label,
        reservedSize: dynamic.reservedSize,
        claim: C2paDynamicClaimContext(
          manifestLabel: 'm',
          instanceId: 'xmp:iid:1',
          format: 'image/jpeg',
          hashAlgorithm: 'sha256',
          assertions: [hardBinding],
        ),
      ),
    );
    expect(dynamic.label, 'cawg.identity__1');
    expect(encodeCbor(output.data).length, 1400);
    final assertion = CawgIdentityAssertion.fromCbor(output.data);
    expect(
      assertion.signerPayload.signatureType,
      CawgIdentityLabels.identityClaimsAggregation,
    );
  });

  test('DID web defaults are disabled and capped at one MiB', () {
    final context = C2paContext();
    expect(context.didWebPolicy.enabled, isFalse);
    expect(context.didWebPolicy.allowedSchemes, {'https'});
    expect(context.didWebPolicy.maxBytes, 1024 * 1024);
  });

  test('Builder and Reader expose repeated identity summaries', () async {
    CawgX509CredentialHolder holder(int size) => CawgX509CredentialHolder(
      signer: CallbackC2paSigner(
        algorithm: 'es256',
        callback: (_) async => Uint8List(64),
      ),
      certificateChain: [
        Uint8List.fromList([1, 2, 3]),
      ],
      reservedAssertionSize: size,
    );
    final builder =
        C2paBuilder(
              definition: ManifestDefinition(
                label: 'urn:c2pa:cawg',
                intent: const BuilderIntent.create(
                  DigitalSourceType.digitalCapture,
                ),
                generatorInfo: ClaimGeneratorInfo(name: 'cawg-test'),
                format: 'application/c2pa',
                instanceId: 'xmp:iid:cawg',
              ),
              context: C2paContext(
                signer: CallbackC2paSigner(
                  algorithm: 'ed25519',
                  callback: (_) async => Uint8List(64),
                ),
              ),
              signingAlgorithm: 'ed25519',
              x5chain: [
                Uint8List.fromList([1]),
              ],
            )
            .withCawgX509Identity(holder(1024))
            .withCawgX509Identity(holder(1024), instance: 1);

    final reader = await C2paReader.fromSource(
      source: MemoryByteSource(await builder.build()),
    );
    final identities = reader.activeManifest!.identityAssertions;
    expect(identities, hasLength(2));
    expect(identities.map((identity) => identity.assertionLabel), [
      'cawg.identity',
      'cawg.identity__1',
    ]);
    expect(
      identities.expand((identity) => identity.statuses).map((s) => s.code),
      everyElement(
        anyOf(CawgStatusCodes.certificateInvalid, CawgStatusCodes.wellFormed),
      ),
    );
    expect(reader.toDetailedJson()['manifests'], isA<Map<String, Object?>>());
  });
}

Future<({CawgIdentityAssertion assertion, Map<String, Object?> jwk})>
_signedIca({
  required String issuer,
  required ClaimHashedUri hardBinding,
  bool rustHashEncoding = false,
  bool vcAssetAlgorithmOnly = false,
}) async {
  final algorithm = Ed25519();
  final keyPair = await algorithm.newKeyPair();
  final pairData = await keyPair.extract();
  final publicKey = await keyPair.extractPublicKey();
  final jwk = <String, Object?>{
    'kty': 'OKP',
    'crv': 'Ed25519',
    'x': base64Url.encode(publicKey.bytes).replaceAll('=', ''),
  };
  final effectiveIssuer = issuer == 'did:jwk'
      ? 'did:jwk:${base64Url.encode(utf8.encode(jsonEncode(jwk))).replaceAll('=', '')}'
      : issuer;
  final signerPayload = CawgSignerPayload(
    referencedAssertions: [
      if (vcAssetAlgorithmOnly)
        ClaimHashedUri(url: hardBinding.url, hash: hardBinding.hash)
      else
        hardBinding,
    ],
    signatureType: CawgIdentityLabels.identityClaimsAggregation,
  );
  final asset =
      (jsonDecode(jsonEncode(signerPayload.toJson())) as Map<String, Object?>);
  if (rustHashEncoding) {
    final references = asset['referenced_assertions']! as List<Object?>;
    final reference = references.single as Map<String, Object?>;
    reference['hash'] = utf8.encode(reference['hash']! as String);
  }
  if (vcAssetAlgorithmOnly) {
    final references = asset['referenced_assertions']! as List<Object?>;
    final reference = references.single as Map<String, Object?>;
    reference['alg'] = hardBinding.algorithm;
  }
  final credential = CawgIdentityClaimsCredential(
    context: const [
      'https://www.w3.org/ns/credentials/v2',
      'https://cawg.io/identity/1.1/ica/context/',
    ],
    types: const [
      'VerifiableCredential',
      'IdentityClaimsAggregationCredential',
    ],
    issuer: CawgIssuer(id: effectiveIssuer),
    validFrom: DateTime.utc(2024),
    verifiedIdentities: [
      CawgVerifiedIdentity(
        type: 'person',
        verifiedAt: DateTime.utc(2025),
        provider: CawgIdentityProvider(
          id: Uri.parse('https://provider.example'),
          name: 'Provider',
        ),
      ),
    ],
    c2paAsset: asset,
  );
  final payload = Uint8List.fromList(
    utf8.encode(jsonEncode(credential.toJson())),
  );
  final cose =
      await CoseSigner(
        backends: {SigningAlgorithm.ed25519: Ed25519SigningBackend(pairData)},
      ).sign(
        algorithm: SigningAlgorithm.ed25519,
        payload: payload,
        protectedHeaders: CoseHeaders({
          CoseHeaderLabel.contentType: 'application/vc',
        }),
      );
  return (
    assertion: CawgIdentityAssertion(
      signerPayload: signerPayload,
      signature: cose,
    ),
    jwk: jwk,
  );
}

final class _FakeResolver implements C2paRemoteResolver {
  _FakeResolver(this.response);

  final C2paRemoteResponse response;
  Uri? lastUri;

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    lastUri = request.uri;
    return response;
  }
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:test/test.dart';

import 'x509_test_support.dart';

void main() {
  late TestCertificateChain certificates;
  late C2paSigner signer;
  late Uint8List trustedManifest;
  late crypto.Ed25519 tsaAlgorithm;
  late crypto.SimpleKeyPair tsaKey;
  late Uint8List tsaCertificate;
  late Uint8List tsaCertificateHash;
  late crypto.SimpleKeyPair ocspIssuerKey;
  late crypto.SimpleKeyPair ocspSignerKey;
  late X509Certificate ocspIssuer;
  late X509Certificate ocspSignerCertificate;
  late Uint8List ocspManifest;

  setUpAll(() async {
    certificates = await loadTestCertificateChain();
    signer = await createNativeTestSigner(certificates);
    trustedManifest = await _build(signer, [
      certificates.leaf,
      certificates.intermediate,
    ]);
    tsaAlgorithm = crypto.Ed25519();
    tsaKey = await tsaAlgorithm.newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 17),
    );
    tsaCertificate = await _tsaCertificate(tsaAlgorithm, tsaKey);
    tsaCertificateHash = Uint8List.fromList(
      await HashAlgorithm.sha256.digest(tsaCertificate),
    );
    ocspIssuerKey = await tsaAlgorithm.newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 51),
    );
    ocspSignerKey = await tsaAlgorithm.newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 91),
    );
    ocspIssuer = X509Certificate.parse(
      await _testCertificate(
        algorithm: tsaAlgorithm,
        subject: 'OCSP Issuer',
        issuer: 'OCSP Issuer',
        subjectKey: ocspIssuerKey,
        issuerKey: ocspIssuerKey,
        serial: 101,
        isCa: true,
      ),
      allowUnknownCriticalExtensions: true,
    );
    ocspSignerCertificate = X509Certificate.parse(
      await _testCertificate(
        algorithm: tsaAlgorithm,
        subject: 'OCSP Test Signer',
        issuer: 'OCSP Issuer',
        subjectKey: ocspSignerKey,
        issuerKey: ocspIssuerKey,
        serial: 102,
        eku: ExtendedKeyUsageOids.codeSigning,
        ocspUrl: Uri.parse('https://ocsp.example.test'),
      ),
      allowUnknownCriticalExtensions: true,
    );
    final ocspSigner = CallbackC2paSigner(
      algorithm: 'ed25519',
      callback: (data) async => Uint8List.fromList(
        (await tsaAlgorithm.sign(data, keyPair: ocspSignerKey)).bytes,
      ),
    );
    ocspManifest = await _build(ocspSigner, [
      ocspSignerCertificate.der,
      ocspIssuer.der,
    ]);
  });

  group('C2paReader X.509 validation', () {
    test('verifies native signature, profile, and trusted path', () async {
      final reader = await _read(
        trustedManifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2027),
        ),
      );
      final codes = _codes(reader);
      final info = reader.activeManifest!.signatureInfo!;

      expect(codes, contains(ValidationCode.claimSignatureValidated.value));
      expect(
        codes,
        contains(ValidationCode.claimSignatureInsideValidity.value),
      );
      expect(codes, contains(ValidationCode.signingCredentialTrusted.value));
      expect(
        codes,
        isNot(contains(ValidationCode.signingCredentialNotRevoked.value)),
      );
      expect(codes, isNot(contains(ValidationCode.timestampValidated.value)));
      expect(codes, isNot(contains(ValidationCode.timestampTrusted.value)));
      expect(reader.validationResults.errors, isEmpty);
      expect(reader.validationResults.state, ValidationState.trusted);
      expect(info.algorithm, 'ps256');
      expect(info.issuer, 'Test Intermediate');
      expect(info.commonName, 'Trusted Signer');
      expect(info.serialNumber, '3');
      expect(info.certificateChain, hasLength(2));
      expect(info.time, isNull);
      expect(info.revocationStatus, isNull);
      expect(() => info.certificateChain.first[0] = 0, throwsUnsupportedError);
    });

    test(
      'keeps a valid signature valid but untrusted without an anchor',
      () async {
        final reader = await _read(
          trustedManifest,
          trust: C2paTrustConfiguration(evaluationTime: DateTime.utc(2027)),
        );
        final codes = _codes(reader);

        expect(codes, contains(ValidationCode.claimSignatureValidated.value));
        expect(
          codes,
          contains(ValidationCode.claimSignatureInsideValidity.value),
        );
        expect(
          codes,
          contains(ValidationCode.signingCredentialUntrusted.value),
        );
        expect(reader.validationResults.state, ValidationState.valid);
      },
    );

    test('reports certificates outside their validity interval', () async {
      final reader = await _read(
        trustedManifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2040),
        ),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.claimSignatureValidated.value));
      expect(
        codes,
        contains(ValidationCode.claimSignatureOutsideValidity.value),
      );
      expect(codes, contains(ValidationCode.signingCredentialExpired.value));
      expect(
        codes,
        isNot(contains(ValidationCode.claimSignatureInsideValidity.value)),
      );
      expect(reader.validationResults.state, ValidationState.invalid);
    });

    test('rejects a signer certificate with a disallowed EKU', () async {
      final manifest = await _build(signer, [
        certificates.wrongEkuLeaf,
        certificates.intermediate,
      ]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2027),
        ),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.claimSignatureValidated.value));
      expect(codes, contains(ValidationCode.signingCredentialInvalid.value));
      expect(reader.validationResults.state, ValidationState.invalid);
    });

    test('rejects a broken certificate chain', () async {
      final brokenIntermediate = Uint8List.fromList(certificates.intermediate);
      brokenIntermediate[brokenIntermediate.length - 1] ^= 1;
      final manifest = await _build(signer, [
        certificates.leaf,
        brokenIntermediate,
      ]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2027),
        ),
      );

      expect(
        _codes(reader),
        contains(ValidationCode.signingCredentialInvalid.value),
      );
      expect(reader.validationResults.state, ValidationState.invalid);
    });

    test('profile-only validation does not require a valid chain', () async {
      final brokenIntermediate = Uint8List.fromList(certificates.intermediate);
      brokenIntermediate[brokenIntermediate.length - 1] ^= 1;
      final manifest = await _build(signer, [
        certificates.leaf,
        brokenIntermediate,
      ]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(evaluationTime: DateTime.utc(2027)),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.claimSignatureValidated.value));
      expect(codes, contains(ValidationCode.signingCredentialUntrusted.value));
      expect(
        codes,
        isNot(contains(ValidationCode.signingCredentialInvalid.value)),
      );
      expect(reader.validationResults.state, ValidationState.valid);
    });

    test('trusts an allow-listed leaf without a certificate path', () async {
      final leafHash = Uint8List.fromList(
        await HashAlgorithm.sha256.digest(certificates.leaf),
      );
      final manifest = await _build(signer, [certificates.leaf]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(
          allowedEndEntitySha256Hashes: [leafHash],
          evaluationTime: DateTime.utc(2027),
        ),
      );

      expect(
        _codes(reader),
        contains(ValidationCode.signingCredentialTrusted.value),
      );
      expect(reader.validationResults.state, ValidationState.trusted);
    });

    test('reports malformed x5chain as invalid and unverifiable', () async {
      final manifest = await _build(signer, [
        Uint8List.fromList([0x30, 0x01, 0x00]),
      ]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(evaluationTime: DateTime.utc(2027)),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.claimSignatureMismatch.value));
      expect(codes, contains(ValidationCode.signingCredentialInvalid.value));
      expect(reader.activeManifest!.signatureInfo, isNull);
      expect(reader.validationResults.state, ValidationState.invalid);
    });

    test('allows an explicitly configured signer EKU', () async {
      final manifest = await _build(signer, [
        certificates.wrongEkuLeaf,
        certificates.intermediate,
      ]);
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          allowedEkuOids: const [ExtendedKeyUsageOids.timeStamping],
          evaluationTime: DateTime.utc(2027),
        ),
      );

      expect(reader.validationResults.state, ValidationState.trusted);
    });

    test('extracts text timestamp headers without breaking COSE', () async {
      final manifest = _addUnprotectedHeader(trustedManifest, 'sigTst2', {
        'tstTokens': [
          {
            'val': Uint8List.fromList([0x30, 0x00]),
          },
        ],
      });
      final reader = await _read(
        manifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2027),
        ),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.claimSignatureValidated.value));
      expect(codes, contains(ValidationCode.timestampMalformed.value));
    });

    test('validates and trusts an RFC 3161 sigTst2 timestamp', () async {
      final signedBytes = _timestampSignedBytes(trustedManifest);
      final token = await _timestampToken(
        algorithm: tsaAlgorithm,
        keyPair: tsaKey,
        certificate: tsaCertificate,
        signedBytes: signedBytes,
      );
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          _addUnprotectedHeader(trustedManifest, 'sigTst2', {
            'tstTokens': [
              {'val': token},
            ],
          }),
        ),
        context: C2paContext(
          trust: C2paTrustConfiguration(
            trustAnchors: [certificates.root],
            evaluationTime: DateTime.utc(2040),
          ),
          timestampTrust: C2paTrustConfiguration(
            allowedEndEntitySha256Hashes: [tsaCertificateHash],
          ),
        ),
      );
      final codes = _codes(reader);

      expect(codes, contains(ValidationCode.timestampValidated.value));
      expect(codes, contains(ValidationCode.timestampTrusted.value));
      expect(codes, contains(ValidationCode.timeOfSigningInsideValidity.value));
      expect(
        codes,
        contains(ValidationCode.claimSignatureInsideValidity.value),
      );
      expect(
        codes,
        isNot(contains(ValidationCode.signingCredentialExpired.value)),
      );
      expect(
        reader.activeManifest!.signatureInfo!.time,
        DateTime.utc(2027, 1, 2, 3, 4, 5),
      );
    });

    test('reports timestamp imprint mismatch and untrusted TSA', () async {
      final token = await _timestampToken(
        algorithm: tsaAlgorithm,
        keyPair: tsaKey,
        certificate: tsaCertificate,
        signedBytes: utf8.encode('wrong imprint'),
      );
      final mismatched = await C2paReader.fromSource(
        source: MemoryByteSource(
          _addUnprotectedHeader(trustedManifest, 'sigTst2', {
            'tstTokens': [
              {'val': token},
            ],
          }),
        ),
        context: C2paContext(
          trust: C2paTrustConfiguration(
            trustAnchors: [certificates.root],
            evaluationTime: DateTime.utc(2027),
          ),
          timestampTrust: C2paTrustConfiguration(
            allowedEndEntitySha256Hashes: [tsaCertificateHash],
          ),
        ),
      );
      expect(
        _codes(mismatched),
        contains(ValidationCode.timestampMismatch.value),
      );

      final validToken = await _timestampToken(
        algorithm: tsaAlgorithm,
        keyPair: tsaKey,
        certificate: tsaCertificate,
        signedBytes: _timestampSignedBytes(trustedManifest),
      );
      final untrusted = await C2paReader.fromSource(
        source: MemoryByteSource(
          _addUnprotectedHeader(trustedManifest, 'sigTst2', {
            'tstTokens': [
              {'val': validToken},
            ],
          }),
        ),
        context: C2paContext(
          trust: C2paTrustConfiguration(
            trustAnchors: [certificates.root],
            evaluationTime: DateTime.utc(2027),
          ),
        ),
      );
      final untrustedCodes = _codes(untrusted);
      expect(untrustedCodes, contains(ValidationCode.timestampValidated.value));
      expect(untrustedCodes, contains(ValidationCode.timestampUntrusted.value));
      expect(untrusted.activeManifest!.signatureInfo!.time, isNull);
    });

    test(
      'Builder attaches valid pre-supplied and callback sigTst2 tokens',
      () async {
        var requests = 0;
        final callback =
            await _builder(signer, [
                  certificates.leaf,
                  certificates.intermediate,
                ], context: C2paContext(signer: signer))
                .withTimestamp(
                  C2paTimestampConfig.callback(
                    callback: (request) async {
                      requests++;
                      expect(request, isNotEmpty);
                      return _timestampToken(
                        algorithm: tsaAlgorithm,
                        keyPair: tsaKey,
                        certificate: tsaCertificate,
                        imprint: _timestampRequestImprint(request),
                      );
                    },
                    reservedSize: 4096,
                  ),
                )
                .build();
        expect(requests, 1);
        final deterministicSigner = CallbackC2paSigner(
          algorithm: 'ed25519',
          callback: (data) async => Uint8List.fromList(
            (await tsaAlgorithm.sign(data, keyPair: tsaKey)).bytes,
          ),
        );
        final deterministicBase = await _builder(deterministicSigner, [
          tsaCertificate,
        ]).build();
        final suppliedToken = await _timestampToken(
          algorithm: tsaAlgorithm,
          keyPair: tsaKey,
          certificate: tsaCertificate,
          signedBytes: _timestampSignedBytes(deterministicBase),
        );
        final supplied = await _builder(deterministicSigner, [tsaCertificate])
            .withTimestamp(
              C2paTimestampConfig.token(suppliedToken, reservedSize: 4096),
            )
            .build();
        for (final manifest in [supplied, callback]) {
          final reader = await C2paReader.fromSource(
            source: MemoryByteSource(manifest),
            context: C2paContext(
              trust: C2paTrustConfiguration(
                verifyTrust: true,
                trustAnchors: [certificates.root],
                intermediates: [certificates.intermediate],
              ),
              timestampTrust: C2paTrustConfiguration(
                verifyTrust: true,
                allowedEndEntitySha256Hashes: [tsaCertificateHash],
              ),
            ),
          );
          expect(
            _codes(reader),
            contains(ValidationCode.timestampValidated.value),
          );
        }
      },
    );

    test(
      'Builder rejects invalid, oversized, failed, and cancelled TSA output',
      () async {
        final base = _builder(signer, [
          certificates.leaf,
          certificates.intermediate,
        ], context: C2paContext(signer: signer));
        await expectLater(
          base
              .withTimestamp(
                C2paTimestampConfig.token(Uint8List.fromList([1, 2, 3])),
              )
              .build(),
          throwsA(isA<C2paTimestampException>()),
        );
        await expectLater(
          base
              .withTimestamp(
                C2paTimestampConfig.callback(
                  callback: (_) async => Uint8List(20),
                  reservedSize: 10,
                ),
              )
              .build(),
          throwsA(isA<C2paTimestampLimitException>()),
        );
        await expectLater(
          base
              .withTimestamp(
                C2paTimestampConfig.callback(
                  callback: (_) async => throw StateError('tsa failed'),
                  reservedSize: 128,
                ),
              )
              .build(),
          throwsA(isA<C2paTimestampException>()),
        );
        await expectLater(
          base
              .withTimestamp(
                C2paTimestampConfig.callback(
                  callback: (_) => Future<Uint8List>.delayed(
                    const Duration(seconds: 1),
                    () => Uint8List(1),
                  ),
                  reservedSize: 128,
                  timeout: const Duration(milliseconds: 1),
                ),
              )
              .build(),
          throwsA(isA<C2paTimestampException>()),
        );
        await expectLater(
          _builder(signer, [
                certificates.leaf,
                certificates.intermediate,
              ], context: C2paContext(signer: signer, isCancelled: () => true))
              .withTimestamp(
                C2paTimestampConfig.callback(
                  callback: (_) async => Uint8List(1),
                  reservedSize: 128,
                ),
              )
              .build(),
          throwsA(isA<C2paTimestampException>()),
        );
      },
    );

    test(
      'Builder archives pre-supplied timestamps but not callbacks',
      () async {
        final token = await _timestampToken(
          algorithm: tsaAlgorithm,
          keyPair: tsaKey,
          certificate: tsaCertificate,
          signedBytes: _timestampSignedBytes(trustedManifest),
        );
        final builder =
            _builder(signer, [
              certificates.leaf,
              certificates.intermediate,
            ], context: C2paContext(signer: signer)).withTimestamp(
              C2paTimestampConfig.token(token, reservedSize: token.length + 32),
            );
        final restored = await C2paBuilder.fromArchive(
          bytes: builder.toArchive(),
          context: C2paContext(signer: signer),
        );
        expect(restored.timestamp!.token, token);
        expect(restored.timestamp!.reservedSize, token.length + 32);
        expect(
          () => builder
              .withTimestamp(
                C2paTimestampConfig.callback(
                  callback: (_) async => token,
                  reservedSize: token.length,
                ),
              )
              .toArchive(),
          throwsA(isA<C2paArchiveException>()),
        );
      },
    );

    test('stapled malformed OCSP takes precedence over fetching', () async {
      var transportCalls = 0;
      final manifest = _addUnprotectedHeader(trustedManifest, 'rVals', {
        'ocspVals': [
          Uint8List.fromList([0x30, 0x00]),
        ],
      });
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(manifest),
        context: C2paContext(
          settings: const C2paSettings(
            allowNetworkAccess: true,
            enableOcspFetch: true,
          ),
          trust: C2paTrustConfiguration(
            trustAnchors: [certificates.root],
            evaluationTime: DateTime.utc(2027),
          ),
          ocspTransport: (endpoint, request) async {
            transportCalls++;
            return Uint8List.fromList([0x30, 0x00]);
          },
        ),
      );

      expect(
        _codes(reader),
        contains(ValidationCode.signingCredentialOcspUnknown.value),
      );
      expect(transportCalls, 0);
    });

    test(
      'Builder staples cached OCSP without implicit network access',
      () async {
        var transportCalls = 0;
        final manifest =
            await _builder(
              signer,
              [certificates.leaf, certificates.intermediate],
              context: C2paContext(
                signer: signer,
                settings: const C2paSettings(
                  allowNetworkAccess: true,
                  enableOcspFetch: true,
                ),
                ocspTransport: (endpoint, request) async {
                  transportCalls++;
                  return Uint8List(0);
                },
              ),
            ).withCachedOcspResponses([
              Uint8List.fromList([0x30, 0x00]),
            ]).build();
        expect(transportCalls, 0);

        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(manifest),
          context: C2paContext(
            settings: const C2paSettings(
              allowNetworkAccess: true,
              enableOcspFetch: true,
            ),
            trust: C2paTrustConfiguration(
              trustAnchors: [certificates.root],
              evaluationTime: DateTime.utc(2027),
            ),
            ocspTransport: (endpoint, request) async {
              transportCalls++;
              return Uint8List(0);
            },
          ),
        );
        expect(transportCalls, 0);
        expect(
          _codes(reader),
          contains(ValidationCode.signingCredentialOcspUnknown.value),
        );
        expect(reader.activeManifest!.signatureInfo!.revocationStatus, isNull);
      },
    );

    test('maps stapled OCSP good, revoked, and unknown exactly', () async {
      for (final status in OcspCertStatus.values) {
        final response = await _ocspResponse(
          algorithm: tsaAlgorithm,
          signerKey: ocspIssuerKey,
          signer: ocspIssuer,
          target: ocspSignerCertificate,
          issuer: ocspIssuer,
          status: status,
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(
            _addUnprotectedHeader(ocspManifest, 'rVals', {
              'ocspVals': [response],
            }),
          ),
          context: C2paContext(
            trust: C2paTrustConfiguration(
              trustAnchors: [ocspIssuer.der],
              evaluationTime: DateTime.utc(2027, 1, 2, 12),
            ),
          ),
        );
        final codes = _codes(reader);

        switch (status) {
          case OcspCertStatus.good:
            expect(
              codes,
              contains(ValidationCode.signingCredentialNotRevoked.value),
            );
            expect(
              reader.activeManifest!.signatureInfo!.revocationStatus,
              isTrue,
            );
          case OcspCertStatus.revoked:
            expect(
              codes,
              contains(ValidationCode.signingCredentialRevoked.value),
            );
            expect(
              reader.activeManifest!.signatureInfo!.revocationStatus,
              isFalse,
            );
          case OcspCertStatus.unknown:
            expect(
              codes,
              contains(ValidationCode.signingCredentialOcspUnknown.value),
            );
            expect(
              reader.activeManifest!.signatureInfo!.revocationStatus,
              isNull,
            );
        }
      }
    });

    test('reports skipped OCSP when network fetching is disabled', () async {
      final reader = await _read(
        trustedManifest,
        trust: C2paTrustConfiguration(
          trustAnchors: [certificates.root],
          evaluationTime: DateTime.utc(2027),
        ),
      );

      expect(
        _codes(reader),
        contains(ValidationCode.signingCredentialOcspSkipped.value),
      );
    });

    test('maps enabled OCSP transport failure to inaccessible', () async {
      var transportCalls = 0;
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(ocspManifest),
        context: C2paContext(
          settings: const C2paSettings(
            allowNetworkAccess: true,
            enableOcspFetch: true,
          ),
          trust: C2paTrustConfiguration(
            trustAnchors: [ocspIssuer.der],
            evaluationTime: DateTime.utc(2027, 1, 2, 12),
          ),
          ocspTransport: (endpoint, request) async {
            transportCalls++;
            throw StateError('offline');
          },
        ),
      );

      expect(transportCalls, 1);
      expect(
        _codes(reader),
        contains(ValidationCode.signingCredentialOcspInaccessible.value),
      );
    });
  });
}

Future<Uint8List> _build(C2paSigner signer, List<Uint8List> chain) =>
    _builder(signer, chain).build();

C2paBuilder _builder(
  C2paSigner signer,
  List<Uint8List> chain, {
  C2paContext? context,
}) => C2paBuilder(
  definition: ManifestDefinition(
    label: 'urn:c2pa:x509-test',
    intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
    generatorInfo: ClaimGeneratorInfo(name: 'x509-test', version: '1.0'),
    title: 'X.509 test',
    format: 'application/c2pa',
    instanceId: 'xmp:iid:x509-test',
    assertions: [
      AssertionDefinition.cbor(label: 'org.example.test', data: {'value': 1}),
    ],
  ),
  context: context ?? C2paContext(signer: signer),
  signingAlgorithm: signer.algorithm,
  x5chain: chain,
);

Future<C2paReader> _read(
  Uint8List manifest, {
  required C2paTrustConfiguration trust,
}) => C2paReader.fromSource(
  source: MemoryByteSource(manifest),
  context: C2paContext(trust: trust),
);

Set<String> _codes(C2paReader reader) =>
    reader.validationResults.issues.map((issue) => issue.code).toSet();

Uint8List _addUnprotectedHeader(Uint8List manifest, String key, Object? value) {
  final root = parseJumbf(manifest);
  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    if (node.label == 'c2pa.signature') {
      final payload = (node.children.single as JumbfCborNode).payload;
      final tagged = payload.first == 0xd2;
      final decoded =
          decodeCbor(tagged ? payload.sublist(1) : payload) as List<Object?>;
      final headers = Map<Object?, Object?>.from(decoded[1] as Map)
        ..[key] = value;
      final encoded = encodeCbor([decoded[0], headers, decoded[2], decoded[3]]);
      return JumbfSuperBoxNode(
        description: node.description,
        children: [
          JumbfCborNode(
            tagged ? Uint8List.fromList([0xd2, ...encoded]) : encoded,
          ),
        ],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children.map(rewrite),
    );
  }

  return (rewrite(root) as JumbfSuperBoxNode).encode();
}

Uint8List _timestampSignedBytes(Uint8List manifest) {
  final root = parseJumbf(manifest);
  JumbfSuperBoxNode? signature;
  void visit(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return;
    if (node.label == 'c2pa.signature') signature = node;
    for (final child in node.children) {
      visit(child);
    }
  }

  visit(root);
  final payload = (signature!.children.single as JumbfCborNode).payload;
  final message = CoseSign1.parse(payload);
  return encodeCbor([
    'CounterSignature',
    message.protectedBytes,
    Uint8List(0),
    encodeCbor(message.signature),
  ]);
}

Uint8List _timestampRequestImprint(Uint8List request) {
  for (var index = 0; index + 34 <= request.length; index++) {
    if (request[index] == 0x04 && request[index + 1] == 32) {
      return Uint8List.sublistView(request, index + 2, index + 34);
    }
  }
  throw const FormatException('Timestamp request has no SHA-256 imprint');
}

Future<Uint8List> _timestampToken({
  required crypto.Ed25519 algorithm,
  required crypto.SimpleKeyPair keyPair,
  required Uint8List certificate,
  List<int>? signedBytes,
  List<int>? imprint,
}) async {
  final resolvedImprint =
      imprint ?? await HashAlgorithm.sha256.digest(signedBytes!);
  final tstInfo = _derSequence([
    _derInteger(BigInt.one),
    _derOid('1.2.3.4.5'),
    _derSequence([
      _derAlgorithm('2.16.840.1.101.3.4.2.1'),
      _derOctet(resolvedImprint),
    ]),
    _derInteger(BigInt.from(77)),
    _derTlv(0x18, ascii.encode('20270102030405Z')),
  ]);
  final contentDigest = await HashAlgorithm.sha256.digest(tstInfo);
  final attributes = <List<int>>[
    _derAttribute(CmsOids.contentType, _derOid(CmsOids.tstInfo)),
    _derAttribute(CmsOids.messageDigest, _derOctet(contentDigest)),
    _derAttribute(
      CmsOids.signingTime,
      _derTlv(0x18, ascii.encode('20270102030405Z')),
    ),
  ]..sort(_compareDer);
  final signedAttributes = _derSet(attributes);
  final encodedAttributes = Uint8List.fromList(signedAttributes)..[0] = 0xa0;
  final signature = (await algorithm.sign(
    signedAttributes,
    keyPair: keyPair,
  )).bytes;
  final signerInfo = _derSequence([
    _derInteger(BigInt.from(3)),
    _derTlv(0x80, [1, 2, 3, 4]),
    _derAlgorithm('2.16.840.1.101.3.4.2.1'),
    encodedAttributes,
    _derSequence([_derOid('1.3.101.112')]),
    _derOctet(signature),
  ]);
  final signedData = _derSequence([
    _derInteger(BigInt.from(3)),
    _derSet([_derAlgorithm('2.16.840.1.101.3.4.2.1')]),
    _derSequence([_derOid(CmsOids.tstInfo), _derTlv(0xa0, _derOctet(tstInfo))]),
    _derTlv(0xa0, certificate),
    _derSet([signerInfo]),
  ]);
  return Uint8List.fromList(
    _derSequence([_derOid(CmsOids.signedData), _derTlv(0xa0, signedData)]),
  );
}

Future<Uint8List> _tsaCertificate(
  crypto.Ed25519 algorithm,
  crypto.SimpleKeyPair keyPair,
) async {
  final publicKey = await keyPair.extractPublicKey();
  final signatureAlgorithm = _derSequence([_derOid('1.3.101.112')]);
  final name = _derName('Test TSA');
  final tbs = _derSequence([
    _derTlv(0xa0, _derInteger(BigInt.from(2))),
    _derInteger(BigInt.from(42)),
    signatureAlgorithm,
    name,
    _derSequence([
      _derTlv(0x17, ascii.encode('250101000000Z')),
      _derTlv(0x17, ascii.encode('300101000000Z')),
    ]),
    name,
    _derSequence([signatureAlgorithm, _derBitString(publicKey.bytes)]),
    _derTlv(
      0xa3,
      _derSequence([
        _derExtension(
          '2.5.29.19',
          critical: true,
          value: _derSequence(const []),
        ),
        _derExtension(
          '2.5.29.15',
          critical: true,
          value: _derBitString([0x80], unusedBits: 7),
        ),
        _derExtension(
          '2.5.29.37',
          critical: true,
          value: _derSequence([_derOid(ExtendedKeyUsageOids.timeStamping)]),
        ),
        _derExtension('2.5.29.14', value: _derOctet([1, 2, 3, 4])),
      ]),
    ),
  ]);
  final signature = (await algorithm.sign(tbs, keyPair: keyPair)).bytes;
  return Uint8List.fromList(
    _derSequence([tbs, signatureAlgorithm, _derBitString(signature)]),
  );
}

Future<Uint8List> _testCertificate({
  required crypto.Ed25519 algorithm,
  required String subject,
  required String issuer,
  required crypto.SimpleKeyPair subjectKey,
  required crypto.SimpleKeyPair issuerKey,
  required int serial,
  bool isCa = false,
  String? eku,
  Uri? ocspUrl,
}) async {
  final signatureAlgorithm = _derSequence([_derOid('1.3.101.112')]);
  final publicKey = await subjectKey.extractPublicKey();
  final tbs = _derSequence([
    _derTlv(0xa0, _derInteger(BigInt.from(2))),
    _derInteger(BigInt.from(serial)),
    signatureAlgorithm,
    _derName(issuer),
    _derSequence([
      _derTlv(0x17, ascii.encode('250101000000Z')),
      _derTlv(0x17, ascii.encode('300101000000Z')),
    ]),
    _derName(subject),
    _derSequence([signatureAlgorithm, _derBitString(publicKey.bytes)]),
    _derTlv(
      0xa3,
      _derSequence([
        _derExtension(
          '2.5.29.19',
          critical: true,
          value: _derSequence([
            if (isCa) _derTlv(0x01, [0xff]),
          ]),
        ),
        _derExtension(
          '2.5.29.15',
          critical: true,
          value: _derBitString(
            isCa ? [0x04] : [0x80],
            unusedBits: isCa ? 2 : 7,
          ),
        ),
        if (eku != null)
          _derExtension(
            '2.5.29.37',
            critical: true,
            value: _derSequence([_derOid(eku)]),
          ),
        if (ocspUrl != null)
          _derExtension(
            '1.3.6.1.5.5.7.1.1',
            value: _derSequence([
              _derSequence([
                _derOid('1.3.6.1.5.5.7.48.1'),
                _derTlv(0x86, ascii.encode(ocspUrl.toString())),
              ]),
            ]),
          ),
        _derExtension(
          '2.5.29.14',
          value: _derOctet(List<int>.generate(4, (index) => serial + index)),
        ),
      ]),
    ),
  ]);
  final signature = (await algorithm.sign(tbs, keyPair: issuerKey)).bytes;
  return Uint8List.fromList(
    _derSequence([tbs, signatureAlgorithm, _derBitString(signature)]),
  );
}

Future<Uint8List> _ocspResponse({
  required crypto.Ed25519 algorithm,
  required crypto.SimpleKeyPair signerKey,
  required X509Certificate signer,
  required X509Certificate target,
  required X509Certificate issuer,
  required OcspCertStatus status,
}) async {
  final certId = _derSequence([
    _derAlgorithm('2.16.840.1.101.3.4.2.1'),
    _derOctet(await HashAlgorithm.sha256.digest(issuer.subject.der)),
    _derOctet(await HashAlgorithm.sha256.digest(issuer.subjectPublicKey)),
    _derInteger(target.serialNumber),
  ]);
  final certStatus = switch (status) {
    OcspCertStatus.good => _derTlv(0x80, const []),
    OcspCertStatus.unknown => _derTlv(0x82, const []),
    OcspCertStatus.revoked => _derTlv(0xa1, [
      ..._derTlv(0x18, ascii.encode('20270101000000Z')),
      ..._derTlv(0xa0, _derTlv(0x0a, [1])),
    ]),
  };
  final responderHash = (await crypto.Sha1().hash(signer.subjectPublicKey))
      .bytes;
  final tbs = Uint8List.fromList(
    _derSequence([
      _derTlv(0x82, responderHash),
      _derTlv(0x18, ascii.encode('20270102110000Z')),
      _derSequence([
        _derSequence([
          certId,
          certStatus,
          _derTlv(0x18, ascii.encode('20270102100000Z')),
          _derTlv(0xa0, _derTlv(0x18, ascii.encode('20270103100000Z'))),
        ]),
      ]),
    ]),
  );
  final signature = (await algorithm.sign(tbs, keyPair: signerKey)).bytes;
  final basic = _derSequence([
    tbs,
    _derSequence([_derOid('1.3.101.112')]),
    _derBitString(signature),
  ]);
  return Uint8List.fromList(
    _derSequence([
      _derTlv(0x0a, [0]),
      _derTlv(
        0xa0,
        _derSequence([_derOid(OcspOids.basicResponse), _derOctet(basic)]),
      ),
    ]),
  );
}

List<int> _derAttribute(String oid, List<int> value) => _derSequence([
  _derOid(oid),
  _derSet([value]),
]);

List<int> _derAlgorithm(String oid) =>
    _derSequence([_derOid(oid), _derTlv(0x05, const [])]);

List<int> _derExtension(
  String oid, {
  bool critical = false,
  required List<int> value,
}) => _derSequence([
  _derOid(oid),
  if (critical) _derTlv(0x01, [0xff]),
  _derOctet(value),
]);

List<int> _derName(String value) => _derSequence([
  _derSet([
    _derSequence([_derOid('2.5.4.3'), _derTlv(0x0c, utf8.encode(value))]),
  ]),
]);

List<int> _derSequence(List<List<int>> values) =>
    _derTlv(0x30, values.expand((value) => value).toList());

List<int> _derSet(List<List<int>> values) =>
    _derTlv(0x31, values.expand((value) => value).toList());

List<int> _derInteger(BigInt value) {
  final bytes = <int>[];
  var remaining = value;
  do {
    bytes.insert(0, (remaining & BigInt.from(0xff)).toInt());
    remaining >>= 8;
  } while (remaining != BigInt.zero);
  if (bytes.first & 0x80 != 0) bytes.insert(0, 0);
  return _derTlv(0x02, bytes);
}

List<int> _derOctet(List<int> value) => _derTlv(0x04, value);

List<int> _derBitString(List<int> value, {int unusedBits = 0}) =>
    _derTlv(0x03, [unusedBits, ...value]);

List<int> _derOid(String oid) {
  final arcs = oid.split('.').map(int.parse).toList();
  final values = <int>[arcs[0] * 40 + arcs[1], ...arcs.skip(2)];
  final output = <int>[];
  for (final original in values) {
    var value = original;
    final encoded = <int>[value & 0x7f];
    value >>= 7;
    while (value != 0) {
      encoded.insert(0, 0x80 | value & 0x7f);
      value >>= 7;
    }
    output.addAll(encoded);
  }
  return _derTlv(0x06, output);
}

List<int> _derTlv(int tag, List<int> content) {
  if (content.length < 128) return [tag, content.length, ...content];
  final length = <int>[];
  var remaining = content.length;
  while (remaining != 0) {
    length.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return [tag, 0x80 | length.length, ...length, ...content];
}

int _compareDer(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    if (left[index] != right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

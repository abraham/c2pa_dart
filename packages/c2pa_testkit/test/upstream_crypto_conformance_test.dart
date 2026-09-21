@TestOn('vm')
library;

import 'dart:convert';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _fixtureRoot = 'test/fixtures/vendor/c2pa-rs-0.90.22/crypto';
const _rawSignatureRoot = '$_fixtureRoot/raw-signature';
const _message = 'some sample content to sign';

void main() {
  group('c2pa-rs raw signature vectors', () {
    for (final vector in const [
      ('ps256', SigningAlgorithm.ps256),
      ('ps384', SigningAlgorithm.ps384),
      ('ps512', SigningAlgorithm.ps512),
      ('es256', SigningAlgorithm.es256),
      ('es384', SigningAlgorithm.es384),
      ('es512', SigningAlgorithm.es512),
      ('ed25519', SigningAlgorithm.ed25519),
    ]) {
      test('verifies ${vector.$1}', () async {
        final publicKeyDer = await loadFixtureBytes(
          '$_rawSignatureRoot/${vector.$1}.pub_key',
        );
        final signature = await loadFixtureBytes(
          '$_rawSignatureRoot/${vector.$1}.raw_sig',
        );
        final certificateChain = _parsePemCertificates(
          await loadFixtureString('$_rawSignatureRoot/${vector.$1}.pub'),
        );

        expect(certificateChain, isNotEmpty);
        expect(
          certificateChain.first.subjectPublicKeyInfoDer,
          publicKeyDer,
          reason: '${vector.$1} .pub and .pub_key must describe the same key',
        );

        expect(
          await _verifyRawSignature(
            vector.$2,
            publicKeyDer,
            certificateChain.first,
            signature,
          ),
          isTrue,
        );
      });
    }
  });

  group('c2pa-rs OCSP vectors', () {
    late X509Certificate certificate;
    late X509Certificate issuer;

    setUpAll(() async {
      final chain = _parsePemCertificates(
        await loadFixtureString('$_fixtureRoot/ocsp/ocsp_chain.pem'),
      );
      expect(chain, hasLength(2));
      certificate = chain.singleWhere(
        (candidate) => !(candidate.basicConstraints?.isCa ?? false),
      );
      issuer = chain.singleWhere(
        (candidate) => candidate.basicConstraints?.isCa ?? false,
      );
      expect(certificate.issuer.der, issuer.subject.der);
    });

    for (final vector in const [
      ('good', OcspResultStatus.good, OcspCertStatus.good),
      ('revoked', OcspResultStatus.revoked, OcspCertStatus.revoked),
      ('unknown', OcspResultStatus.unknown, OcspCertStatus.unknown),
    ]) {
      test('parses and validates ${vector.$1}', () async {
        final der = await loadFixtureBytes(
          '$_fixtureRoot/ocsp/response_${vector.$1}.der',
        );
        final parsed = OcspResponse.parse(der);

        expect(parsed.responseStatus, OcspResponseStatus.successful);
        expect(parsed.responses, hasLength(1));
        expect(parsed.responses.single.status, vector.$3);
        expect(parsed.producedAt, isNotNull);

        final evaluationTime = parsed.producedAt!;
        final verified = await verifyOcspResponse(
          der,
          certificate: certificate,
          issuer: issuer,
          trustPolicy: TrustPolicy(
            trustAnchors: [issuer.der],
            evaluationTime: evaluationTime,
          ),
          evaluationTime: evaluationTime,
        );
        expect(
          verified.status,
          vector.$2,
          reason: verified.issues
              .map((issue) => '${issue.code.name}: ${issue.message}')
              .join('\n'),
        );
      });
    }
  });

  group('official trust-list snapshots', () {
    for (final path in const [
      'test/fixtures/vendor/c2pa-conformance-public/trust/C2PA-TRUST-LIST.pem',
      'test/fixtures/vendor/c2pa-conformance-public/trust/C2PA-TSA-TRUST-LIST.pem',
    ]) {
      test('parses every certificate in $path', () async {
        final certificates = _parsePemCertificates(
          await loadFixtureString(path),
        );

        expect(certificates, isNotEmpty);
        for (final certificate in certificates) {
          expect(certificate.der, isNotEmpty);
          expect(certificate.subject.der, isNotEmpty);
          expect(certificate.subjectPublicKeyInfoDer, isNotEmpty);
          expect(certificate.notBefore.isBefore(certificate.notAfter), isTrue);
        }
      });
    }
  });
}

Future<bool> _verifyRawSignature(
  SigningAlgorithm algorithm,
  List<int> publicKeyDer,
  X509Certificate certificate,
  List<int> signature,
) async {
  final message = utf8.encode(_message);
  return switch (algorithm) {
    SigningAlgorithm.ps256 ||
    SigningAlgorithm.ps384 ||
    SigningAlgorithm.ps512 => WebCryptoRsaPssVerificationBackend(
      algorithm,
      await importRsaPssPublicKeySpki(algorithm, publicKeyDer),
    ).verify(algorithm, message, signature),
    SigningAlgorithm.es256 ||
    SigningAlgorithm.es384 ||
    SigningAlgorithm.es512 => WebCryptoEcdsaVerificationBackend(
      algorithm,
      await importEcdsaPublicKeySpki(algorithm, publicKeyDer),
    ).verify(algorithm, message, signature),
    SigningAlgorithm.ed25519 => verifySignatureWithCertificatePublicKey(
      certificate: certificate,
      signatureAlgorithm: X509AlgorithmIdentifier('1.3.101.112', null),
      data: message,
      signature: signature,
    ),
  };
}

List<X509Certificate> _parsePemCertificates(String pem) {
  final matches = RegExp(
    r'-----BEGIN CERTIFICATE-----\s*'
    r'([A-Za-z0-9+/=\s]+?)'
    r'\s*-----END CERTIFICATE-----',
    multiLine: true,
  ).allMatches(pem);
  return matches
      .map((match) {
        final encoded = match.group(1)!.replaceAll(RegExp(r'\s'), '');
        return X509Certificate.parse(base64Decode(encoded));
      })
      .toList(growable: false);
}

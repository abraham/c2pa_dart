@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

import 'trust_list_fixtures.dart';

void main() {
  late Uint8List signerDer;
  late Uint8List tsaDer;

  setUpAll(() {
    signerDer = parsePemCertificateBundle(signerTrustPem).single;
    tsaDer = parsePemCertificateBundle(tsaTrustPem).single;
  });

  group('PEM certificate bundles', () {
    test('parses multiple blocks with CRLF and surrounding whitespace', () {
      final bundle =
          '\r\n${signerTrustPem.replaceAll('\n', '\r\n')}\r\n'
          '${tsaTrustPem.replaceAll('\n', '\r\n')}\r\n';
      final parsed = parsePemCertificateBundle(bundle);

      expect(parsed, hasLength(2));
      expect(parsed[0], signerDer);
      expect(parsed[1], tsaDer);
    });

    test('encodes deterministic canonical PEM and round trips', () {
      final encoded = encodePemCertificateBundle([signerDer, tsaDer]);

      expect(encoded, isNot(contains('\r')));
      expect(
        encoded.split('\n').where((line) => !line.startsWith('-----')),
        everyElement(
          predicate<String>(
            (line) => line.isEmpty || line.length <= 64,
            'a base64 line no longer than 64 columns',
          ),
        ),
      );
      expect(parsePemCertificateBundle(encoded), [signerDer, tsaDer]);
    });

    test('rejects malformed markers, text, base64, and certificate DER', () {
      expect(
        () => parsePemCertificateBundle(
          signerTrustPem.replaceFirst(
            '-----END CERTIFICATE-----',
            '-----END OTHER-----',
          ),
        ),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle('metadata\n$signerTrustPem'),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle(
          '-----BEGIN CERTIFICATE-----\n%%%\n'
          '-----END CERTIFICATE-----\n',
        ),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle(
          '-----BEGIN CERTIFICATE-----\n${base64.encode([1, 2, 3])}\n'
          '-----END CERTIFICATE-----\n',
        ),
        throwsFormatException,
      );
      expect(
        () =>
            parsePemCertificateBundle(signerTrustPem.replaceFirst('\n', '\r')),
        throwsFormatException,
      );
    });

    test('rejects or ignores duplicates explicitly', () {
      final duplicate = '$signerTrustPem\n$signerTrustPem';
      expect(() => parsePemCertificateBundle(duplicate), throwsFormatException);
      expect(
        parsePemCertificateBundle(
          duplicate,
          duplicateHandling: PemDuplicateCertificateHandling.ignore,
        ),
        [signerDer],
      );
      expect(
        encodePemCertificateBundle([
          signerDer,
          signerDer,
        ], duplicateHandling: PemDuplicateCertificateHandling.ignore),
        signerTrustPem,
      );
    });

    test('enforces certificate, count, and bundle byte limits', () {
      expect(
        () => parsePemCertificateBundle(
          signerTrustPem,
          limits: const PemCertificateLimits(maxCertificateBytes: 16),
        ),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle(
          '$signerTrustPem$tsaTrustPem',
          limits: const PemCertificateLimits(maxCertificates: 1),
        ),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle(
          signerTrustPem,
          limits: const PemCertificateLimits(maxBundleBytes: 16),
        ),
        throwsFormatException,
      );
      expect(
        () => parsePemCertificateBundle(
          signerTrustPem,
          limits: const PemCertificateLimits(maxCertificates: 0),
        ),
        throwsFormatException,
      );
    });
  });

  group('trust policy ingestion', () {
    test('keeps signer and TSA anchors separate and deduplicated', () async {
      final policies = await buildC2paTrustPolicies(
        signerPemBundles: [signerTrustPem, signerTrustPem],
        tsaPemBundles: [tsaTrustPem],
        evaluationTime: DateTime.utc(2026),
      );

      expect(policies.signer.trustAnchors, [signerDer]);
      expect(policies.tsa.trustAnchors, [tsaDer]);
      final exposed = policies.signer.trustAnchors;
      exposed.single[0] ^= 0xff;
      expect(policies.signer.trustAnchors.single, signerDer);
    });

    test('requires explicit deterministic platform merge precedence', () async {
      final provider = _Provider([tsaDer, signerDer]);
      await expectLater(
        () => buildC2paTrustPolicies(
          signerPemBundles: [signerTrustPem],
          tsaPemBundles: [tsaTrustPem],
          signerPlatformProvider: provider,
        ),
        throwsArgumentError,
      );

      final pemFirst = await buildC2paTrustPolicies(
        signerPemBundles: [signerTrustPem],
        tsaPemBundles: [tsaTrustPem],
        signerPlatformProvider: provider,
        platformMergePrecedence: TrustAnchorMergePrecedence.pemThenPlatform,
      );
      expect(pemFirst.signer.trustAnchors, [signerDer, tsaDer]);

      final platformFirst = await buildC2paTrustPolicies(
        signerPemBundles: [signerTrustPem],
        tsaPemBundles: [tsaTrustPem],
        signerPlatformProvider: provider,
        platformMergePrecedence: TrustAnchorMergePrecedence.platformThenPem,
      );
      expect(platformFirst.signer.trustAnchors, [tsaDer, signerDer]);
    });

    test('wraps provider failures without falling back implicitly', () async {
      await expectLater(
        () => buildC2paTrustPolicies(
          signerPemBundles: [signerTrustPem],
          tsaPemBundles: [tsaTrustPem],
          tsaPlatformProvider: _FailingProvider(),
          platformMergePrecedence: TrustAnchorMergePrecedence.pemThenPlatform,
        ),
        throwsA(
          isA<TrustAnchorProviderException>().having(
            (error) => error.cause,
            'cause',
            isA<StateError>(),
          ),
        ),
      );
    });

    test('rejects empty signer or TSA anchor sets', () async {
      await expectLater(
        () => buildC2paTrustPolicies(
          signerPemBundles: const [],
          tsaPemBundles: [tsaTrustPem],
        ),
        throwsFormatException,
      );
    });
  });
}

final class _Provider implements PlatformTrustAnchorProvider {
  const _Provider(this.anchors);

  final List<Uint8List> anchors;

  @override
  Future<Iterable<List<int>>> loadTrustAnchors() async => anchors;
}

final class _FailingProvider implements PlatformTrustAnchorProvider {
  @override
  Future<Iterable<List<int>>> loadTrustAnchors() async {
    throw StateError('platform trust is unavailable');
  }
}

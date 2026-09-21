import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

void main() {
  group('COSE orchestration', () {
    test('routes every supported algorithm to injected backends', () async {
      for (final algorithm in SigningAlgorithm.values) {
        final signatureLength = algorithm.p1363SignatureLength ?? 17;
        final backend = _FakeBackend(
          signature: List<int>.filled(signatureLength, algorithm.index + 1),
        );
        final signer = CoseSigner(backends: {algorithm: backend});
        final encoded = await signer.sign(
          algorithm: algorithm,
          payload: [1, 2, 3],
          externalAad: [4, 5],
        );
        final message = CoseSign1.parse(encoded);

        expect(backend.signedAlgorithm, algorithm);
        expect(
          backend.signedData,
          message.signatureStructure(externalAad: Uint8List.fromList([4, 5])),
        );

        final verifier = CoseVerifier(backends: {algorithm: backend});
        expect(
          await verifier.verify(
            message,
            payload: [1, 2, 3],
            externalAad: [4, 5],
          ),
          isTrue,
        );
        expect(backend.verifiedAlgorithm, algorithm);
        expect(backend.verifiedSignature, backend.signature);
      }
    });

    test('preserves caller headers and encodes deterministically', () async {
      final backend = _FakeBackend(signature: List<int>.filled(64, 9));
      final protected = CoseHeaders({
        CoseHeaderLabel.algorithm: -7,
        CoseHeaderLabel.contentType: 'application/c2pa',
        CoseHeaderLabel.custom(100): 'custom protected',
      });
      final unprotected = CoseHeaders({
        CoseHeaderLabel.x509Chain: Uint8List.fromList([1, 2, 3]),
        CoseHeaderLabel.custom(101): 'custom unprotected',
      });
      final signer = CoseSigner(backends: {SigningAlgorithm.es256: backend});

      final first = await signer.sign(
        algorithm: SigningAlgorithm.es256,
        payload: [4, 5, 6],
        protectedHeaders: protected,
        unprotectedHeaders: unprotected,
      );
      final second = await signer.sign(
        algorithm: SigningAlgorithm.es256,
        payload: [4, 5, 6],
        protectedHeaders: protected,
        unprotectedHeaders: unprotected,
      );
      final parsed = CoseSign1.parse(first);

      expect(first, second);
      expect(
        parsed.protectedHeaders[CoseHeaderLabel.contentType],
        'application/c2pa',
      );
      expect(
        parsed.protectedHeaders[CoseHeaderLabel.custom(100)],
        'custom protected',
      );
      expect(parsed.unprotectedHeaders[CoseHeaderLabel.x509Chain], [1, 2, 3]);
      expect(
        parsed.unprotectedHeaders[CoseHeaderLabel.custom(101)],
        'custom unprotected',
      );
    });

    test('supports detached payloads and exact Sig_structure bytes', () async {
      final backend = _FakeBackend(signature: List<int>.filled(64, 1));
      final signer = CoseSigner(backends: {SigningAlgorithm.es256: backend});
      final encoded = await signer.sign(
        algorithm: SigningAlgorithm.es256,
        payload: [7, 8],
        detached: true,
      );
      final message = CoseSign1.parse(encoded);

      expect(message.payload, isNull);
      expect(
        backend.signedData,
        message.signatureStructure(detachedPayload: Uint8List.fromList([7, 8])),
      );
      expect(
        await CoseVerifier(backends: {SigningAlgorithm.es256: backend})
            .verify(message, payload: [7, 8]),
        isTrue,
      );
    });

    test('rejects protected algorithm mismatch', () async {
      final signer = CoseSigner(
        backends: {
          SigningAlgorithm.es256: _FakeBackend(
            signature: List<int>.filled(64, 1),
          ),
        },
      );
      expect(
        () => signer.sign(
          algorithm: SigningAlgorithm.es256,
          payload: [1],
          protectedHeaders: CoseHeaders({
            CoseHeaderLabel.algorithm: SigningAlgorithm.es384.coseId,
          }),
        ),
        throwsA(isA<AlgorithmMismatchException>()),
      );

      final message = _message(SigningAlgorithm.es256, 64);
      expect(
        () =>
            CoseVerifier(
              backends: {
                SigningAlgorithm.es256: _FakeBackend(
                  signature: List<int>.filled(64, 1),
                ),
              },
            ).verify(
              message,
              payload: [1],
              expectedAlgorithm: SigningAlgorithm.es384,
            ),
        throwsA(isA<AlgorithmMismatchException>()),
      );
    });

    test('rejects mismatched embedded payload', () {
      final message = _message(SigningAlgorithm.ps256, 8);
      expect(
        () => CoseVerifier(
          backends: {
            SigningAlgorithm.ps256: _FakeBackend(
              signature: List<int>.filled(8, 1),
            ),
          },
        ).verify(message, payload: [2]),
        throwsA(isA<PayloadMismatchException>()),
      );
    });

    test('rejects unknown protected algorithm', () {
      final message = CoseSign1(
        protectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -999}),
        payload: Uint8List.fromList([1]),
        signature: Uint8List(1),
      );
      expect(
        () => CoseVerifier().verify(message, payload: [1]),
        throwsA(
          isA<UnknownCoseAlgorithmException>().having(
            (error) => error.coseId,
            'coseId',
            -999,
          ),
        ),
      );
    });

    test('rejects malformed ECDSA widths before backend invocation', () async {
      for (final algorithm in [
        SigningAlgorithm.es256,
        SigningAlgorithm.es384,
        SigningAlgorithm.es512,
      ]) {
        final expected = algorithm.p1363SignatureLength!;
        final signingBackend = _FakeBackend(
          signature: List<int>.filled(expected - 1, 1),
        );
        await expectLater(
          () =>
              CoseSigner(backends: {algorithm: signingBackend})
                  .sign(algorithm: algorithm, payload: [1]),
          throwsA(isA<InvalidSignatureWidthException>()),
        );

        final verificationBackend = _FakeBackend(
          signature: List<int>.filled(expected, 1),
        );
        await expectLater(
          () =>
              CoseVerifier(backends: {algorithm: verificationBackend})
                  .verify(_message(algorithm, expected + 1), payload: [1]),
          throwsA(isA<InvalidSignatureWidthException>()),
        );
        expect(verificationBackend.verifiedAlgorithm, isNull);
      }
    });

    test('reports unavailable RSA and ECDSA backends explicitly', () async {
      for (final algorithm in [
        SigningAlgorithm.es256,
        SigningAlgorithm.es384,
        SigningAlgorithm.es512,
        SigningAlgorithm.ps256,
        SigningAlgorithm.ps384,
        SigningAlgorithm.ps512,
      ]) {
        await expectLater(
          () => CoseSigner().sign(algorithm: algorithm, payload: [1]),
          throwsA(isA<UnsupportedBackendException>()),
        );
        await expectLater(
          () => CoseVerifier().verify(
            _message(algorithm, algorithm.p1363SignatureLength ?? 8),
            payload: [1],
          ),
          throwsA(isA<UnsupportedBackendException>()),
        );
      }
    });
  });

  group('Ed25519 backend', () {
    test('signs, verifies, and rejects tampering', () async {
      final implementation = Ed25519();
      final keyPair = await (await implementation.newKeyPairFromSeed(
        List<int>.generate(32, (index) => index),
      )).extract();
      final signingBackend = Ed25519SigningBackend(keyPair);
      final verificationBackend = Ed25519VerificationBackend(keyPair.publicKey);
      final encoded =
          await CoseSigner(backends: {SigningAlgorithm.ed25519: signingBackend})
              .sign(
                algorithm: SigningAlgorithm.ed25519,
                payload: [1, 2, 3],
                externalAad: [4, 5],
              );
      final verifier = CoseVerifier(
        backends: {SigningAlgorithm.ed25519: verificationBackend},
      );

      expect(
        await verifier.verifyEncoded(
          encoded,
          payload: [1, 2, 3],
          externalAad: [4, 5],
        ),
        isTrue,
      );
      expect(
        () => verifier.verifyEncoded(
          encoded,
          payload: [1, 2, 4],
          externalAad: [4, 5],
        ),
        throwsA(isA<PayloadMismatchException>()),
      );
      expect(
        await verifier.verifyEncoded(
          encoded,
          payload: [1, 2, 3],
          externalAad: [4, 6],
        ),
        isFalse,
      );

      final parsed = CoseSign1.parse(encoded);
      final tamperedSignature = parsed.signature..[0] ^= 1;
      final tampered = CoseSign1(
        protectedHeaders: parsed.protectedHeaders,
        unprotectedHeaders: parsed.unprotectedHeaders,
        payload: parsed.payload,
        signature: tamperedSignature,
        tagged: parsed.tagged,
      );
      expect(await verifier.verify(tampered, payload: [1, 2, 3]), isFalse);
    });

    test('strictly validates key types and lengths', () {
      final validPublic = SimplePublicKey(
        List<int>.filled(32, 1),
        type: KeyPairType.ed25519,
      );
      expect(
        () => Ed25519VerificationBackend(
          SimplePublicKey(List<int>.filled(31, 1), type: KeyPairType.ed25519),
        ),
        throwsArgumentError,
      );
      expect(
        () => Ed25519VerificationBackend(
          SimplePublicKey(List<int>.filled(32, 1), type: KeyPairType.x25519),
        ),
        throwsArgumentError,
      );
      expect(
        () => Ed25519SigningBackend(
          SimpleKeyPairData(
            List<int>.filled(31, 1),
            publicKey: validPublic,
            type: KeyPairType.ed25519,
          ),
        ),
        throwsArgumentError,
      );
      expect(
        () => Ed25519SigningBackend(
          SimpleKeyPairData(
            List<int>.filled(32, 1),
            publicKey: validPublic,
            type: KeyPairType.x25519,
          ),
        ),
        throwsArgumentError,
      );
    });
  });
}

CoseSign1 _message(SigningAlgorithm algorithm, int signatureLength) =>
    CoseSign1(
      protectedHeaders: CoseHeaders({
        CoseHeaderLabel.algorithm: algorithm.coseId,
      }),
      payload: Uint8List.fromList([1]),
      signature: Uint8List.fromList(List<int>.filled(signatureLength, 1)),
    );

final class _FakeBackend
    implements CoseSigningBackend, CoseVerificationBackend {
  _FakeBackend({required this.signature});

  final List<int> signature;
  SigningAlgorithm? signedAlgorithm;
  List<int>? signedData;
  SigningAlgorithm? verifiedAlgorithm;
  List<int>? verifiedData;
  List<int>? verifiedSignature;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    signedAlgorithm = algorithm;
    signedData = List<int>.from(data);
    return List<int>.from(signature);
  }

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) async {
    verifiedAlgorithm = algorithm;
    verifiedData = List<int>.from(data);
    verifiedSignature = List<int>.from(signature);
    return true;
  }
}

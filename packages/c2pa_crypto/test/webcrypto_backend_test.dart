@TestOn('vm || browser')
library;

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';
import 'package:webcrypto/webcrypto.dart' as webcrypto;

void main() {
  group('WebCrypto ECDSA backends', () {
    for (final algorithm in [
      SigningAlgorithm.es256,
      SigningAlgorithm.es384,
      SigningAlgorithm.es512,
    ]) {
      test(
        '${algorithm.name} generated-key sign, verify, and tamper',
        () async {
          final generated = await generateEcdsaKeyPair(algorithm);
          final privateBytes = await generated.privateKey.exportPkcs8Key();
          final publicBytes = await generated.publicKey.exportSpkiKey();
          final privateKey = await importEcdsaPrivateKeyPkcs8(
            algorithm,
            privateBytes,
          );
          final publicKey = await importEcdsaPublicKeySpki(
            algorithm,
            publicBytes,
          );
          final signerBackend = WebCryptoEcdsaSigningBackend(
            algorithm,
            privateKey,
          );
          final verifierBackend = WebCryptoEcdsaVerificationBackend(
            algorithm,
            publicKey,
          );
          final encoded = await CoseSigner(backends: {algorithm: signerBackend})
              .sign(
                algorithm: algorithm,
                payload: [1, 2, 3, algorithm.index],
                externalAad: [9, 8],
              );
          final message = CoseSign1.parse(encoded);
          final verifier = CoseVerifier(backends: {algorithm: verifierBackend});

          expect(message.signature, hasLength(algorithm.p1363SignatureLength));
          expect(
            await verifier.verify(
              message,
              payload: [1, 2, 3, algorithm.index],
              externalAad: [9, 8],
            ),
            isTrue,
          );
          expect(
            await verifier.verify(
              message,
              payload: [1, 2, 3, algorithm.index],
              externalAad: [9, 7],
            ),
            isFalse,
          );

          final tamperedSignature = message.signature..[0] ^= 1;
          final tampered = CoseSign1(
            protectedHeaders: message.protectedHeaders,
            unprotectedHeaders: message.unprotectedHeaders,
            payload: message.payload,
            signature: tamperedSignature,
            tagged: message.tagged,
          );
          expect(
            await verifier.verify(
              tampered,
              payload: [1, 2, 3, algorithm.index],
              externalAad: [9, 8],
            ),
            isFalse,
          );
        },
      );
    }

    test('rejects curve and configured algorithm mismatches', () async {
      final p256 = await generateEcdsaKeyPair(SigningAlgorithm.es256);
      final backend = WebCryptoEcdsaSigningBackend(
        SigningAlgorithm.es384,
        p256.privateKey,
      );
      await expectLater(
        () => backend.sign(SigningAlgorithm.es384, [1]),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      await expectLater(
        () => WebCryptoEcdsaSigningBackend(
          SigningAlgorithm.es256,
          p256.privateKey,
        ).sign(SigningAlgorithm.es384, [1]),
        throwsA(isA<AlgorithmMismatchException>()),
      );
    });

    test('strict imports reject malformed and mismatched keys', () async {
      await expectLater(
        () => importEcdsaPrivateKeyPkcs8(SigningAlgorithm.es256, [1, 2, 3]),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      final p256 = await generateEcdsaKeyPair(SigningAlgorithm.es256);
      final spki = await p256.publicKey.exportSpkiKey();
      await expectLater(
        () => importEcdsaPublicKeySpki(SigningAlgorithm.es384, spki),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      expect(
        () => importEcdsaPublicKeySpki(SigningAlgorithm.es256, [256]),
        throwsArgumentError,
      );
    });
  });

  group('WebCrypto RSA-PSS backends', () {
    for (final algorithm in [
      SigningAlgorithm.ps256,
      SigningAlgorithm.ps384,
      SigningAlgorithm.ps512,
    ]) {
      test(
        '${algorithm.name} generated-key sign, verify, and tamper',
        () async {
          final generated = await generateRsaPssKeyPair(algorithm);
          final privateBytes = await generated.privateKey.exportPkcs8Key();
          final publicBytes = await generated.publicKey.exportSpkiKey();
          final privateKey = await importRsaPssPrivateKeyPkcs8(
            algorithm,
            privateBytes,
          );
          final publicKey = await importRsaPssPublicKeySpki(
            algorithm,
            publicBytes,
          );
          final signerBackend = WebCryptoRsaPssSigningBackend(
            algorithm,
            privateKey,
          );
          final verifierBackend = WebCryptoRsaPssVerificationBackend(
            algorithm,
            publicKey,
          );
          final encoded = await CoseSigner(backends: {algorithm: signerBackend})
              .sign(
                algorithm: algorithm,
                payload: [4, 5, 6, algorithm.index],
                externalAad: [7, 8],
              );
          final message = CoseSign1.parse(encoded);
          final verifier = CoseVerifier(backends: {algorithm: verifierBackend});

          expect(
            await verifier.verify(
              message,
              payload: [4, 5, 6, algorithm.index],
              externalAad: [7, 8],
            ),
            isTrue,
          );
          expect(
            await verifier.verify(
              message,
              payload: [4, 5, 6, algorithm.index],
              externalAad: [7, 9],
            ),
            isFalse,
          );

          final tamperedSignature = message.signature..[0] ^= 1;
          final tampered = CoseSign1(
            protectedHeaders: message.protectedHeaders,
            unprotectedHeaders: message.unprotectedHeaders,
            payload: message.payload,
            signature: tamperedSignature,
            tagged: message.tagged,
          );
          expect(
            await verifier.verify(
              tampered,
              payload: [4, 5, 6, algorithm.index],
              externalAad: [7, 8],
            ),
            isFalse,
          );
        },
      );
    }

    test('rejects key and configured algorithm mismatches', () async {
      final ps256 = await generateRsaPssKeyPair(SigningAlgorithm.ps256);
      final backend = WebCryptoRsaPssVerificationBackend(
        SigningAlgorithm.ps384,
        ps256.publicKey,
      );
      await expectLater(
        () => backend.verify(SigningAlgorithm.ps384, [1], [2]),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      await expectLater(
        () => WebCryptoRsaPssSigningBackend(
          SigningAlgorithm.ps256,
          ps256.privateKey,
        ).sign(SigningAlgorithm.ps512, [1]),
        throwsA(isA<AlgorithmMismatchException>()),
      );
    });

    test('strict imports reject malformed keys and wrong families', () async {
      await expectLater(
        () => importRsaPssPublicKeySpki(SigningAlgorithm.ps256, [1, 2, 3]),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      expect(
        () => importRsaPssPrivateKeyPkcs8(SigningAlgorithm.ps256, [-1]),
        throwsArgumentError,
      );
      expect(
        () => generateRsaPssKeyPair(SigningAlgorithm.es256),
        throwsA(isA<UnsupportedBackendException>()),
      );
      expect(
        () => generateEcdsaKeyPair(SigningAlgorithm.ps256),
        throwsA(isA<UnsupportedBackendException>()),
      );
    });

    test('imports generic rsaEncryption SPKI for every PSS hash', () async {
      final generic = await webcrypto.RsassaPkcs1V15PrivateKey.generateKey(
        2048,
        BigInt.from(65537),
        webcrypto.Hash.sha256,
      );
      final spki = await generic.publicKey.exportSpkiKey();
      final pkcs8 = await generic.privateKey.exportPkcs8Key();
      for (final entry in {
        SigningAlgorithm.ps256: (webcrypto.Hash.sha256, 32),
        SigningAlgorithm.ps384: (webcrypto.Hash.sha384, 48),
        SigningAlgorithm.ps512: (webcrypto.Hash.sha512, 64),
      }.entries) {
        final publicKey = await importRsaPssPublicKeySpki(entry.key, spki);
        final privateKey = await webcrypto.RsaPssPrivateKey.importPkcs8Key(
          pkcs8,
          entry.value.$1,
        );
        final signature = await privateKey.signBytes(const [
          1,
          2,
          3,
        ], entry.value.$2);
        expect(
          await publicKey.verifyBytes(signature, const [
            1,
            2,
            3,
          ], entry.value.$2),
          isTrue,
        );
      }
    });

    test('uses digest-length PSS salts', () async {
      for (final entry in {
        SigningAlgorithm.ps256: 32,
        SigningAlgorithm.ps384: 48,
        SigningAlgorithm.ps512: 64,
      }.entries) {
        final keys = await generateRsaPssKeyPair(entry.key);
        final backend = WebCryptoRsaPssSigningBackend(
          entry.key,
          keys.privateKey,
        );
        final signature = await backend.sign(entry.key, [1, 2, 3]);
        expect(
          await keys.publicKey.verifyBytes(signature, [1, 2, 3], entry.value),
          isTrue,
        );
        expect(
          await keys.publicKey.verifyBytes(signature, [
            1,
            2,
            3,
          ], entry.value - 1),
          isFalse,
        );
      }
    });
  });

  test('P-521 unavailability is surfaced explicitly', () async {
    try {
      final keys = await generateEcdsaKeyPair(SigningAlgorithm.es512);
      expect(keys.publicKey, isA<webcrypto.EcdsaPublicKey>());
    } on PlatformAlgorithmUnavailableException catch (error) {
      expect(error.algorithm, SigningAlgorithm.es512);
      expect(error.message, contains('unavailable'));
    }
  });
}

@TestOn('vm || browser')
library;

import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

void main() {
  group('PointyCastle ECDSA backends', () {
    for (final algorithm in [
      SigningAlgorithm.es256,
      SigningAlgorithm.es384,
      SigningAlgorithm.es512,
    ]) {
      test(
        '${algorithm.name} generated-key sign, verify, and tamper',
        () async {
          final generated = await generateEcdsaKeyPair(algorithm);
          final privateBytes = encodeEcdsaPrivateKeyPkcs8(
            generated.privateKey,
            algorithm,
          );
          final publicBytes = encodeEcdsaPublicKeySpki(
            generated.publicKey,
            algorithm,
          );
          final privateKey = await importEcdsaPrivateKeyPkcs8(
            algorithm,
            privateBytes,
          );
          final publicKey = await importEcdsaPublicKeySpki(
            algorithm,
            publicBytes,
          );
          final signerBackend = EcdsaSigningBackend(algorithm, privateKey);
          final verifierBackend = EcdsaVerificationBackend(
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
      final backend = EcdsaSigningBackend(
        SigningAlgorithm.es384,
        p256.privateKey,
      );
      await expectLater(
        () => backend.sign(SigningAlgorithm.es384, [1]),
        throwsA(isA<InvalidKeyForAlgorithmException>()),
      );
      await expectLater(
        () => EcdsaSigningBackend(
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
      final spki = encodeEcdsaPublicKeySpki(
        p256.publicKey,
        SigningAlgorithm.es256,
      );
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

  group('PointyCastle RSA-PSS backends', () {
    for (final algorithm in [
      SigningAlgorithm.ps256,
      SigningAlgorithm.ps384,
      SigningAlgorithm.ps512,
    ]) {
      test(
        '${algorithm.name} generated-key sign, verify, and tamper',
        () async {
          final generated = await generateRsaPssKeyPair(algorithm);
          final privateBytes = encodeRsaPssPrivateKeyPkcs8(
            generated.privateKey,
          );
          final publicBytes = encodeRsaPssPublicKeySpki(generated.publicKey);
          final privateKey = await importRsaPssPrivateKeyPkcs8(
            algorithm,
            privateBytes,
          );
          final publicKey = await importRsaPssPublicKeySpki(
            algorithm,
            publicBytes,
          );
          final signerBackend = RsaPssSigningBackend(algorithm, privateKey);
          final verifierBackend = RsaPssVerificationBackend(
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

    test('rejects configured algorithm mismatches', () async {
      final ps256 = await generateRsaPssKeyPair(SigningAlgorithm.ps256);
      await expectLater(
        () => RsaPssSigningBackend(
          SigningAlgorithm.ps256,
          ps256.privateKey,
        ).sign(SigningAlgorithm.ps512, [1]),
        throwsA(isA<AlgorithmMismatchException>()),
      );
      await expectLater(
        () => RsaPssVerificationBackend(
          SigningAlgorithm.ps256,
          ps256.publicKey,
        ).verify(SigningAlgorithm.ps384, [1], [2]),
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
      final generator = pc.RSAKeyGenerator()
        ..init(
          pc.ParametersWithRandom(
            pc.RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
            _testSecureRandom(),
          ),
        );
      final generic = generator.generateKeyPair();
      final spki = encodeRsaPssPublicKeySpki(generic.publicKey);
      for (final entry in {
        SigningAlgorithm.ps256: (() => pc.SHA256Digest(), 32),
        SigningAlgorithm.ps384: (() => pc.SHA384Digest(), 48),
        SigningAlgorithm.ps512: (() => pc.SHA512Digest(), 64),
      }.entries) {
        final publicKey = await importRsaPssPublicKeySpki(entry.key, spki);
        final digestFactory = entry.value.$1;
        final saltLength = entry.value.$2;
        final signer =
            pc.PSSSigner(pc.RSAEngine(), digestFactory(), digestFactory())
              ..init(
                true,
                pc.ParametersWithSaltConfiguration(
                  pc.PrivateKeyParameter<pc.RSAPrivateKey>(generic.privateKey),
                  _testSecureRandom(),
                  saltLength,
                ),
              );
        final signature = signer.generateSignature(
          Uint8List.fromList(const [1, 2, 3]),
        );
        expect(
          _verifyRsaPss(publicKey, digestFactory, saltLength, const [
            1,
            2,
            3,
          ], signature.bytes),
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
        final backend = RsaPssSigningBackend(entry.key, keys.privateKey);
        final signature = await backend.sign(entry.key, [1, 2, 3]);
        final digestFactory = switch (entry.key) {
          SigningAlgorithm.ps256 => () => pc.SHA256Digest(),
          SigningAlgorithm.ps384 => () => pc.SHA384Digest(),
          SigningAlgorithm.ps512 => () => pc.SHA512Digest(),
          _ => throw StateError('unreachable'),
        };
        expect(
          _verifyRsaPss(keys.publicKey, digestFactory, entry.value, const [
            1,
            2,
            3,
          ], signature),
          isTrue,
        );
        expect(
          _verifyRsaPss(keys.publicKey, digestFactory, entry.value - 1, const [
            1,
            2,
            3,
          ], signature),
          isFalse,
        );
      }
    });
  });

  test('P-521 keys round-trip through PKCS#8 and SPKI', () async {
    final keys = await generateEcdsaKeyPair(SigningAlgorithm.es512);
    final privateBytes = encodeEcdsaPrivateKeyPkcs8(
      keys.privateKey,
      SigningAlgorithm.es512,
    );
    final publicBytes = encodeEcdsaPublicKeySpki(
      keys.publicKey,
      SigningAlgorithm.es512,
    );
    final privateKey = await importEcdsaPrivateKeyPkcs8(
      SigningAlgorithm.es512,
      privateBytes,
    );
    final publicKey = await importEcdsaPublicKeySpki(
      SigningAlgorithm.es512,
      publicBytes,
    );
    final signerBackend = EcdsaSigningBackend(
      SigningAlgorithm.es512,
      privateKey,
    );
    final verifierBackend = EcdsaVerificationBackend(
      SigningAlgorithm.es512,
      publicKey,
    );
    final signature = await signerBackend.sign(SigningAlgorithm.es512, [1, 2]);
    expect(
      await verifierBackend.verify(SigningAlgorithm.es512, [1, 2], signature),
      isTrue,
    );
  });
}

bool _verifyRsaPss(
  pc.RSAPublicKey key,
  pc.Digest Function() digest,
  int saltLength,
  List<int> data,
  List<int> signature,
) {
  final verifier = pc.PSSSigner(pc.RSAEngine(), digest(), digest())
    ..init(
      false,
      pc.ParametersWithSaltConfiguration(
        pc.PublicKeyParameter<pc.RSAPublicKey>(key),
        _testSecureRandom(),
        saltLength,
      ),
    );
  try {
    return verifier.verifySignature(
      Uint8List.fromList(data),
      pc.PSSSignature(Uint8List.fromList(signature)),
    );
  } on ArgumentError {
    return false;
  }
}

pc.SecureRandom _testSecureRandom() {
  final random = pc.FortunaRandom();
  random.seed(pc.KeyParameter(Uint8List.fromList(List<int>.filled(32, 7))));
  return random;
}

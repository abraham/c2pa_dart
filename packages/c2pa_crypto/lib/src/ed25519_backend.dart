import 'package:cryptography/cryptography.dart';

import 'cose_signing.dart';
import 'signing_algorithm.dart';

/// Ed25519 signing using a caller-provided [SimpleKeyPairData].
final class Ed25519SigningBackend implements CoseSigningBackend {
  Ed25519SigningBackend(SimpleKeyPairData keyPair, {Ed25519? implementation})
    : _keyPair = _validateKeyPair(keyPair),
      _implementation = implementation ?? Ed25519();

  final SimpleKeyPairData _keyPair;
  final Ed25519 _implementation;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    if (algorithm != SigningAlgorithm.ed25519) {
      throw UnsupportedBackendException(algorithm);
    }
    final signature = await _implementation.sign(data, keyPair: _keyPair);
    return signature.bytes;
  }
}

/// Ed25519 verification using a caller-provided [SimplePublicKey].
final class Ed25519VerificationBackend implements CoseVerificationBackend {
  Ed25519VerificationBackend(
    SimplePublicKey publicKey, {
    Ed25519? implementation,
  }) : _publicKey = _validatePublicKey(publicKey),
       _implementation = implementation ?? Ed25519();

  final SimplePublicKey _publicKey;
  final Ed25519 _implementation;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) {
    if (algorithm != SigningAlgorithm.ed25519) {
      throw UnsupportedBackendException(algorithm);
    }
    if (signature.length != 64) {
      return Future.value(false);
    }
    return _implementation.verify(
      data,
      signature: Signature(signature, publicKey: _publicKey),
    );
  }
}

SimpleKeyPairData _validateKeyPair(SimpleKeyPairData keyPair) {
  if (keyPair.type != KeyPairType.ed25519) {
    throw ArgumentError.value(
      keyPair.type,
      'keyPair',
      'Expected an Ed25519 key pair',
    );
  }
  if (keyPair.bytes.length != 32) {
    throw ArgumentError.value(
      keyPair.bytes.length,
      'keyPair',
      'Ed25519 private keys must be exactly 32 bytes',
    );
  }
  _validatePublicKey(keyPair.publicKey);
  return keyPair;
}

SimplePublicKey _validatePublicKey(SimplePublicKey publicKey) {
  if (publicKey.type != KeyPairType.ed25519) {
    throw ArgumentError.value(
      publicKey.type,
      'publicKey',
      'Expected an Ed25519 public key',
    );
  }
  if (publicKey.bytes.length != 32) {
    throw ArgumentError.value(
      publicKey.bytes.length,
      'publicKey',
      'Ed25519 public keys must be exactly 32 bytes',
    );
  }
  return publicKey;
}

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'byte_compare.dart';
import 'cose_signing.dart';
import 'der_writer.dart';
import 'key_encoding.dart' as keyenc;
import 'signing_algorithm.dart';

/// A PointyCastle ECDSA private/public key pair.
typedef EcdsaKeyPair = ({pc.ECPrivateKey privateKey, pc.ECPublicKey publicKey});

/// A PointyCastle RSA-PSS private/public key pair.
typedef RsaPssKeyPair = ({
  pc.RSAPrivateKey privateKey,
  pc.RSAPublicKey publicKey,
});

/// Generates a pure-Dart ECDSA key pair for [algorithm].
Future<EcdsaKeyPair> generateEcdsaKeyPair(SigningAlgorithm algorithm) async {
  final parameters = _ecdsaParameters(algorithm);
  final generator = pc.ECKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.ECKeyGeneratorParameters(parameters.domain),
        _secureRandom(),
      ),
    );
  final pair = generator.generateKeyPair();
  return (privateKey: pair.privateKey, publicKey: pair.publicKey);
}

/// Generates a pure-Dart RSA-PSS key pair for [algorithm].
Future<RsaPssKeyPair> generateRsaPssKeyPair(
  SigningAlgorithm algorithm, {
  int modulusLength = 2048,
  BigInt? publicExponent,
}) async {
  _rsaParameters(algorithm);
  final generator = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(
          publicExponent ?? BigInt.from(65537),
          modulusLength,
          64,
        ),
        _secureRandom(),
      ),
    );
  final pair = generator.generateKeyPair();
  return (privateKey: pair.privateKey, publicKey: pair.publicKey);
}

/// Encodes [privateKey] as an RFC 5915 `ECPrivateKey` wrapped in a PKCS#8
/// `PrivateKeyInfo`, matching [algorithm]'s curve.
Uint8List encodeEcdsaPrivateKeyPkcs8(
  pc.ECPrivateKey privateKey,
  SigningAlgorithm algorithm,
) {
  final parameters = _ecdsaParameters(algorithm);
  return keyenc.encodeEcdsaPrivateKeyPkcs8(
    privateKey,
    parameters.curveOid,
    parameters.componentLength,
  );
}

/// Encodes [publicKey] as an `id-ecPublicKey` SPKI, matching [algorithm]'s
/// curve.
Uint8List encodeEcdsaPublicKeySpki(
  pc.ECPublicKey publicKey,
  SigningAlgorithm algorithm,
) {
  final parameters = _ecdsaParameters(algorithm);
  return keyenc.encodeEcdsaPublicKeySpki(publicKey, parameters.curveOid);
}

/// Encodes [privateKey] as an `rsaEncryption` PKCS#8 `PrivateKeyInfo`.
Uint8List encodeRsaPssPrivateKeyPkcs8(pc.RSAPrivateKey privateKey) =>
    keyenc.encodeRsaPrivateKeyPkcs8(privateKey);

/// Encodes [publicKey] as an `rsaEncryption` SPKI.
Uint8List encodeRsaPssPublicKeySpki(pc.RSAPublicKey publicKey) =>
    keyenc.encodeRsaPublicKeySpki(publicKey);

/// Strictly imports an ECDSA PKCS#8 private key for [algorithm].
Future<pc.ECPrivateKey> importEcdsaPrivateKeyPkcs8(
  SigningAlgorithm algorithm,
  List<int> pkcs8,
) async {
  final parameters = _ecdsaParameters(algorithm);
  _validateBytes(pkcs8, 'pkcs8');
  try {
    final key = keyenc.decodeEcPrivateKeyPkcs8(pkcs8, parameters.domain);
    await _validateEcdsaKeyDomain(key.parameters, algorithm);
    return key;
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid PKCS#8 encoding or curve mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an ECDSA SPKI public key for [algorithm].
Future<pc.ECPublicKey> importEcdsaPublicKeySpki(
  SigningAlgorithm algorithm,
  List<int> spki,
) async {
  final parameters = _ecdsaParameters(algorithm);
  _validateBytes(spki, 'spki');
  try {
    final parsed = keyenc.parseEcPublicKeySpki(spki);
    if (parsed == null || !bytesEqual(parsed.curveOid, parameters.curveOid)) {
      throw const FormatException('Curve mismatch or not an EC public key');
    }
    final point = parameters.domain.curve.decodePoint(parsed.point);
    if (point == null) {
      throw const FormatException('Invalid EC point encoding');
    }
    final key = pc.ECPublicKey(point, parameters.domain);
    await _validateEcdsaKeyDomain(key.parameters, algorithm);
    return key;
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid SPKI encoding or curve mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an RSA-PSS PKCS#8 private key for [algorithm].
Future<pc.RSAPrivateKey> importRsaPssPrivateKeyPkcs8(
  SigningAlgorithm algorithm,
  List<int> pkcs8,
) async {
  _rsaParameters(algorithm);
  _validateBytes(pkcs8, 'pkcs8');
  try {
    return keyenc.decodeRsaPrivateKeyPkcs8(pkcs8);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid PKCS#8 encoding or algorithm mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an RSA-PSS SPKI public key for [algorithm].
///
/// Accepts both the generic `rsaEncryption` OID and `id-RSASSA-PSS`, as long
/// as any embedded PSS parameters name the hash required by [algorithm].
Future<pc.RSAPublicKey> importRsaPssPublicKeySpki(
  SigningAlgorithm algorithm,
  List<int> spki,
) async {
  final parameters = _rsaParameters(algorithm);
  _validateBytes(spki, 'spki');
  try {
    final parsed = keyenc.parseRsaPublicKeySpki(
      spki,
      expectedHashOid: parameters.hashOid,
    );
    if (parsed == null) {
      throw const FormatException('SPKI is not an RSA public key');
    }
    return pc.RSAPublicKey(parsed.modulus, parsed.exponent);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid SPKI encoding or algorithm mismatch',
      cause: error,
    );
  }
}

/// Platform-independent ECDSA signer that emits fixed-width P1363 signatures.
final class EcdsaSigningBackend implements CoseSigningBackend {
  /// Creates a pure-Dart ECDSA signer for [algorithm].
  EcdsaSigningBackend(this.algorithm, this.privateKey)
    : _parameters = _ecdsaParameters(algorithm),
      _keyValidation = _validateEcdsaKeyDomain(
        privateKey.parameters,
        algorithm,
      );

  /// The configured ECDSA signing algorithm.
  final SigningAlgorithm algorithm;

  /// The private key used to produce signatures.
  final pc.ECPrivateKey privateKey;
  final _EcdsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    _requireAlgorithm(this.algorithm, algorithm);
    await _keyValidation;
    final signer = pc.ECDSASigner(_parameters.digest())
      ..init(
        true,
        pc.ParametersWithRandom(
          pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey),
          _secureRandom(),
        ),
      );
    final signature =
        signer.generateSignature(Uint8List.fromList(data)) as pc.ECSignature;
    return [
      ...derFixedWidthUnsigned(signature.r, _parameters.componentLength),
      ...derFixedWidthUnsigned(signature.s, _parameters.componentLength),
    ];
  }
}

/// Platform-independent ECDSA verifier for fixed-width P1363 signatures.
final class EcdsaVerificationBackend implements CoseVerificationBackend {
  /// Creates a pure-Dart ECDSA verifier for [algorithm].
  EcdsaVerificationBackend(this.algorithm, this.publicKey)
    : _parameters = _ecdsaParameters(algorithm),
      _keyValidation = _validateEcdsaKeyDomain(publicKey.parameters, algorithm);

  /// The configured ECDSA verification algorithm.
  final SigningAlgorithm algorithm;

  /// The public key used to verify signatures.
  final pc.ECPublicKey publicKey;
  final _EcdsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) async {
    _requireAlgorithm(this.algorithm, algorithm);
    await _keyValidation;
    final expected = _parameters.componentLength * 2;
    if (signature.length != expected) {
      throw InvalidSignatureWidthException(
        algorithm,
        expected,
        signature.length,
      );
    }
    final r = bigIntFromUnsignedBytes(
      signature.sublist(0, _parameters.componentLength),
    );
    final s = bigIntFromUnsignedBytes(
      signature.sublist(_parameters.componentLength),
    );
    final verifier = pc.ECDSASigner(_parameters.digest())
      ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKey));
    return verifier.verifySignature(
      Uint8List.fromList(data),
      pc.ECSignature(r, s),
    );
  }
}

/// Platform-independent RSA-PSS signer using a digest-sized salt.
final class RsaPssSigningBackend implements CoseSigningBackend {
  /// Creates a pure-Dart RSA-PSS signer using a digest-sized salt.
  RsaPssSigningBackend(this.algorithm, this.privateKey)
    : _parameters = _rsaParameters(algorithm);

  /// The configured RSA-PSS signing algorithm.
  final SigningAlgorithm algorithm;

  /// The RSA-PSS private key used to produce signatures.
  final pc.RSAPrivateKey privateKey;
  final _RsaParameters _parameters;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    _requireAlgorithm(this.algorithm, algorithm);
    final signer =
        pc.PSSSigner(pc.RSAEngine(), _parameters.digest(), _parameters.digest())
          ..init(
            true,
            pc.ParametersWithSaltConfiguration(
              pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey),
              _secureRandom(),
              _parameters.saltLength,
            ),
          );
    final signature = signer.generateSignature(Uint8List.fromList(data));
    return signature.bytes;
  }
}

/// Platform-independent RSA-PSS verifier using a digest-sized salt.
final class RsaPssVerificationBackend implements CoseVerificationBackend {
  /// Creates a pure-Dart RSA-PSS verifier using a digest-sized salt.
  RsaPssVerificationBackend(this.algorithm, this.publicKey)
    : _parameters = _rsaParameters(algorithm);

  /// The configured RSA-PSS verification algorithm.
  final SigningAlgorithm algorithm;

  /// The RSA-PSS public key used to verify signatures.
  final pc.RSAPublicKey publicKey;
  final _RsaParameters _parameters;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) async {
    _requireAlgorithm(this.algorithm, algorithm);
    final verifier =
        pc.PSSSigner(pc.RSAEngine(), _parameters.digest(), _parameters.digest())
          ..init(
            false,
            pc.ParametersWithSaltConfiguration(
              pc.PublicKeyParameter<pc.RSAPublicKey>(publicKey),
              _secureRandom(),
              _parameters.saltLength,
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
}

Future<void> _validateEcdsaKeyDomain(
  pc.ECDomainParameters? domain,
  SigningAlgorithm algorithm,
) async {
  final parameters = _ecdsaParameters(algorithm);
  final oid = domain == null
      ? null
      : keyenc.curveOidForDomainParameters(domain);
  if (oid == null || !bytesEqual(oid, parameters.curveOid)) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'expected ${parameters.jwkCurve} ECDSA key',
    );
  }
}

void _requireAlgorithm(
  SigningAlgorithm configured,
  SigningAlgorithm requested,
) {
  if (configured != requested) {
    throw AlgorithmMismatchException(configured, requested);
  }
}

void _validateBytes(List<int> bytes, String name) {
  if (bytes.isEmpty || bytes.any((byte) => byte < 0 || byte > 0xff)) {
    throw ArgumentError.value(bytes, name, 'Must be non-empty bytes');
  }
}

_EcdsaParameters _ecdsaParameters(SigningAlgorithm algorithm) =>
    switch (algorithm) {
      SigningAlgorithm.es256 => _EcdsaParameters(
        pc.ECCurve_secp256r1(),
        pc.SHA256Digest.new,
        keyenc.prime256v1Oid,
        'P-256',
        32,
      ),
      SigningAlgorithm.es384 => _EcdsaParameters(
        pc.ECCurve_secp384r1(),
        pc.SHA384Digest.new,
        keyenc.secp384r1Oid,
        'P-384',
        48,
      ),
      SigningAlgorithm.es512 => _EcdsaParameters(
        pc.ECCurve_secp521r1(),
        pc.SHA512Digest.new,
        keyenc.secp521r1Oid,
        'P-521',
        66,
      ),
      _ => throw UnsupportedBackendException(algorithm),
    };

_RsaParameters _rsaParameters(SigningAlgorithm algorithm) =>
    switch (algorithm) {
      SigningAlgorithm.ps256 => _RsaParameters(
        pc.SHA256Digest.new,
        32,
        keyenc.sha256HashOid,
      ),
      SigningAlgorithm.ps384 => _RsaParameters(
        pc.SHA384Digest.new,
        48,
        keyenc.sha384HashOid,
      ),
      SigningAlgorithm.ps512 => _RsaParameters(
        pc.SHA512Digest.new,
        64,
        keyenc.sha512HashOid,
      ),
      _ => throw UnsupportedBackendException(algorithm),
    };

pc.SecureRandom _secureRandom() {
  final random = pc.FortunaRandom();
  final seedSource = Random.secure();
  final seed = Uint8List.fromList(
    List<int>.generate(32, (_) => seedSource.nextInt(256)),
  );
  random.seed(pc.KeyParameter(seed));
  return random;
}

final class _EcdsaParameters {
  const _EcdsaParameters(
    this.domain,
    this.digest,
    this.curveOid,
    this.jwkCurve,
    this.componentLength,
  );

  final pc.ECDomainParameters domain;
  final pc.Digest Function() digest;
  final List<int> curveOid;
  final String jwkCurve;
  final int componentLength;
}

final class _RsaParameters {
  const _RsaParameters(this.digest, this.saltLength, this.hashOid);

  final pc.Digest Function() digest;
  final int saltLength;
  final List<int> hashOid;
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart' as webcrypto;

import 'cose_signing.dart';
import 'ecdsa_signature.dart';
import 'signing_algorithm.dart';

/// A WebCrypto ECDSA private/public key pair.
typedef WebCryptoEcdsaKeyPair = ({
  webcrypto.EcdsaPrivateKey privateKey,
  webcrypto.EcdsaPublicKey publicKey,
});

/// A WebCrypto RSA-PSS private/public key pair.
typedef WebCryptoRsaPssKeyPair = ({
  webcrypto.RsaPssPrivateKey privateKey,
  webcrypto.RsaPssPublicKey publicKey,
});

/// Generates a platform-backed ECDSA key pair for [algorithm].
Future<WebCryptoEcdsaKeyPair> generateEcdsaKeyPair(
  SigningAlgorithm algorithm,
) async {
  final parameters = _ecdsaParameters(algorithm);
  try {
    return await webcrypto.EcdsaPrivateKey.generateKey(parameters.curve);
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  }
}

/// Generates a platform-backed RSA-PSS key pair for [algorithm].
Future<WebCryptoRsaPssKeyPair> generateRsaPssKeyPair(
  SigningAlgorithm algorithm, {
  int modulusLength = 2048,
  BigInt? publicExponent,
}) async {
  final parameters = _rsaParameters(algorithm);
  try {
    return await webcrypto.RsaPssPrivateKey.generateKey(
      modulusLength,
      publicExponent ?? BigInt.from(65537),
      parameters.hash,
    );
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  }
}

/// Strictly imports an ECDSA PKCS#8 private key for [algorithm].
Future<webcrypto.EcdsaPrivateKey> importEcdsaPrivateKeyPkcs8(
  SigningAlgorithm algorithm,
  List<int> pkcs8,
) async {
  final parameters = _ecdsaParameters(algorithm);
  _validateBytes(pkcs8, 'pkcs8');
  try {
    final key = await webcrypto.EcdsaPrivateKey.importPkcs8Key(
      pkcs8,
      parameters.curve,
    );
    await _validateEcdsaKey(key.exportJsonWebKey(), algorithm);
    return key;
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid PKCS#8 encoding or curve mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an ECDSA SPKI public key for [algorithm].
Future<webcrypto.EcdsaPublicKey> importEcdsaPublicKeySpki(
  SigningAlgorithm algorithm,
  List<int> spki,
) async {
  final parameters = _ecdsaParameters(algorithm);
  _validateBytes(spki, 'spki');
  try {
    final key = await webcrypto.EcdsaPublicKey.importSpkiKey(
      spki,
      parameters.curve,
    );
    await _validateEcdsaKey(key.exportJsonWebKey(), algorithm);
    return key;
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid SPKI encoding or curve mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an RSA-PSS PKCS#8 private key for [algorithm].
Future<webcrypto.RsaPssPrivateKey> importRsaPssPrivateKeyPkcs8(
  SigningAlgorithm algorithm,
  List<int> pkcs8,
) async {
  final parameters = _rsaParameters(algorithm);
  _validateBytes(pkcs8, 'pkcs8');
  try {
    final key = await webcrypto.RsaPssPrivateKey.importPkcs8Key(
      pkcs8,
      parameters.hash,
    );
    await _validateRsaKey(key.exportJsonWebKey(), algorithm);
    return key;
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid PKCS#8 encoding or algorithm mismatch',
      cause: error,
    );
  }
}

/// Strictly imports an RSA-PSS SPKI public key for [algorithm].
Future<webcrypto.RsaPssPublicKey> importRsaPssPublicKeySpki(
  SigningAlgorithm algorithm,
  List<int> spki,
) async {
  final parameters = _rsaParameters(algorithm);
  _validateBytes(spki, 'spki');
  try {
    final parsedRsa = _parseRsaPublicKeySpki(spki, algorithm);
    final key = parsedRsa == null
        ? await webcrypto.RsaPssPublicKey.importSpkiKey(spki, parameters.hash)
        : await webcrypto.RsaPssPublicKey.importJsonWebKey({
            'kty': 'RSA',
            'alg': parameters.jwkAlgorithm,
            'use': 'sig',
            'key_ops': const ['verify'],
            'ext': true,
            'n': _base64UrlNoPadding(parsedRsa.modulus),
            'e': _base64UrlNoPadding(parsedRsa.exponent),
          }, parameters.hash);
    await _validateRsaKey(
      key.exportJsonWebKey(),
      algorithm,
      allowGenericPublicKeyAlgorithm: true,
    );
    return key;
  } on UnsupportedError catch (error) {
    throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
  } on FormatException catch (error) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'invalid SPKI encoding or algorithm mismatch',
      cause: error,
    );
  }
}

({Uint8List modulus, Uint8List exponent})? _parseRsaPublicKeySpki(
  List<int> spki,
  SigningAlgorithm signingAlgorithm,
) {
  final outer = _SpkiDerReader(Uint8List.fromList(spki));
  final sequence = outer.read(0x30).reader();
  outer.requireEnd();

  final algorithm = sequence.read(0x30).reader();
  final oid = algorithm.read(0x06).content;
  const rsaEncryptionOid = <int>[
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
  ];
  const rsaPssOid = <int>[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
  if (_equalBytes(oid, rsaEncryptionOid)) {
    final parameters = algorithm.read(0x05);
    if (parameters.content.isNotEmpty) {
      throw const FormatException('rsaEncryption parameters must be NULL');
    }
    algorithm.requireEnd();
  } else if (_equalBytes(oid, rsaPssOid)) {
    _validateRsaPssSpkiParameters(algorithm, signingAlgorithm);
  } else {
    return null;
  }

  final bitString = sequence.read(0x03).content;
  sequence.requireEnd();
  if (bitString.isEmpty || bitString.first != 0) {
    throw const FormatException(
      'RSA SubjectPublicKey BIT STRING must have zero unused bits',
    );
  }
  final rsa = _SpkiDerReader(Uint8List.fromList(bitString.sublist(1)));
  final publicKey = rsa.read(0x30).reader();
  rsa.requireEnd();
  final modulus = _positiveInteger(publicKey.read(0x02).content, 'modulus');
  final exponent = _positiveInteger(publicKey.read(0x02).content, 'exponent');
  publicKey.requireEnd();
  return (modulus: modulus, exponent: exponent);
}

void _validateRsaPssSpkiParameters(
  _SpkiDerReader algorithm,
  SigningAlgorithm signingAlgorithm,
) {
  final parameters = algorithm.read(0x30).reader();
  algorithm.requireEnd();

  final expectedHashOid = switch (signingAlgorithm) {
    SigningAlgorithm.ps256 => const [
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x01,
    ],
    SigningAlgorithm.ps384 => const [
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x02,
    ],
    SigningAlgorithm.ps512 => const [
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x03,
    ],
    _ => throw UnsupportedBackendException(signingAlgorithm),
  };
  const mgf1Oid = <int>[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

  final hashWrapper = parameters.read(0xa0).reader();
  final hash = hashWrapper.read(0x30).reader();
  hashWrapper.requireEnd();
  _requireAlgorithmIdentifier(hash, expectedHashOid, 'RSA-PSS hash');

  final maskWrapper = parameters.read(0xa1).reader();
  final mask = maskWrapper.read(0x30).reader();
  maskWrapper.requireEnd();
  if (!_equalBytes(mask.read(0x06).content, mgf1Oid)) {
    throw const FormatException('RSA-PSS mask algorithm must be MGF1');
  }
  final maskHash = mask.read(0x30).reader();
  _requireAlgorithmIdentifier(maskHash, expectedHashOid, 'RSA-PSS MGF1 hash');
  mask.requireEnd();

  final saltWrapper = parameters.read(0xa2).reader();
  final saltLength = _readPositiveIntegerValue(
    saltWrapper.read(0x02).content,
    'RSA-PSS salt length',
  );
  saltWrapper.requireEnd();
  if (saltLength != signingAlgorithm.hashAlgorithm!.digestLength) {
    throw FormatException(
      'RSA-PSS salt length does not match ${signingAlgorithm.name}',
    );
  }
  if (parameters.peekTag() == 0xa3) {
    final trailer = parameters.read(0xa3).reader();
    final trailerValue = _readPositiveIntegerValue(
      trailer.read(0x02).content,
      'RSA-PSS trailer field',
    );
    trailer.requireEnd();
    if (trailerValue != 1) {
      throw const FormatException('RSA-PSS trailer field must be 1');
    }
  }
  parameters.requireEnd();
}

void _requireAlgorithmIdentifier(
  _SpkiDerReader algorithm,
  List<int> expectedOid,
  String name,
) {
  if (!_equalBytes(algorithm.read(0x06).content, expectedOid)) {
    throw FormatException('$name does not match the requested algorithm');
  }
  final nullParameters = algorithm.read(0x05);
  if (nullParameters.content.isNotEmpty) {
    throw FormatException('$name parameters must be NULL');
  }
  algorithm.requireEnd();
}

int _readPositiveIntegerValue(Uint8List bytes, String name) {
  final value = _positiveInteger(bytes, name);
  if (value.length > 4) {
    throw FormatException('$name is too large');
  }
  var result = 0;
  for (final byte in value) {
    result = result << 8 | byte;
  }
  return result;
}

Uint8List _positiveInteger(Uint8List bytes, String name) {
  if (bytes.isEmpty || bytes.first >= 0x80) {
    throw FormatException('RSA $name must be a positive DER INTEGER');
  }
  if (bytes.length > 1 && bytes.first == 0 && bytes[1] < 0x80) {
    throw FormatException('RSA $name has redundant sign padding');
  }
  final value = bytes.length > 1 && bytes.first == 0 ? bytes.sublist(1) : bytes;
  if (value.every((byte) => byte == 0)) {
    throw FormatException('RSA $name must be non-zero');
  }
  return Uint8List.fromList(value);
}

String _base64UrlNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

final class _SpkiDerValue {
  const _SpkiDerValue(this.content);

  final Uint8List content;

  _SpkiDerReader reader() => _SpkiDerReader(content);
}

final class _SpkiDerReader {
  _SpkiDerReader(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  int? peekTag() => offset == bytes.length ? null : bytes[offset];

  void requireEnd() {
    if (offset != bytes.length) {
      throw const FormatException('Trailing DER data in RSA SPKI');
    }
  }

  _SpkiDerValue read(int expectedTag) {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated RSA SPKI');
    }
    final tag = bytes[offset++];
    if (tag != expectedTag) {
      throw FormatException(
        'Expected DER tag 0x${expectedTag.toRadixString(16)}, '
        'found 0x${tag.toRadixString(16)}',
      );
    }
    final length = _readLength();
    if (length > bytes.length - offset) {
      throw const FormatException('RSA SPKI value exceeds its container');
    }
    final content = Uint8List.fromList(bytes.sublist(offset, offset + length));
    offset += length;
    return _SpkiDerValue(content);
  }

  int _readLength() {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated RSA SPKI length');
    }
    final first = bytes[offset++];
    if (first < 0x80) {
      return first;
    }
    final count = first & 0x7f;
    if (count == 0 ||
        count > 4 ||
        count > bytes.length - offset ||
        bytes[offset] == 0) {
      throw const FormatException('Invalid RSA SPKI DER length');
    }
    var length = 0;
    for (var index = 0; index < count; index++) {
      length = length << 8 | bytes[offset++];
    }
    if (length < 0x80) {
      throw const FormatException('Non-minimal RSA SPKI DER length');
    }
    return length;
  }
}

/// Platform-backed ECDSA signer that emits fixed-width P1363 signatures.
final class WebCryptoEcdsaSigningBackend implements CoseSigningBackend {
  /// Creates a platform-backed ECDSA signer for [algorithm].
  WebCryptoEcdsaSigningBackend(this.algorithm, this.privateKey)
    : _parameters = _ecdsaParameters(algorithm),
      _keyValidation = _validateEcdsaKey(
        privateKey.exportJsonWebKey(),
        algorithm,
      );

  /// The configured ECDSA signing algorithm.
  final SigningAlgorithm algorithm;

  /// The WebCrypto private key used to produce signatures.
  final webcrypto.EcdsaPrivateKey privateKey;
  final _EcdsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    _requireAlgorithm(this.algorithm, algorithm);
    try {
      await _keyValidation;
      final signature = await privateKey.signBytes(data, _parameters.hash);
      if (signature.length == _parameters.componentLength * 2) {
        return signature;
      }
      if (signature.isNotEmpty && signature.first == 0x30) {
        return ecdsaDerToP1363(
          signature,
          componentLength: _parameters.componentLength,
        );
      }
      throw InvalidSignatureWidthException(
        algorithm,
        _parameters.componentLength * 2,
        signature.length,
      );
    } on UnsupportedError catch (error) {
      throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
    }
  }
}

/// Platform-backed ECDSA verifier for fixed-width P1363 signatures.
final class WebCryptoEcdsaVerificationBackend
    implements CoseVerificationBackend {
  /// Creates a platform-backed ECDSA verifier for [algorithm].
  WebCryptoEcdsaVerificationBackend(this.algorithm, this.publicKey)
    : _parameters = _ecdsaParameters(algorithm),
      _keyValidation = _validateEcdsaKey(
        publicKey.exportJsonWebKey(),
        algorithm,
      );

  /// The configured ECDSA verification algorithm.
  final SigningAlgorithm algorithm;

  /// The WebCrypto public key used to verify signatures.
  final webcrypto.EcdsaPublicKey publicKey;
  final _EcdsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) async {
    _requireAlgorithm(this.algorithm, algorithm);
    try {
      await _keyValidation;
      final expected = _parameters.componentLength * 2;
      if (signature.length != expected) {
        throw InvalidSignatureWidthException(
          algorithm,
          expected,
          signature.length,
        );
      }
      return await publicKey.verifyBytes(signature, data, _parameters.hash);
    } on UnsupportedError catch (error) {
      throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
    }
  }
}

/// Platform-backed RSA-PSS signer using a digest-sized salt.
final class WebCryptoRsaPssSigningBackend implements CoseSigningBackend {
  /// Creates a platform-backed RSA-PSS signer using digest-sized salt.
  WebCryptoRsaPssSigningBackend(this.algorithm, this.privateKey)
    : _parameters = _rsaParameters(algorithm),
      _keyValidation = _validateRsaKey(
        privateKey.exportJsonWebKey(),
        algorithm,
      );

  /// The configured RSA-PSS signing algorithm.
  final SigningAlgorithm algorithm;

  /// The WebCrypto RSA-PSS private key used to produce signatures.
  final webcrypto.RsaPssPrivateKey privateKey;
  final _RsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) async {
    _requireAlgorithm(this.algorithm, algorithm);
    try {
      await _keyValidation;
      return await privateKey.signBytes(data, _parameters.saltLength);
    } on UnsupportedError catch (error) {
      throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
    }
  }
}

/// Platform-backed RSA-PSS verifier using a digest-sized salt.
final class WebCryptoRsaPssVerificationBackend
    implements CoseVerificationBackend {
  /// Creates a platform-backed RSA-PSS verifier using digest-sized salt.
  WebCryptoRsaPssVerificationBackend(this.algorithm, this.publicKey)
    : _parameters = _rsaParameters(algorithm),
      _keyValidation = _validateRsaKey(publicKey.exportJsonWebKey(), algorithm);

  /// The configured RSA-PSS verification algorithm.
  final SigningAlgorithm algorithm;

  /// The WebCrypto RSA-PSS public key used to verify signatures.
  final webcrypto.RsaPssPublicKey publicKey;
  final _RsaParameters _parameters;
  final Future<void> _keyValidation;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) async {
    _requireAlgorithm(this.algorithm, algorithm);
    try {
      await _keyValidation;
      return await publicKey.verifyBytes(
        signature,
        data,
        _parameters.saltLength,
      );
    } on UnsupportedError catch (error) {
      throw PlatformAlgorithmUnavailableException(algorithm, cause: error);
    }
  }
}

Future<void> _validateEcdsaKey(
  Future<Map<String, dynamic>> jwkFuture,
  SigningAlgorithm algorithm,
) async {
  final parameters = _ecdsaParameters(algorithm);
  final jwk = await jwkFuture;
  if (jwk['kty'] != 'EC' || jwk['crv'] != parameters.jwkCurve) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'expected ${parameters.jwkCurve} ECDSA key',
    );
  }
}

Future<void> _validateRsaKey(
  Future<Map<String, dynamic>> jwkFuture,
  SigningAlgorithm algorithm, {
  bool allowGenericPublicKeyAlgorithm = false,
}) async {
  final parameters = _rsaParameters(algorithm);
  final jwk = await jwkFuture;
  final keyAlgorithm = jwk['alg'];
  final genericPublicAlgorithm =
      allowGenericPublicKeyAlgorithm &&
      (keyAlgorithm == null ||
          (keyAlgorithm is String && keyAlgorithm.startsWith('RS')));
  if (jwk['kty'] != 'RSA' ||
      (keyAlgorithm != parameters.jwkAlgorithm && !genericPublicAlgorithm)) {
    throw InvalidKeyForAlgorithmException(
      algorithm,
      'expected ${parameters.jwkAlgorithm} RSA-PSS key',
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

_EcdsaParameters _ecdsaParameters(SigningAlgorithm algorithm) =>
    switch (algorithm) {
      SigningAlgorithm.es256 => const _EcdsaParameters(
        webcrypto.EllipticCurve.p256,
        webcrypto.Hash.sha256,
        'P-256',
        32,
      ),
      SigningAlgorithm.es384 => const _EcdsaParameters(
        webcrypto.EllipticCurve.p384,
        webcrypto.Hash.sha384,
        'P-384',
        48,
      ),
      SigningAlgorithm.es512 => const _EcdsaParameters(
        webcrypto.EllipticCurve.p521,
        webcrypto.Hash.sha512,
        'P-521',
        66,
      ),
      _ => throw UnsupportedBackendException(algorithm),
    };

_RsaParameters _rsaParameters(SigningAlgorithm algorithm) =>
    switch (algorithm) {
      SigningAlgorithm.ps256 => const _RsaParameters(
        webcrypto.Hash.sha256,
        'PS256',
        32,
      ),
      SigningAlgorithm.ps384 => const _RsaParameters(
        webcrypto.Hash.sha384,
        'PS384',
        48,
      ),
      SigningAlgorithm.ps512 => const _RsaParameters(
        webcrypto.Hash.sha512,
        'PS512',
        64,
      ),
      _ => throw UnsupportedBackendException(algorithm),
    };

void _validateBytes(List<int> bytes, String name) {
  if (bytes.isEmpty || bytes.any((byte) => byte < 0 || byte > 0xff)) {
    throw ArgumentError.value(bytes, name, 'Must be non-empty bytes');
  }
}

final class _EcdsaParameters {
  const _EcdsaParameters(
    this.curve,
    this.hash,
    this.jwkCurve,
    this.componentLength,
  );

  final webcrypto.EllipticCurve curve;
  final webcrypto.Hash hash;
  final String jwkCurve;
  final int componentLength;
}

final class _RsaParameters {
  const _RsaParameters(this.hash, this.jwkAlgorithm, this.saltLength);

  final webcrypto.Hash hash;
  final String jwkAlgorithm;
  final int saltLength;
}

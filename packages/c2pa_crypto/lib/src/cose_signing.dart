import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';

import 'signing_algorithm.dart';

/// Performs signing for one or more algorithms using caller-owned keys.
abstract interface class CoseSigningBackend {
  /// Signs the Sig_structure [data] for [algorithm].
  ///
  /// Implementations must return raw COSE signature bytes, using fixed-width
  /// P1363 encoding for ECDSA algorithms.
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data);
}

/// Performs verification for one or more algorithms using caller-owned keys.
abstract interface class CoseVerificationBackend {
  /// Verifies raw COSE [signature] bytes over Sig_structure [data].
  ///
  /// ECDSA signatures are supplied in fixed-width P1363 encoding.
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  );
}

/// Base class for failures in the COSE cryptographic orchestration layer.
sealed class CoseCryptoException implements Exception {
  /// Creates a COSE crypto exception carrying a human-readable [message].
  const CoseCryptoException(this.message);

  /// The human-readable failure detail.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The protected COSE algorithm identifier is not supported.
final class UnknownCoseAlgorithmException extends CoseCryptoException {
  /// Creates an exception for an unsupported protected COSE [coseId].
  UnknownCoseAlgorithmException(this.coseId)
    : super('Unsupported protected COSE algorithm identifier: $coseId');

  /// The unsupported COSE algorithm identifier.
  final int coseId;
}

/// A COSE algorithm differs from the algorithm required by the caller.
final class AlgorithmMismatchException extends CoseCryptoException {
  /// Creates an exception for an expected versus actual algorithm mismatch.
  AlgorithmMismatchException(this.expected, this.actual)
    : super('Expected ${expected.name}, but protected alg is ${actual.name}');

  /// The algorithm required by the caller or protected headers.
  final SigningAlgorithm expected;

  /// The algorithm found in the protected COSE headers.
  final SigningAlgorithm actual;
}

/// The supplied payload does not match the embedded COSE payload.
final class PayloadMismatchException extends CoseCryptoException {
  /// Creates an exception for a detached payload mismatch.
  const PayloadMismatchException()
    : super('The supplied payload does not match the embedded COSE payload');
}

/// An ECDSA signature does not have the required fixed P1363 width.
final class InvalidSignatureWidthException extends CoseCryptoException {
  /// Creates an exception for an ECDSA P1363 signature length mismatch.
  InvalidSignatureWidthException(this.algorithm, this.expected, this.actual)
    : super(
        '${algorithm.name} requires a $expected-byte P1363 signature, '
        'but received $actual bytes',
      );

  /// The algorithm whose fixed signature width was violated.
  final SigningAlgorithm algorithm;

  /// The required signature length in bytes.
  final int expected;

  /// The received signature length in bytes.
  final int actual;
}

/// No key backend was supplied for the requested algorithm.
final class UnsupportedBackendException extends CoseCryptoException {
  /// Creates an exception for a missing backend for [algorithm].
  UnsupportedBackendException(this.algorithm)
    : super('No cryptographic backend is available for ${algorithm.name}');

  /// The algorithm for which no backend was supplied.
  final SigningAlgorithm algorithm;
}

/// A key is incompatible with the requested signing algorithm.
final class InvalidKeyForAlgorithmException extends CoseCryptoException {
  /// Creates an exception for a key rejected for [algorithm].
  InvalidKeyForAlgorithmException(this.algorithm, String detail, {this.cause})
    : super('Key is not valid for ${algorithm.name}: $detail');

  /// The algorithm the key was expected to satisfy.
  final SigningAlgorithm algorithm;

  /// The underlying import or validation error, if one was available.
  final Object? cause;
}

/// The platform cannot provide the requested cryptographic algorithm.
final class PlatformAlgorithmUnavailableException extends CoseCryptoException {
  /// Creates an exception for a platform algorithm lookup failure.
  PlatformAlgorithmUnavailableException(this.algorithm, {this.cause})
    : super('${algorithm.name} is unavailable on this platform');

  /// The algorithm the platform could not provide.
  final SigningAlgorithm algorithm;

  /// The underlying platform error, if one was available.
  final Object? cause;
}

/// Creates deterministic COSE_Sign1 encodings around injected key operations.
final class CoseSigner {
  /// Creates a signer using the supplied algorithm-to-backend map.
  CoseSigner({Map<SigningAlgorithm, CoseSigningBackend> backends = const {}})
    : _backends = Map.unmodifiable(backends);

  final Map<SigningAlgorithm, CoseSigningBackend> _backends;

  /// Signs [payload] and returns a deterministic encoded COSE_Sign1 message.
  ///
  /// When [detached] is true, the returned message contains a null payload
  /// while the supplied payload is still included in the Sig_structure.
  Future<Uint8List> sign({
    required SigningAlgorithm algorithm,
    required List<int> payload,
    CoseHeaders? protectedHeaders,
    CoseHeaders? unprotectedHeaders,
    List<int> externalAad = const [],
    bool detached = false,
    bool tagged = true,
  }) async {
    final backend = _backends[algorithm];
    if (backend == null) {
      throw UnsupportedBackendException(algorithm);
    }

    final protected = _withAlgorithm(protectedHeaders, algorithm);
    final payloadBytes = _bytes(payload, 'payload');
    final aadBytes = _bytes(externalAad, 'externalAad');
    final unsigned = CoseSign1(
      protectedHeaders: protected,
      unprotectedHeaders: unprotectedHeaders,
      payload: detached ? null : payloadBytes,
      signature: Uint8List(0),
      tagged: tagged,
    );
    final structure = unsigned.signatureStructure(
      externalAad: aadBytes,
      detachedPayload: detached ? payloadBytes : null,
    );
    final signature = await backend.sign(algorithm, structure);
    _validateSignatureWidth(algorithm, signature);

    return CoseSign1(
      protectedHeaders: protected,
      unprotectedHeaders: unprotectedHeaders,
      payload: detached ? null : payloadBytes,
      signature: _bytes(signature, 'signature'),
      tagged: tagged,
    ).encode();
  }
}

/// Verifies COSE_Sign1 messages using algorithm-specific injected backends.
final class CoseVerifier {
  /// Creates a verifier using the supplied algorithm-to-backend map.
  CoseVerifier({
    Map<SigningAlgorithm, CoseVerificationBackend> backends = const {},
  }) : _backends = Map.unmodifiable(backends);

  final Map<SigningAlgorithm, CoseVerificationBackend> _backends;

  /// Verifies [message] against the exact supplied [payload].
  Future<bool> verify(
    CoseSign1 message, {
    required List<int> payload,
    List<int> externalAad = const [],
    SigningAlgorithm? expectedAlgorithm,
  }) async {
    final algorithm = _algorithmFrom(message);
    if (expectedAlgorithm != null && expectedAlgorithm != algorithm) {
      throw AlgorithmMismatchException(expectedAlgorithm, algorithm);
    }

    final embedded = message.payload;
    final payloadBytes = _bytes(payload, 'payload');
    if (embedded != null && !_equalBytes(embedded, payloadBytes)) {
      throw const PayloadMismatchException();
    }

    final signature = message.signature;
    _validateSignatureWidth(algorithm, signature);
    final backend = _backends[algorithm];
    if (backend == null) {
      throw UnsupportedBackendException(algorithm);
    }

    final structure = message.signatureStructure(
      externalAad: _bytes(externalAad, 'externalAad'),
      detachedPayload: embedded == null ? payloadBytes : null,
    );
    return backend.verify(algorithm, structure, signature);
  }

  /// Parses and verifies an encoded COSE_Sign1 message.
  Future<bool> verifyEncoded(
    List<int> encoded, {
    required List<int> payload,
    List<int> externalAad = const [],
    SigningAlgorithm? expectedAlgorithm,
    bool allowTagged = true,
    bool allowUntagged = true,
  }) {
    final message = CoseSign1.parse(
      encoded,
      allowTagged: allowTagged,
      allowUntagged: allowUntagged,
    );
    return verify(
      message,
      payload: payload,
      externalAad: externalAad,
      expectedAlgorithm: expectedAlgorithm,
    );
  }
}

CoseHeaders _withAlgorithm(CoseHeaders? supplied, SigningAlgorithm algorithm) {
  final values = Map<CoseHeaderLabel, Object?>.from(
    supplied?.values ?? const {},
  );
  final suppliedId = values[CoseHeaderLabel.algorithm];
  if (suppliedId != null) {
    final suppliedAlgorithm = _algorithmFromId(suppliedId as int);
    if (suppliedAlgorithm != algorithm) {
      throw AlgorithmMismatchException(algorithm, suppliedAlgorithm);
    }
  }
  values[CoseHeaderLabel.algorithm] = algorithm.coseId;
  return CoseHeaders(values);
}

SigningAlgorithm _algorithmFrom(CoseSign1 message) => _algorithmFromId(
  message.protectedHeaders[CoseHeaderLabel.algorithm] as int,
);

SigningAlgorithm _algorithmFromId(int coseId) {
  try {
    return SigningAlgorithm.fromCoseId(coseId);
  } on ArgumentError {
    throw UnknownCoseAlgorithmException(coseId);
  }
}

void _validateSignatureWidth(SigningAlgorithm algorithm, List<int> signature) {
  final expected = algorithm.p1363SignatureLength;
  if (expected != null && signature.length != expected) {
    throw InvalidSignatureWidthException(algorithm, expected, signature.length);
  }
}

Uint8List _bytes(List<int> input, String name) {
  if (input.any((byte) => byte < 0 || byte > 0xff)) {
    throw ArgumentError.value(input, name, 'Must contain only bytes');
  }
  return Uint8List.fromList(input);
}

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) {
      return false;
    }
  }
  return true;
}

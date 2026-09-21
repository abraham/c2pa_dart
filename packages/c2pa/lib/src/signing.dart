import 'dart:typed_data';

/// Callback that signs canonical claim bytes.
typedef C2paSignCallback = Future<Uint8List> Function(Uint8List data);

/// Callback that verifies a signature over canonical claim bytes.
typedef C2paVerifyCallback = Future<bool> Function({
  required String algorithm,
  required Uint8List data,
  required Uint8List signature,
  required Uint8List publicKey,
});

/// Signer used to produce C2PA claim signatures.
abstract interface class C2paSigner {
  /// Signature algorithm name advertised in the claim.
  String get algorithm;

  /// Signs [data] and returns the raw signature bytes.
  Future<Uint8List> sign(Uint8List data);
}

/// A signer that explicitly declares the exact signature-space reservation
/// needed by embedded DataHash placeholder workflows.
abstract interface class C2paReservedSizeSigner implements C2paSigner {
  /// Exact reserved signature size in bytes; zero is not a reservation.
  int get reservedSignatureSize;
}

/// Verifier used to check C2PA claim signatures.
abstract interface class C2paVerifier {
  /// Verifies [signature] over [data] with [publicKey].
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  });
}

/// [C2paSigner] adapter backed by a [C2paSignCallback].
final class CallbackC2paSigner implements C2paReservedSizeSigner {
  /// Creates a callback-backed signer.
  const CallbackC2paSigner({
    required this.algorithm,
    required this.callback,
    this.reservedSignatureSize = 0,
  });

  @override
  /// Signature algorithm name passed through to C2PA metadata.
  final String algorithm;

  /// Callback invoked by [sign].
  final C2paSignCallback callback;

  @override
  /// Reserved signature size in bytes for placeholder workflows.
  final int reservedSignatureSize;

  @override
  Future<Uint8List> sign(Uint8List data) => callback(data);
}

/// [C2paVerifier] adapter backed by a [C2paVerifyCallback].
final class CallbackC2paVerifier implements C2paVerifier {
  /// Creates a callback-backed verifier.
  const CallbackC2paVerifier(this.callback);

  /// Callback invoked by [verify].
  final C2paVerifyCallback callback;

  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) => callback(
    algorithm: algorithm,
    data: data,
    signature: signature,
    publicKey: publicKey,
  );
}

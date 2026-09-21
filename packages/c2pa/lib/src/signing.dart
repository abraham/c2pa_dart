import 'dart:typed_data';

typedef C2paSignCallback = Future<Uint8List> Function(Uint8List data);

typedef C2paVerifyCallback = Future<bool> Function({
  required String algorithm,
  required Uint8List data,
  required Uint8List signature,
  required Uint8List publicKey,
});

abstract interface class C2paSigner {
  String get algorithm;

  Future<Uint8List> sign(Uint8List data);
}

/// A signer that explicitly declares the exact signature-space reservation
/// needed by embedded DataHash placeholder workflows.
abstract interface class C2paReservedSizeSigner implements C2paSigner {
  int get reservedSignatureSize;
}

abstract interface class C2paVerifier {
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  });
}

final class CallbackC2paSigner implements C2paReservedSizeSigner {
  const CallbackC2paSigner({
    required this.algorithm,
    required this.callback,
    this.reservedSignatureSize = 0,
  });

  @override
  final String algorithm;
  final C2paSignCallback callback;

  @override
  final int reservedSignatureSize;

  @override
  Future<Uint8List> sign(Uint8List data) => callback(data);
}

final class CallbackC2paVerifier implements C2paVerifier {
  const CallbackC2paVerifier(this.callback);

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

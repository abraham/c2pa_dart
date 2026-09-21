import 'dart:typed_data';

typedef C2paTimestampCallback = Future<Uint8List> Function(
  Uint8List requestDer,
);

/// Immutable timestamp configuration for a Builder claim signature.
final class C2paTimestampConfig {
  C2paTimestampConfig.callback({
    required this.callback,
    required this.reservedSize,
    this.hashAlgorithm = 'sha256',
    this.policyOid,
    this.nonce,
    this.timeout,
  }) : _token = null {
    _validate();
  }

  C2paTimestampConfig.token(
    Uint8List token, {
    int? reservedSize,
    this.hashAlgorithm = 'sha256',
  }) : callback = null,
       policyOid = null,
       nonce = null,
       timeout = null,
       reservedSize = reservedSize ?? token.length,
       _token = Uint8List.fromList(token).asUnmodifiableView() {
    _validate();
  }

  final C2paTimestampCallback? callback;
  final Uint8List? _token;
  final int reservedSize;
  final String hashAlgorithm;
  final String? policyOid;
  final BigInt? nonce;
  final Duration? timeout;

  Uint8List? get token =>
      _token == null ? null : Uint8List.fromList(_token).asUnmodifiableView();

  bool get usesCallback => callback != null;

  void _validate() {
    if (reservedSize <= 0) {
      throw ArgumentError.value(
        reservedSize,
        'reservedSize',
        'Must be positive',
      );
    }
    if (_token != null && _token.length > reservedSize) {
      throw ArgumentError.value(
        _token.length,
        'token',
        'Timestamp token exceeds its reservation',
      );
    }
    if (timeout != null && timeout! <= Duration.zero) {
      throw ArgumentError.value(timeout, 'timeout', 'Must be positive');
    }
    if (nonce != null && nonce! < BigInt.zero) {
      throw ArgumentError.value(nonce, 'nonce', 'Must not be negative');
    }
  }
}

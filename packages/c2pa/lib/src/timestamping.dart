import 'dart:typed_data';

/// Callback that exchanges a timestamp request for a timestamp token.
typedef C2paTimestampCallback = Future<Uint8List> Function(
  Uint8List requestDer,
);

/// Immutable timestamp configuration for a Builder claim signature.
final class C2paTimestampConfig {
  /// Creates timestamping config that obtains a token by callback.
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

  /// Creates timestamping config from a precomputed token.
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

  /// Timestamp callback, or `null` when [token] is precomputed.
  final C2paTimestampCallback? callback;
  final Uint8List? _token;

  /// Reserved timestamp token size in bytes.
  final int reservedSize;

  /// Hash algorithm used in timestamp requests; default `sha256`.
  final String hashAlgorithm;

  /// Optional timestamp policy OID requested from the authority.
  final String? policyOid;

  /// Optional non-negative nonce included in timestamp requests.
  final BigInt? nonce;

  /// Optional positive timeout for the timestamp callback.
  final Duration? timeout;

  /// Immutable timestamp token bytes, or `null` when callback-based.
  Uint8List? get token =>
      _token == null ? null : Uint8List.fromList(_token).asUnmodifiableView();

  /// Whether timestamping requires invoking [callback].
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

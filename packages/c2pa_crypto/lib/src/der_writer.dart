/// Minimal strict DER encoding helpers shared by the key encoding backends.
///
/// These mirror the strictness of [DerReader]: minimal length encoding and
/// minimal, non-negative `INTEGER` content. They only cover the handful of
/// universal types needed to build `PrivateKeyInfo` (PKCS#8) and
/// `SubjectPublicKeyInfo` (SPKI) structures.
library;

import 'dart:typed_data';

/// Encodes a definite-form DER length for [length] bytes of content.
Uint8List derLength(int length) {
  if (length < 0) {
    throw ArgumentError.value(length, 'length', 'Must be non-negative');
  }
  if (length < 0x80) {
    return Uint8List.fromList([length]);
  }
  final bytes = <int>[];
  var remaining = length;
  while (remaining != 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
}

/// Encodes a single DER tag-length-value triple for [tag] and [content].
Uint8List derTlv(int tag, List<int> content) =>
    Uint8List.fromList([tag, ...derLength(content.length), ...content]);

/// Encodes a `SEQUENCE` whose content is the concatenation of [children].
Uint8List derSequence(List<List<int>> children) =>
    derTlv(0x30, children.expand((child) => child).toList(growable: false));

/// Encodes a DER `NULL`.
Uint8List derNull() => derTlv(0x05, const []);

/// Encodes a DER `OBJECT IDENTIFIER` from its raw content octets.
Uint8List derOid(List<int> oidBytes) => derTlv(0x06, oidBytes);

/// Encodes a DER `OCTET STRING`.
Uint8List derOctetString(List<int> content) => derTlv(0x04, content);

/// Encodes a DER `BIT STRING` with [unusedBits] trailing padding bits.
Uint8List derBitString(List<int> content, {int unusedBits = 0}) =>
    derTlv(0x03, [unusedBits, ...content]);

/// Encodes a non-negative [value] as a minimal, strictly positive DER
/// `INTEGER`.
Uint8List derInteger(BigInt value) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'Must be non-negative');
  }
  if (value == BigInt.zero) {
    return derTlv(0x02, const [0]);
  }
  final bytes = unsignedBigIntBytes(value);
  final content = bytes.first & 0x80 != 0 ? [0, ...bytes] : bytes;
  return derTlv(0x02, content);
}

/// Encodes [value] as a fixed-width big-endian unsigned integer.
///
/// Throws [ArgumentError] when [value] does not fit in [length] bytes.
Uint8List derFixedWidthUnsigned(BigInt value, int length) {
  final bytes = unsignedBigIntBytes(value);
  if (bytes.length > length) {
    throw ArgumentError.value(value, 'value', 'Exceeds $length bytes');
  }
  return Uint8List.fromList([
    ...List<int>.filled(length - bytes.length, 0),
    ...bytes,
  ]);
}

/// Encodes a non-negative [value] as minimal big-endian bytes.
///
/// Returns a single zero byte for [BigInt.zero].
List<int> unsignedBigIntBytes(BigInt value) {
  if (value.isNegative) {
    throw ArgumentError.value(value, 'value', 'Must be non-negative');
  }
  if (value == BigInt.zero) {
    return const [0];
  }
  var hex = value.toRadixString(16);
  if (hex.length.isOdd) {
    hex = '0$hex';
  }
  final bytes = <int>[];
  for (var index = 0; index < hex.length; index += 2) {
    bytes.add(int.parse(hex.substring(index, index + 2), radix: 16));
  }
  return bytes;
}

/// Decodes big-endian [bytes] as a non-negative [BigInt].
BigInt bigIntFromUnsignedBytes(List<int> bytes) {
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

/// Shared fixed-width integer readers for asset format handlers.
///
/// Every container this package parses is a tree of length-prefixed boxes,
/// chunks, or segments, so each handler needs the same handful of big- and
/// little-endian reads. Keeping one implementation means a bounds or width
/// mistake can only be made once.
///
/// All readers take `List<int>` rather than [Uint8List] because handlers pass
/// both raw reads and views. Reading past the end of a buffer throws
/// [RangeError] on the VM and a plain [ArgumentError] on the web, so callers
/// that catch it should match [ArgumentError].
library;

import 'dart:typed_data';

/// The largest byte offset that a Dart [int] represents exactly on every
/// platform.
///
/// On the web an [int] is a double, so values above 2^53-1 silently lose
/// precision. Offsets are compared and added throughout this package, so a
/// declared size beyond this bound is rejected rather than rounded.
const int maxExactByteValue = 0x1fffffffffffff;

ByteData _view(List<int> bytes) => ByteData.sublistView(
  bytes is Uint8List ? bytes : Uint8List.fromList(bytes),
);

/// Reads a big-endian unsigned 16-bit integer at [offset].
int readUint16Be(List<int> bytes, int offset) =>
    _view(bytes).getUint16(offset, Endian.big);

/// Reads a little-endian unsigned 16-bit integer at [offset].
int readUint16Le(List<int> bytes, int offset) =>
    _view(bytes).getUint16(offset, Endian.little);

/// Reads a big-endian unsigned 32-bit integer at [offset].
int readUint32Be(List<int> bytes, int offset) =>
    _view(bytes).getUint32(offset, Endian.big);

/// Reads a little-endian unsigned 32-bit integer at [offset].
int readUint32Le(List<int> bytes, int offset) =>
    _view(bytes).getUint32(offset, Endian.little);

/// Reads a big-endian unsigned 64-bit integer at [offset], or returns `null`
/// when the value exceeds [maxExactByteValue].
///
/// The two halves are combined by multiplication rather than by shifting.
/// Shifting is 32-bit on the web, which would silently discard the high word
/// and turn an oversized declared size into a small one.
int? tryReadUint64Be(List<int> bytes, int offset) {
  final data = _view(bytes);
  final high = data.getUint32(offset, Endian.big);
  final low = data.getUint32(offset + 4, Endian.big);
  return high > 0x1fffff ? null : high * 0x100000000 + low;
}

/// Reads a little-endian unsigned 64-bit integer at [offset], or returns
/// `null` when the value exceeds [maxExactByteValue].
int? tryReadUint64Le(List<int> bytes, int offset) {
  final data = _view(bytes);
  final low = data.getUint32(offset, Endian.little);
  final high = data.getUint32(offset + 4, Endian.little);
  return high > 0x1fffff ? null : high * 0x100000000 + low;
}

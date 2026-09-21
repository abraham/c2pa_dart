import 'dart:typed_data';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';
import 'random_access_byte_source.dart';

/// A sequential reader constrained to a fixed range of a byte source.
final class BoundedByteReader {
  /// Creates a reader over [bounds] in [source] starting at the range start.
  BoundedByteReader(this.source, this.bounds) : _position = bounds.start;

  /// Source used for every random-access read.
  final RandomAccessByteSource source;

  /// Absolute byte range this reader is allowed to consume.
  final ByteRange bounds;
  int _position;

  /// Current offset relative to the start of [bounds].
  int get position => _position - bounds.start;

  /// Current byte offset relative to the start of [source].
  int get absolutePosition => _position;

  /// Number of bytes remaining before the end of [bounds].
  int get remaining => bounds.end - _position;

  /// Whether the reader position is exactly at the end of [bounds].
  bool get isAtEnd => _position == bounds.end;

  /// Moves to [position] bytes from the start of [bounds].
  void seek(int position) {
    final absolute = ByteRange.checkedAdd(bounds.start, position);
    final target = ByteRange(absolute, absolute);
    if (!bounds.containsRange(target)) {
      throw ByteRangeOutOfBoundsException(target, bounds);
    }
    _position = absolute;
  }

  /// Reads exactly [count] bytes and advances the reader position.
  Future<Uint8List> readExact(int count) async {
    final range = ByteRange.fromStartAndLength(_position, count);
    if (!bounds.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, bounds);
    }

    final bytes = await source.read(range);
    if (bytes.length != count) {
      throw TruncatedReadException(
        range: range,
        expectedLength: count,
        actualLength: bytes.length,
      );
    }
    _position = range.end;
    return Uint8List.fromList(bytes);
  }

  /// Reads an unsigned 8-bit integer and advances by one byte.
  Future<int> readUint8() async => (await readExact(1))[0];

  /// Reads a big-endian unsigned 16-bit integer and advances by two bytes.
  Future<int> readUint16() async =>
      ByteData.sublistView(await readExact(2)).getUint16(0, Endian.big);

  /// Reads a big-endian unsigned 32-bit integer and advances by four bytes.
  Future<int> readUint32() async =>
      ByteData.sublistView(await readExact(4)).getUint32(0, Endian.big);

  /// Reads a big-endian unsigned 64-bit integer and advances by eight bytes.
  Future<int> readUint64() async =>
      ByteData.sublistView(await readExact(8)).getUint64(0, Endian.big);
}

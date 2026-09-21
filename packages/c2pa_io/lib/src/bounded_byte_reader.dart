import 'dart:typed_data';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';
import 'random_access_byte_source.dart';

/// A sequential reader constrained to a fixed range of a byte source.
final class BoundedByteReader {
  BoundedByteReader(this.source, this.bounds) : _position = bounds.start;

  final RandomAccessByteSource source;
  final ByteRange bounds;
  int _position;

  int get position => _position - bounds.start;
  int get absolutePosition => _position;
  int get remaining => bounds.end - _position;
  bool get isAtEnd => _position == bounds.end;

  void seek(int position) {
    final absolute = ByteRange.checkedAdd(bounds.start, position);
    final target = ByteRange(absolute, absolute);
    if (!bounds.containsRange(target)) {
      throw ByteRangeOutOfBoundsException(target, bounds);
    }
    _position = absolute;
  }

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

  Future<int> readUint8() async => (await readExact(1))[0];

  Future<int> readUint16() async =>
      ByteData.sublistView(await readExact(2)).getUint16(0, Endian.big);

  Future<int> readUint32() async =>
      ByteData.sublistView(await readExact(4)).getUint32(0, Endian.big);

  Future<int> readUint64() async =>
      ByteData.sublistView(await readExact(8)).getUint64(0, Endian.big);
}

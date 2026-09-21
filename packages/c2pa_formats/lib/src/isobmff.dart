import 'package:c2pa_io/c2pa_io.dart';

final class IsoBmffBox {
  IsoBmffBox({
    required this.type,
    required this.offset,
    required this.size,
    required this.headerSize,
    required this.usesExtendedSize,
    required this.extendsToEnd,
    Iterable<int>? userType,
  }) : userType = userType == null ? null : List<int>.unmodifiable(userType);

  final String type;
  final int offset;
  final int size;
  final int headerSize;
  final bool usesExtendedSize;
  final bool extendsToEnd;
  final List<int>? userType;

  int get end => offset + size;
  int get payloadOffset => offset + headerSize;
  int get payloadLength => size - headerSize;
  ByteRange get range => ByteRange(offset, end);
}

abstract interface class IsoBmffBoxProvider {
  Future<List<IsoBmffBox>> getTopLevelBoxes(RandomAccessByteSource source);
}

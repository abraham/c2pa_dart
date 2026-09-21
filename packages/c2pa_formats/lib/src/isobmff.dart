import 'package:c2pa_io/c2pa_io.dart';

/// A top-level ISO BMFF box discovered in an asset.
final class IsoBmffBox {
  /// Creates metadata for one ISO BMFF box.
  IsoBmffBox({
    required this.type,
    required this.offset,
    required this.size,
    required this.headerSize,
    required this.usesExtendedSize,
    required this.extendsToEnd,
    Iterable<int>? userType,
  }) : userType = userType == null ? null : List<int>.unmodifiable(userType);

  /// Four-character ISO BMFF box type, such as `ftyp` or `uuid`.
  final String type;

  /// Absolute byte offset of the box header.
  final int offset;

  /// Total box size in bytes, including the header and payload.
  final int size;

  /// Header size in bytes, including any extended-size or user type fields.
  final int headerSize;

  /// Whether the box uses the 64-bit ISO BMFF extended-size field.
  final bool usesExtendedSize;

  /// Whether a size-zero box extends to end of file.
  final bool extendsToEnd;

  /// The 16-byte UUID for a `uuid` box, or `null` for other box types.
  final List<int>? userType;

  /// Absolute byte offset immediately after the box.
  int get end => offset + size;

  /// Absolute byte offset where the box payload begins.
  int get payloadOffset => offset + headerSize;

  /// Payload length in bytes, excluding the box header.
  int get payloadLength => size - headerSize;

  /// Absolute half-open byte range for the complete box.
  ByteRange get range => ByteRange(offset, end);
}

/// A handler capability for listing top-level ISO BMFF boxes.
abstract interface class IsoBmffBoxProvider {
  /// Returns top-level boxes in [source] in file order.
  Future<List<IsoBmffBox>> getTopLevelBoxes(RandomAccessByteSource source);
}

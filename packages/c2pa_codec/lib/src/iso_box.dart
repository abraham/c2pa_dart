import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

const int _uint32Limit = 0xffffffff;
const int _maxSafeInteger = 9007199254740991;
final BigInt _maxSafeIntegerBig = BigInt.from(_maxSafeInteger);

/// Parses an ISO box header at [offset], bounded by [end].
IsoBoxHeader parseIsoBoxHeader(List<int> bytes, {int offset = 0, int? end}) =>
    IsoBoxHeader.parse(bytes, offset: offset, end: end);

/// Creates and encodes an ISO box header.
Uint8List encodeIsoBoxHeader({
  required String type,
  required int payloadSize,
  Uint8List? userType,
  bool forceLargeSize = false,
}) => IsoBoxHeader.create(
  type: type,
  payloadSize: payloadSize,
  userType: userType,
  forceLargeSize: forceLargeSize,
).encode();

/// A parsed or newly constructed ISO base media file format box header.
final class IsoBoxHeader {
  IsoBoxHeader._({
    required this.type,
    required this.size,
    required this.headerSize,
    required this.offset,
    required this.extendsToEnd,
    Uint8List? userType,
  }) : _userType = userType == null ? null : Uint8List.fromList(userType);

  /// The four-character box type.
  final String type;

  /// Total box size, including this header.
  final int size;

  /// Header size: 8, 16, 24, or 32 bytes.
  final int headerSize;

  /// Offset at which the header begins in the parsed source.
  final int offset;

  /// Whether the encoded 32-bit size was zero, meaning "to end of parent".
  final bool extendsToEnd;

  final Uint8List? _userType;

  /// A copy of the 16-byte user type for a `uuid` box.
  Uint8List? get userType {
    final value = _userType;
    return value == null ? null : Uint8List.fromList(value);
  }

  /// Payload size in bytes, excluding the encoded box header.
  int get payloadSize => size - headerSize;

  /// Byte offset immediately after this box within the parsed source.
  int get endOffset => offset + size;

  /// Whether this header uses the 64-bit `largesize` field.
  bool get isLargeSize => headerSize == 16 || headerSize == 32;

  /// Whether [type] is the ISO `uuid` extension box type.
  bool get isUuid => type == 'uuid';

  /// Parses one box header at [offset], bounded by [end].
  ///
  /// A zero 32-bit size extends to [end]. The returned [size] is always the
  /// resolved total size.
  static IsoBoxHeader parse(List<int> bytes, {int offset = 0, int? end}) {
    final input = bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
    final limit = end ?? input.length;
    if (offset < 0 || limit < offset || limit > input.length) {
      throw IsoBoxException(
        IsoBoxErrorCode.invalidOffset,
        'Invalid box bounds [$offset, $limit) for ${input.length} bytes',
        offset: offset,
      );
    }
    if (limit - offset < 8) {
      throw IsoBoxException(
        IsoBoxErrorCode.truncated,
        'ISO box header requires at least 8 bytes',
        offset: offset,
      );
    }

    final data = ByteData.sublistView(input);
    final size32 = data.getUint32(offset, Endian.big);
    final typeBytes = input.sublist(offset + 4, offset + 8);
    final type = _decodeType(typeBytes, offset + 4);
    var cursor = offset + 8;
    var headerSize = 8;
    var extendsToEnd = false;
    late int size;

    if (size32 == 1) {
      if (limit - cursor < 8) {
        throw IsoBoxException(
          IsoBoxErrorCode.truncated,
          'Large-size ISO box header is truncated',
          offset: cursor,
        );
      }
      final largeSize = _readUint64(input, cursor);
      if (largeSize > _maxSafeIntegerBig) {
        throw IsoBoxException(
          IsoBoxErrorCode.sizeOutOfRange,
          'Large box size cannot be addressed on this platform',
          offset: cursor,
        );
      }
      if (largeSize > BigInt.from(limit - offset)) {
        throw IsoBoxException(
          IsoBoxErrorCode.truncated,
          'Box declares $largeSize bytes but only ${limit - offset} are available',
          offset: offset,
        );
      }
      size = largeSize.toInt();
      cursor += 8;
      headerSize += 8;
    } else if (size32 == 0) {
      size = limit - offset;
      extendsToEnd = true;
    } else {
      size = size32;
    }

    Uint8List? userType;
    if (type == 'uuid') {
      if (limit - cursor < 16) {
        throw IsoBoxException(
          IsoBoxErrorCode.truncated,
          'UUID box header is missing its 16-byte user type',
          offset: cursor,
        );
      }
      userType = Uint8List.fromList(input.sublist(cursor, cursor + 16));
      cursor += 16;
      headerSize += 16;
    }

    if (size < headerSize) {
      throw IsoBoxException(
        IsoBoxErrorCode.invalidSize,
        'Box size $size is smaller than its $headerSize-byte header',
        offset: offset,
      );
    }
    if (size > limit - offset) {
      throw IsoBoxException(
        IsoBoxErrorCode.truncated,
        'Box declares $size bytes but only ${limit - offset} are available',
        offset: offset,
      );
    }

    return IsoBoxHeader._(
      type: type,
      size: size,
      headerSize: headerSize,
      offset: offset,
      extendsToEnd: extendsToEnd,
      userType: userType,
    );
  }

  /// Creates a header and chooses 32-bit or large-size representation.
  factory IsoBoxHeader.create({
    required String type,
    required int payloadSize,
    Uint8List? userType,
    bool forceLargeSize = false,
  }) {
    _validateType(type);
    if (payloadSize < 0) {
      throw const IsoBoxException(
        IsoBoxErrorCode.invalidSize,
        'Payload size must not be negative',
      );
    }
    if (type == 'uuid') {
      if (userType == null || userType.length != 16) {
        throw const IsoBoxException(
          IsoBoxErrorCode.missingUserType,
          'A UUID box requires a 16-byte user type',
        );
      }
    } else if (userType != null) {
      throw const IsoBoxException(
        IsoBoxErrorCode.unexpectedUserType,
        'Only a UUID box may have a user type',
      );
    }

    final uuidBytes = type == 'uuid' ? 16 : 0;
    var headerSize = 8 + uuidBytes;
    if (payloadSize > _maxSafeInteger - headerSize) {
      throw const IsoBoxException(
        IsoBoxErrorCode.sizeOutOfRange,
        'Box size cannot be addressed on this platform',
      );
    }
    var size = headerSize + payloadSize;
    if (forceLargeSize || size > _uint32Limit) {
      if (size > _maxSafeInteger - 8) {
        throw const IsoBoxException(
          IsoBoxErrorCode.sizeOutOfRange,
          'Box size cannot be addressed on this platform',
        );
      }
      headerSize += 8;
      size += 8;
    }
    return IsoBoxHeader._(
      type: type,
      size: size,
      headerSize: headerSize,
      offset: 0,
      extendsToEnd: false,
      userType: userType,
    );
  }

  /// Encodes this header. Parsed zero-size headers retain zero-size encoding.
  Uint8List encode() {
    final output = ByteData(headerSize);
    if (extendsToEnd) {
      output.setUint32(0, 0, Endian.big);
    } else if (isLargeSize) {
      output.setUint32(0, 1, Endian.big);
      _writeUint64(output.buffer.asUint8List(), 8, BigInt.from(size));
    } else {
      output.setUint32(0, size, Endian.big);
    }
    final typeBytes = ascii.encode(type);
    output.buffer.asUint8List().setRange(4, 8, typeBytes);
    final uuid = _userType;
    if (uuid != null) {
      output.buffer.asUint8List().setRange(headerSize - 16, headerSize, uuid);
    }
    return output.buffer.asUint8List();
  }

  /// Writes this header into [destination] at [offset].
  void writeTo(Uint8List destination, {int offset = 0}) {
    if (offset < 0 || headerSize > destination.length - offset) {
      throw IsoBoxException(
        IsoBoxErrorCode.invalidOffset,
        'The $headerSize-byte header does not fit at offset $offset',
        offset: offset,
      );
    }
    destination.setRange(offset, offset + headerSize, encode());
  }
}

String _decodeType(List<int> bytes, int offset) {
  if (bytes.any((byte) => byte < 0x20 || byte > 0x7e)) {
    throw IsoBoxException(
      IsoBoxErrorCode.invalidType,
      'Box type must contain four printable ASCII characters',
      offset: offset,
    );
  }
  return ascii.decode(bytes);
}

void _validateType(String type) {
  final bytes = type.codeUnits;
  if (type.length != 4 ||
      bytes.length != 4 ||
      bytes.any((byte) => byte < 0x20 || byte > 0x7e)) {
    throw const IsoBoxException(
      IsoBoxErrorCode.invalidType,
      'Box type must contain exactly four printable ASCII characters',
    );
  }
}

BigInt _readUint64(Uint8List bytes, int offset) {
  var value = BigInt.zero;
  for (var index = 0; index < 8; index++) {
    value = (value << 8) | BigInt.from(bytes[offset + index]);
  }
  return value;
}

void _writeUint64(Uint8List bytes, int offset, BigInt value) {
  var remaining = value;
  for (var index = 7; index >= 0; index--) {
    bytes[offset + index] = (remaining & BigInt.from(0xff)).toInt();
    remaining >>= 8;
  }
}

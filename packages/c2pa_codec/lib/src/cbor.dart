import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';

const int _maxSafeInteger = 9007199254740991;
final BigInt _maxSafeIntegerBig = BigInt.from(_maxSafeInteger);
final BigInt _minSafeIntegerBig = -_maxSafeIntegerBig;
final BigInt _uint64Max = BigInt.parse('18446744073709551615');
final BigInt _minimumNint64 = -(_uint64Max + BigInt.one);

/// Encodes [value] as deterministic, definite-length CBOR.
///
/// Supported values are `null`, [bool], [int], [BigInt], finite [double],
/// [String], [Uint8List], [List], and [Map]. Values outside JavaScript's safe
/// integer range decode as [BigInt].
Uint8List encodeCbor(Object? value, {int maxNestingDepth = 64}) =>
    CborCodec(maxNestingDepth: maxNestingDepth).encode(value);

/// Decodes exactly one strict, deterministic CBOR data item.
Object? decodeCbor(
  List<int> bytes, {
  int maxNestingDepth = 64,
  bool requireCanonicalMapOrder = true,
  bool allowIndefiniteLength = false,
}) => CborCodec(
  maxNestingDepth: maxNestingDepth,
  requireCanonicalMapOrder: requireCanonicalMapOrder,
  allowIndefiniteLength: allowIndefiniteLength,
).decode(bytes);

/// A deterministic CBOR encoder and strict decoder.
final class CborCodec {
  const CborCodec({
    this.maxNestingDepth = 64,
    this.requireCanonicalMapOrder = true,
    this.allowIndefiniteLength = false,
  }) : assert(maxNestingDepth >= 0);

  final int maxNestingDepth;
  final bool requireCanonicalMapOrder;
  final bool allowIndefiniteLength;

  Uint8List encode(Object? value) {
    if (maxNestingDepth < 0) {
      throw const CborEncodingException(
        CborEncodingErrorCode.excessiveNesting,
        'maxNestingDepth must not be negative',
      );
    }
    final output = BytesBuilder(copy: false);
    _CborEncoder(output, maxNestingDepth).write(value, 0);
    return output.takeBytes();
  }

  Object? decode(List<int> bytes) {
    if (maxNestingDepth < 0) {
      throw CborDecodingException(
        CborDecodingErrorCode.excessiveNesting,
        'maxNestingDepth must not be negative',
        offset: 0,
      );
    }
    final input = bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
    final decoder = _CborDecoder(
      input,
      maxNestingDepth,
      requireCanonicalMapOrder: requireCanonicalMapOrder,
      allowIndefiniteLength: allowIndefiniteLength,
    );
    final value = decoder.read(0);
    if (!decoder.isAtEnd) {
      throw CborDecodingException(
        CborDecodingErrorCode.trailingData,
        'Trailing data follows the top-level CBOR item',
        offset: decoder.offset,
      );
    }
    return value;
  }
}

final class _CborEncoder {
  _CborEncoder(this.output, this.maxDepth);

  final BytesBuilder output;
  final int maxDepth;

  void write(Object? value, int depth) {
    if (depth > maxDepth) {
      throw CborEncodingException(
        CborEncodingErrorCode.excessiveNesting,
        'CBOR nesting exceeds the configured limit of $maxDepth',
      );
    }
    if (value == null) {
      output.addByte(0xf6);
    } else if (value is bool) {
      output.addByte(value ? 0xf5 : 0xf4);
    } else if (value is int) {
      if (value > _maxSafeInteger || value < -_maxSafeInteger) {
        throw CborEncodingException(
          CborEncodingErrorCode.integerOutOfRange,
          'Use BigInt for integers outside the JavaScript-safe range: $value',
        );
      }
      _writeInteger(BigInt.from(value));
    } else if (value is BigInt) {
      _writeInteger(value);
    } else if (value is double) {
      _writeDouble(value);
    } else if (value is Uint8List) {
      _writeBytes(value);
    } else if (value is String) {
      final encoded = utf8.encode(value);
      _writeArgument(3, BigInt.from(encoded.length));
      output.add(encoded);
    } else if (value is List) {
      _writeArgument(4, BigInt.from(value.length));
      for (final item in value) {
        write(item, depth + 1);
      }
    } else if (value is Map) {
      _writeMap(value, depth);
    } else {
      throw CborEncodingException(
        CborEncodingErrorCode.unsupportedType,
        'Unsupported CBOR value type: ${value.runtimeType}',
      );
    }
  }

  void _writeInteger(BigInt value) {
    if (value > _uint64Max || value < _minimumNint64) {
      throw CborEncodingException(
        CborEncodingErrorCode.integerOutOfRange,
        'Integer is outside the supported signed 64-bit range: $value',
      );
    }
    if (!value.isNegative) {
      _writeArgument(0, value);
    } else {
      _writeArgument(1, -BigInt.one - value);
    }
  }

  void _writeDouble(double value) {
    if (!value.isFinite) {
      throw const CborEncodingException(
        CborEncodingErrorCode.nonFiniteDouble,
        'Only finite CBOR floating-point values are supported',
      );
    }
    final data = ByteData(9)
      ..setUint8(0, 0xfb)
      ..setFloat64(1, value, Endian.big);
    output.add(data.buffer.asUint8List());
  }

  void _writeBytes(Uint8List bytes) {
    _writeArgument(2, BigInt.from(bytes.length));
    output.add(bytes);
  }

  void _writeMap(Map<dynamic, dynamic> map, int depth) {
    final entries = <_EncodedMapEntry>[];
    for (final entry in map.entries) {
      final keyOutput = BytesBuilder(copy: false);
      _CborEncoder(keyOutput, maxDepth).write(entry.key, depth + 1);
      entries.add(_EncodedMapEntry(keyOutput.takeBytes(), entry.value));
    }
    entries.sort((a, b) => _compareCanonicalKeys(a.key, b.key));
    for (var index = 1; index < entries.length; index++) {
      if (_compareBytes(entries[index - 1].key, entries[index].key) == 0) {
        throw const CborEncodingException(
          CborEncodingErrorCode.duplicateMapKey,
          'Map contains keys with identical canonical CBOR encodings',
        );
      }
    }
    _writeArgument(5, BigInt.from(entries.length));
    for (final entry in entries) {
      output.add(entry.key);
      write(entry.value, depth + 1);
    }
  }

  void _writeArgument(int majorType, BigInt argument) {
    if (argument.isNegative || argument > _uint64Max) {
      throw CborEncodingException(
        CborEncodingErrorCode.integerOutOfRange,
        'CBOR argument is outside the supported range: $argument',
      );
    }
    final prefix = majorType << 5;
    if (argument < BigInt.from(24)) {
      output.addByte(prefix | argument.toInt());
    } else if (argument <= BigInt.from(0xff)) {
      output.add([prefix | 24, argument.toInt()]);
    } else if (argument <= BigInt.from(0xffff)) {
      _writeFixedWidth(prefix | 25, argument, 2);
    } else if (argument <= BigInt.from(0xffffffff)) {
      _writeFixedWidth(prefix | 26, argument, 4);
    } else {
      _writeFixedWidth(prefix | 27, argument, 8);
    }
  }

  void _writeFixedWidth(int initial, BigInt value, int byteCount) {
    final bytes = Uint8List(byteCount + 1);
    bytes[0] = initial;
    var remaining = value;
    for (var index = byteCount; index > 0; index--) {
      bytes[index] = (remaining & BigInt.from(0xff)).toInt();
      remaining >>= 8;
    }
    output.add(bytes);
  }
}

final class _CborDecoder {
  _CborDecoder(
    this.input,
    this.maxDepth, {
    required this.requireCanonicalMapOrder,
    required this.allowIndefiniteLength,
  });

  final Uint8List input;
  final int maxDepth;
  final bool requireCanonicalMapOrder;
  final bool allowIndefiniteLength;
  int offset = 0;

  bool get isAtEnd => offset == input.length;

  Object? read(int depth) {
    if (depth > maxDepth) {
      _fail(
        CborDecodingErrorCode.excessiveNesting,
        'CBOR nesting exceeds the configured limit of $maxDepth',
      );
    }
    final initialOffset = offset;
    final initial = _readByte();
    final majorType = initial >> 5;
    final additional = initial & 0x1f;

    if (additional == 31) {
      if (allowIndefiniteLength) {
        return switch (majorType) {
          2 => _readIndefiniteByteString(depth),
          3 => _readIndefiniteTextString(depth),
          4 => _readIndefiniteArray(depth),
          5 => _readIndefiniteMap(depth),
          _ => _failAt(
            CborDecodingErrorCode.indefiniteLength,
            'Invalid indefinite-length CBOR item',
            initialOffset,
          ),
        };
      }
      _failAt(
        CborDecodingErrorCode.indefiniteLength,
        'Indefinite-length CBOR items are not supported',
        initialOffset,
      );
    }

    switch (majorType) {
      case 0:
        return _narrowInteger(_readArgument(additional, initialOffset));
      case 1:
        return _narrowInteger(
          -BigInt.one - _readArgument(additional, initialOffset),
        );
      case 2:
        return _readByteString(
          _readLength(additional, initialOffset, bytesPerItem: 1),
        );
      case 3:
        return _readTextString(
          _readLength(additional, initialOffset, bytesPerItem: 1),
        );
      case 4:
        return _readArray(
          _readLength(additional, initialOffset, bytesPerItem: 1),
          depth,
        );
      case 5:
        return _readMap(
          _readLength(additional, initialOffset, bytesPerItem: 2),
          depth,
        );
      case 6:
        _failAt(
          CborDecodingErrorCode.unsupportedTag,
          'CBOR tags are not supported',
          initialOffset,
        );
      case 7:
        return _readSimple(additional, initialOffset);
    }
    throw StateError('Unreachable CBOR major type');
  }

  BigInt _readArgument(int additional, int initialOffset) {
    if (additional < 24) return BigInt.from(additional);
    late BigInt value;
    switch (additional) {
      case 24:
        value = BigInt.from(_readByte());
        if (value < BigInt.from(24)) {
          _nonMinimal(initialOffset);
        }
      case 25:
        value = _readUnsignedBig(2);
        if (value <= BigInt.from(0xff)) {
          _nonMinimal(initialOffset);
        }
      case 26:
        value = _readUnsignedBig(4);
        if (value <= BigInt.from(0xffff)) {
          _nonMinimal(initialOffset);
        }
      case 27:
        value = _readUnsignedBig(8);
        if (value <= BigInt.from(0xffffffff)) {
          _nonMinimal(initialOffset);
        }
      default:
        _failAt(
          CborDecodingErrorCode.invalidAdditionalInformation,
          'Reserved additional information value $additional',
          initialOffset,
        );
    }
    return value;
  }

  int _readLength(
    int additional,
    int initialOffset, {
    required int bytesPerItem,
  }) {
    final value = _readArgument(additional, initialOffset);
    final availableItems = (input.length - offset) ~/ bytesPerItem;
    if (value > _maxSafeIntegerBig) {
      _failAt(
        CborDecodingErrorCode.integerOutOfRange,
        'CBOR length cannot be addressed by the current input',
        initialOffset,
      );
    }
    if (value > BigInt.from(availableItems)) {
      _failAt(
        CborDecodingErrorCode.truncated,
        'CBOR item is truncated',
        initialOffset,
      );
    }
    return value.toInt();
  }

  Object _narrowInteger(BigInt value) {
    if (value >= _minSafeIntegerBig && value <= _maxSafeIntegerBig) {
      return value.toInt();
    }
    return value;
  }

  Uint8List _readByteString(int length) {
    _require(length);
    final value = Uint8List.fromList(input.sublist(offset, offset + length));
    offset += length;
    return value;
  }

  String _readTextString(int length) {
    final start = offset;
    _require(length);
    try {
      final value = utf8.decode(
        input.sublist(offset, offset + length),
        allowMalformed: false,
      );
      offset += length;
      return value;
    } on FormatException {
      _failAt(
        CborDecodingErrorCode.invalidUtf8,
        'Text string contains invalid UTF-8',
        start,
      );
    }
  }

  List<Object?> _readArray(int length, int depth) =>
      List<Object?>.generate(length, (_) => read(depth + 1), growable: false);

  Map<Object?, Object?> _readMap(int length, int depth) {
    final result = <Object?, Object?>{};
    final canonicalKeys = <String>{};
    Uint8List? previousKey;
    for (var index = 0; index < length; index++) {
      final keyStart = offset;
      final key = read(depth + 1);
      final encodedKey = Uint8List.fromList(input.sublist(keyStart, offset));
      final canonicalKeyOutput = BytesBuilder(copy: false);
      _CborEncoder(canonicalKeyOutput, maxDepth).write(key, 0);
      final canonicalKey = canonicalKeyOutput.takeBytes();
      if (!canonicalKeys.add(base64.encode(canonicalKey))) {
        _failAt(
          CborDecodingErrorCode.duplicateMapKey,
          'Map contains duplicate canonical keys',
          keyStart,
        );
      }
      if (requireCanonicalMapOrder && previousKey != null) {
        final comparison = _compareCanonicalKeys(previousKey, encodedKey);
        if (comparison > 0) {
          _failAt(
            CborDecodingErrorCode.nonCanonicalMapOrder,
            'Map keys are not in canonical order',
            keyStart,
          );
        }
      }
      previousKey = encodedKey;
      if (result.containsKey(key)) {
        _failAt(
          CborDecodingErrorCode.duplicateMapKey,
          'Map keys collide under Dart equality',
          keyStart,
        );
      }
      result[key] = read(depth + 1);
    }
    return Map<Object?, Object?>.unmodifiable(result);
  }

  Uint8List _readIndefiniteByteString(int depth) {
    final output = BytesBuilder(copy: false);
    while (!_consumeBreak()) {
      _require(1);
      final initial = input[offset];
      if (initial >> 5 != 2 || (initial & 0x1f) == 31) {
        _fail(
          CborDecodingErrorCode.indefiniteLength,
          'An indefinite byte string must contain definite byte strings',
        );
      }
      output.add(read(depth + 1) as Uint8List);
    }
    return output.takeBytes();
  }

  String _readIndefiniteTextString(int depth) {
    final output = StringBuffer();
    while (!_consumeBreak()) {
      _require(1);
      final initial = input[offset];
      if (initial >> 5 != 3 || (initial & 0x1f) == 31) {
        _fail(
          CborDecodingErrorCode.indefiniteLength,
          'An indefinite text string must contain definite text strings',
        );
      }
      output.write(read(depth + 1) as String);
    }
    return output.toString();
  }

  List<Object?> _readIndefiniteArray(int depth) {
    final result = <Object?>[];
    while (!_consumeBreak()) {
      result.add(read(depth + 1));
    }
    return List<Object?>.unmodifiable(result);
  }

  Map<Object?, Object?> _readIndefiniteMap(int depth) {
    final result = <Object?, Object?>{};
    final canonicalKeys = <String>{};
    while (!_consumeBreak()) {
      final keyStart = offset;
      final key = read(depth + 1);
      if (_consumeBreak()) {
        _failAt(
          CborDecodingErrorCode.truncated,
          'An indefinite map is missing a value',
          keyStart,
        );
      }
      final canonicalKeyOutput = BytesBuilder(copy: false);
      _CborEncoder(canonicalKeyOutput, maxDepth).write(key, 0);
      if (!canonicalKeys.add(base64.encode(canonicalKeyOutput.takeBytes())) ||
          result.containsKey(key)) {
        _failAt(
          CborDecodingErrorCode.duplicateMapKey,
          'Map contains duplicate keys',
          keyStart,
        );
      }
      result[key] = read(depth + 1);
    }
    return Map<Object?, Object?>.unmodifiable(result);
  }

  bool _consumeBreak() {
    _require(1);
    if (input[offset] != 0xff) return false;
    offset++;
    return true;
  }

  Object? _readSimple(int additional, int initialOffset) {
    switch (additional) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      case 25:
        return _finiteDouble(_readFloat16(), initialOffset);
      case 26:
        return _finiteDouble(_readFloat32(), initialOffset);
      case 27:
        return _finiteDouble(_readFloat64(), initialOffset);
      default:
        _failAt(
          CborDecodingErrorCode.unsupportedSimpleValue,
          'Unsupported CBOR simple or floating-point value',
          initialOffset,
        );
    }
  }

  double _finiteDouble(double value, int initialOffset) {
    if (!value.isFinite) {
      _failAt(
        CborDecodingErrorCode.nonFiniteDouble,
        'Only finite CBOR floating-point values are supported',
        initialOffset,
      );
    }
    return value;
  }

  double _readFloat16() {
    final bits = _readUnsignedBig(2).toInt();
    final sign = (bits & 0x8000) == 0 ? 1.0 : -1.0;
    final exponent = (bits >> 10) & 0x1f;
    final fraction = bits & 0x3ff;
    if (exponent == 0) {
      return sign * fraction * 5.960464477539063e-8;
    }
    if (exponent == 31) {
      return fraction == 0 ? sign * double.infinity : double.nan;
    }
    return sign * (1.0 + fraction / 1024.0) * _powerOfTwo(exponent - 15);
  }

  double _readFloat32() {
    _require(4);
    final value = ByteData.sublistView(
      input,
      offset,
      offset + 4,
    ).getFloat32(0, Endian.big);
    offset += 4;
    return value;
  }

  double _readFloat64() {
    _require(8);
    final value = ByteData.sublistView(
      input,
      offset,
      offset + 8,
    ).getFloat64(0, Endian.big);
    offset += 8;
    return value;
  }

  double _powerOfTwo(int exponent) {
    var result = 1.0;
    if (exponent >= 0) {
      for (var index = 0; index < exponent; index++) {
        result *= 2;
      }
    } else {
      for (var index = 0; index > exponent; index--) {
        result /= 2;
      }
    }
    return result;
  }

  int _readByte() {
    _require(1);
    return input[offset++];
  }

  BigInt _readUnsignedBig(int byteCount) {
    _require(byteCount);
    var value = BigInt.zero;
    for (var index = 0; index < byteCount; index++) {
      value = (value << 8) | BigInt.from(input[offset++]);
    }
    return value;
  }

  void _require(int byteCount) {
    if (byteCount < 0 || byteCount > input.length - offset) {
      _fail(CborDecodingErrorCode.truncated, 'CBOR item is truncated');
    }
  }

  Never _nonMinimal(int initialOffset) => _failAt(
    CborDecodingErrorCode.nonMinimalInteger,
    'CBOR integer or length is not minimally encoded',
    initialOffset,
  );

  Never _fail(CborDecodingErrorCode code, String message) =>
      _failAt(code, message, offset);

  Never _failAt(CborDecodingErrorCode code, String message, int at) {
    throw CborDecodingException(code, message, offset: at);
  }
}

final class _EncodedMapEntry {
  const _EncodedMapEntry(this.key, this.value);

  final Uint8List key;
  final Object? value;
}

int _compareCanonicalKeys(Uint8List a, Uint8List b) {
  final lengthComparison = a.length.compareTo(b.length);
  return lengthComparison != 0 ? lengthComparison : _compareBytes(a, b);
}

int _compareBytes(Uint8List a, Uint8List b) {
  final length = a.length < b.length ? a.length : b.length;
  for (var index = 0; index < length; index++) {
    final comparison = a[index].compareTo(b[index]);
    if (comparison != 0) return comparison;
  }
  return a.length.compareTo(b.length);
}

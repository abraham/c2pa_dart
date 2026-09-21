part of '../pdf_handler.dart';

final class _PdfParser {
  _PdfParser(this.bytes, this.index, {int? end, required this.maxDepth})
    : end = end ?? bytes.length;

  final Uint8List bytes;
  int index;
  final int end;
  final int maxDepth;

  void skipWhitespaceAndComments() {
    while (index < end) {
      if (_isWhitespace(bytes[index])) {
        index++;
        continue;
      }
      if (bytes[index] == 0x25) {
        index++;
        while (index < end && bytes[index] != 0x0a && bytes[index] != 0x0d) {
          index++;
        }
        continue;
      }
      break;
    }
  }

  Object? parseValue([int depth = 0]) {
    if (depth > maxDepth) {
      throw AssetLimitExceededException(limit: maxDepth, actual: depth);
    }
    skipWhitespaceAndComments();
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'Unexpected end of PDF object.',
      );
    }
    final byte = bytes[index];
    if (byte == 0x2f) return _parseName();
    if (byte == 0x28) return _parseLiteralString();
    if (byte == 0x5b) return _parseArray(depth + 1);
    if (byte == 0x3c) {
      if (index + 1 < end && bytes[index + 1] == 0x3c) {
        return _parseDictionary(depth + 1);
      }
      return _parseHexString();
    }
    if (byte == 0x2b ||
        byte == 0x2d ||
        byte == 0x2e ||
        (byte >= 0x30 && byte <= 0x39)) {
      return _parseNumberOrReference();
    }
    final keyword = readRequiredKeyword('PDF value');
    return switch (keyword) {
      'true' => true,
      'false' => false,
      'null' => null,
      _ => throw MalformedAssetFormatException(
        'Unexpected PDF keyword "$keyword".',
      ),
    };
  }

  int readRequiredInteger(String description) {
    skipWhitespaceAndComments();
    final value = _parseNumber();
    if (value is! int) {
      throw MalformedAssetFormatException(
        'The PDF $description is not an integer.',
      );
    }
    return value;
  }

  String readRequiredKeyword(String description) {
    skipWhitespaceAndComments();
    final start = index;
    while (index < end && !_isDelimiter(bytes[index])) {
      index++;
    }
    if (start == index) {
      throw MalformedAssetFormatException('The PDF $description is missing.');
    }
    return ascii.decode(bytes.sublist(start, index), allowInvalid: false);
  }

  bool consumeKeyword(String keyword) {
    skipWhitespaceAndComments();
    final encoded = ascii.encode(keyword);
    if (!bytesEqualAt(bytes, index, encoded) ||
        (index + encoded.length < end &&
            !_isDelimiter(bytes[index + encoded.length]))) {
      return false;
    }
    index += encoded.length;
    return true;
  }

  Object _parseNumberOrReference() {
    final first = _parseNumber();
    if (first is! int) return first;
    final saved = index;
    try {
      final second = readRequiredInteger('reference generation');
      if (consumeKeyword('R')) return _PdfReference(first, second);
    } on AssetFormatException {
      // It was a single number.
    }
    index = saved;
    return first;
  }

  num _parseNumber() {
    skipWhitespaceAndComments();
    final start = index;
    if (index < end && (bytes[index] == 0x2b || bytes[index] == 0x2d)) {
      index++;
    }
    var hasDigit = false;
    var hasDot = false;
    while (index < end) {
      final byte = bytes[index];
      if (byte >= 0x30 && byte <= 0x39) {
        hasDigit = true;
        index++;
      } else if (byte == 0x2e && !hasDot) {
        hasDot = true;
        index++;
      } else {
        break;
      }
    }
    if (!hasDigit) {
      throw const MalformedAssetFormatException(
        'A PDF numeric value is invalid.',
      );
    }
    final text = ascii.decode(bytes.sublist(start, index));
    final value = hasDot ? double.tryParse(text) : int.tryParse(text);
    if (value == null) {
      throw const MalformedAssetFormatException(
        'A PDF numeric value is out of range.',
      );
    }
    return value;
  }

  _PdfName _parseName() {
    index++;
    final result = <int>[];
    while (index < end && !_isDelimiter(bytes[index])) {
      if (bytes[index] == 0x23) {
        if (index + 2 >= end) {
          throw const MalformedAssetFormatException(
            'A PDF name has an incomplete escape.',
          );
        }
        final high = _hex(bytes[index + 1]);
        final low = _hex(bytes[index + 2]);
        if (high < 0 || low < 0) {
          throw const MalformedAssetFormatException(
            'A PDF name has an invalid escape.',
          );
        }
        result.add((high << 4) | low);
        index += 3;
      } else {
        result.add(bytes[index++]);
      }
    }
    return _PdfName(latin1.decode(result));
  }

  Uint8List _parseLiteralString() {
    index++;
    var nesting = 1;
    final result = <int>[];
    while (index < end && nesting > 0) {
      var byte = bytes[index++];
      if (byte == 0x5c) {
        if (index >= end) break;
        byte = bytes[index++];
        switch (byte) {
          case 0x6e:
            result.add(0x0a);
          case 0x72:
            result.add(0x0d);
          case 0x74:
            result.add(0x09);
          case 0x62:
            result.add(0x08);
          case 0x66:
            result.add(0x0c);
          case 0x0d:
            if (index < end && bytes[index] == 0x0a) index++;
          case 0x0a:
            break;
          case >= 0x30 && <= 0x37:
            var value = byte - 0x30;
            var count = 1;
            while (count < 3 &&
                index < end &&
                bytes[index] >= 0x30 &&
                bytes[index] <= 0x37) {
              value = (value << 3) | (bytes[index++] - 0x30);
              count++;
            }
            result.add(value & 0xff);
          default:
            result.add(byte);
        }
      } else if (byte == 0x28) {
        nesting++;
        result.add(byte);
      } else if (byte == 0x29) {
        nesting--;
        if (nesting > 0) result.add(byte);
      } else {
        result.add(byte);
      }
    }
    if (nesting != 0) {
      throw const MalformedAssetFormatException(
        'A PDF literal string is unterminated.',
      );
    }
    return Uint8List.fromList(result);
  }

  Uint8List _parseHexString() {
    index++;
    final digits = <int>[];
    while (index < end && bytes[index] != 0x3e) {
      if (!_isWhitespace(bytes[index])) digits.add(bytes[index]);
      index++;
    }
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'A PDF hexadecimal string is unterminated.',
      );
    }
    index++;
    final result = Uint8List((digits.length + 1) ~/ 2);
    for (var i = 0; i < digits.length; i += 2) {
      final high = _hex(digits[i]);
      final low = i + 1 < digits.length ? _hex(digits[i + 1]) : 0;
      if (high < 0 || low < 0) {
        throw const MalformedAssetFormatException(
          'A PDF hexadecimal string contains a non-hexadecimal digit.',
        );
      }
      result[i ~/ 2] = (high << 4) | low;
    }
    return result;
  }

  List<Object?> _parseArray(int depth) {
    index++;
    final result = <Object?>[];
    while (true) {
      skipWhitespaceAndComments();
      if (index >= end) {
        throw const MalformedAssetFormatException(
          'A PDF array is unterminated.',
        );
      }
      if (bytes[index] == 0x5d) {
        index++;
        return result;
      }
      result.add(parseValue(depth));
    }
  }

  Map<String, Object?> _parseDictionary(int depth) {
    index += 2;
    final result = <String, Object?>{};
    while (true) {
      skipWhitespaceAndComments();
      if (index + 1 < end && bytes[index] == 0x3e && bytes[index + 1] == 0x3e) {
        index += 2;
        return result;
      }
      if (index >= end || bytes[index] != 0x2f) {
        throw const MalformedAssetFormatException(
          'A PDF dictionary key is not a name.',
        );
      }
      final name = _parseName().value;
      if (result.containsKey(name)) {
        throw MalformedAssetFormatException(
          'The PDF dictionary contains duplicate key /$name.',
        );
      }
      result[name] = parseValue(depth);
    }
  }
}

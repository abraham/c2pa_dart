part of '../pdf_handler.dart';

Uint8List _applyPredictor(
  Uint8List bytes,
  Map<String, Object?> parameters,
  int limit,
) {
  final predictor = parameters['Predictor'] ?? 1;
  if (predictor is! int) {
    throw const MalformedAssetFormatException(
      'The PDF stream Predictor is not an integer.',
    );
  }
  if (predictor == 1) return bytes;
  final colors = parameters['Colors'] ?? 1;
  final bits = parameters['BitsPerComponent'] ?? 8;
  final columns = parameters['Columns'] ?? 1;
  if (colors is! int ||
      colors <= 0 ||
      bits != 8 ||
      columns is! int ||
      columns <= 0) {
    throw const UnsupportedPdfFeatureException(
      'stream predictor parameters other than 8-bit components',
    );
  }
  final rowBytes = colors * columns;
  if (rowBytes <= 0 || rowBytes > limit) {
    throw AssetLimitExceededException(limit: limit, actual: rowBytes);
  }
  if (predictor == 2) {
    if (bytes.length % rowBytes != 0) {
      throw const MalformedAssetFormatException(
        'A TIFF-predicted PDF stream has a partial row.',
      );
    }
    final output = Uint8List.fromList(bytes);
    for (var row = 0; row < output.length; row += rowBytes) {
      for (var i = colors; i < rowBytes; i++) {
        output[row + i] = (output[row + i] + output[row + i - colors]) & 0xff;
      }
    }
    return output;
  }
  if (predictor < 10 || predictor > 15) {
    throw UnsupportedPdfFeatureException('stream predictor $predictor');
  }
  final encodedRow = rowBytes + 1;
  if (bytes.length % encodedRow != 0) {
    throw const MalformedAssetFormatException(
      'A PNG-predicted PDF stream has a partial row.',
    );
  }
  final rows = bytes.length ~/ encodedRow;
  if (rows > limit ~/ rowBytes) {
    throw AssetLimitExceededException(limit: limit, actual: rows * rowBytes);
  }
  final output = Uint8List(rows * rowBytes);
  for (var row = 0; row < rows; row++) {
    final filter = bytes[row * encodedRow];
    if (filter > 4) {
      throw const MalformedAssetFormatException(
        'A PNG-predicted PDF stream has an invalid filter.',
      );
    }
    for (var column = 0; column < rowBytes; column++) {
      final raw = bytes[row * encodedRow + 1 + column];
      final left = column >= colors
          ? output[row * rowBytes + column - colors]
          : 0;
      final above = row > 0 ? output[(row - 1) * rowBytes + column] : 0;
      final upperLeft = row > 0 && column >= colors
          ? output[(row - 1) * rowBytes + column - colors]
          : 0;
      final value = switch (filter) {
        0 => raw,
        1 => raw + left,
        2 => raw + above,
        3 => raw + ((left + above) >> 1),
        4 => raw + _paeth(left, above, upperLeft),
        _ => raw,
      };
      output[row * rowBytes + column] = value & 0xff;
    }
  }
  return output;
}

int _paeth(int left, int above, int upperLeft) {
  final estimate = left + above - upperLeft;
  final leftDistance = (estimate - left).abs();
  final aboveDistance = (estimate - above).abs();
  final diagonalDistance = (estimate - upperLeft).abs();
  if (leftDistance <= aboveDistance && leftDistance <= diagonalDistance) {
    return left;
  }
  return aboveDistance <= diagonalDistance ? above : upperLeft;
}

Uint8List _inflateZlib(Uint8List input, int limit) {
  if (input.length < 6) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has a truncated zlib wrapper.',
    );
  }
  final cmf = input[0];
  final flg = input[1];
  if ((cmf & 0x0f) != 8 || ((cmf << 8) + flg) % 31 != 0) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has an invalid zlib header.',
    );
  }
  if ((flg & 0x20) != 0) {
    throw const UnsupportedPdfFeatureException(
      'FlateDecode streams with preset dictionaries',
    );
  }
  final reader = _BitReader(input, 2, input.length - 4);
  final output = <int>[];
  var finalBlock = false;
  while (!finalBlock) {
    finalBlock = reader.readBits(1) == 1;
    final type = reader.readBits(2);
    if (type == 0) {
      reader.align();
      final length = reader.readByte() | (reader.readByte() << 8);
      final inverse = reader.readByte() | (reader.readByte() << 8);
      if ((length ^ 0xffff) != inverse) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stored block has an invalid length.',
        );
      }
      if (length > limit - output.length) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + length,
        );
      }
      for (var i = 0; i < length; i++) {
        output.add(reader.readByte());
      }
    } else if (type == 1 || type == 2) {
      final tables = type == 1
          ? _fixedHuffmanTables()
          : _dynamicHuffmanTables(reader);
      _inflateHuffmanBlock(reader, output, tables.$1, tables.$2, limit);
    } else {
      throw const MalformedAssetFormatException(
        'A FlateDecode stream uses a reserved block type.',
      );
    }
  }
  if (!reader.onlyPaddingBitsRemain) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has trailing compressed data.',
    );
  }
  final expected =
      input[input.length - 4] * 0x1000000 +
      input[input.length - 3] * 0x10000 +
      input[input.length - 2] * 0x100 +
      input[input.length - 1];
  if (_adler32(output) != expected) {
    throw const MalformedAssetFormatException(
      'A FlateDecode stream has an invalid Adler-32 checksum.',
    );
  }
  return Uint8List.fromList(output);
}

void _inflateHuffmanBlock(
  _BitReader reader,
  List<int> output,
  _Huffman literals,
  _Huffman distances,
  int limit,
) {
  const lengthBases = <int>[
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    13,
    15,
    17,
    19,
    23,
    27,
    31,
    35,
    43,
    51,
    59,
    67,
    83,
    99,
    115,
    131,
    163,
    195,
    227,
    258,
  ];
  const lengthExtras = <int>[
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1,
    1,
    2,
    2,
    2,
    2,
    3,
    3,
    3,
    3,
    4,
    4,
    4,
    4,
    5,
    5,
    5,
    5,
    0,
  ];
  const distanceBases = <int>[
    1,
    2,
    3,
    4,
    5,
    7,
    9,
    13,
    17,
    25,
    33,
    49,
    65,
    97,
    129,
    193,
    257,
    385,
    513,
    769,
    1025,
    1537,
    2049,
    3073,
    4097,
    6145,
    8193,
    12289,
    16385,
    24577,
  ];
  const distanceExtras = <int>[
    0,
    0,
    0,
    0,
    1,
    1,
    2,
    2,
    3,
    3,
    4,
    4,
    5,
    5,
    6,
    6,
    7,
    7,
    8,
    8,
    9,
    9,
    10,
    10,
    11,
    11,
    12,
    12,
    13,
    13,
  ];
  while (true) {
    final symbol = literals.read(reader);
    if (symbol < 256) {
      if (output.length >= limit) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + 1,
        );
      }
      output.add(symbol);
    } else if (symbol == 256) {
      return;
    } else {
      final index = symbol - 257;
      if (index < 0 || index >= lengthBases.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid length symbol.',
        );
      }
      final length = lengthBases[index] + reader.readBits(lengthExtras[index]);
      final distanceSymbol = distances.read(reader);
      if (distanceSymbol >= distanceBases.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid distance symbol.',
        );
      }
      final distance =
          distanceBases[distanceSymbol] +
          reader.readBits(distanceExtras[distanceSymbol]);
      if (distance <= 0 || distance > output.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream has an invalid back-reference.',
        );
      }
      if (length > limit - output.length) {
        throw AssetLimitExceededException(
          limit: limit,
          actual: output.length + length,
        );
      }
      for (var i = 0; i < length; i++) {
        output.add(output[output.length - distance]);
      }
    }
  }
}

(_Huffman, _Huffman) _fixedHuffmanTables() {
  final literalLengths = List<int>.filled(288, 8);
  for (var i = 144; i <= 255; i++) {
    literalLengths[i] = 9;
  }
  for (var i = 256; i <= 279; i++) {
    literalLengths[i] = 7;
  }
  final distanceLengths = List<int>.filled(32, 5);
  return (_Huffman(literalLengths), _Huffman(distanceLengths));
}

(_Huffman, _Huffman) _dynamicHuffmanTables(_BitReader reader) {
  final literalCount = reader.readBits(5) + 257;
  final distanceCount = reader.readBits(5) + 1;
  final codeCount = reader.readBits(4) + 4;
  const order = <int>[
    16,
    17,
    18,
    0,
    8,
    7,
    9,
    6,
    10,
    5,
    11,
    4,
    12,
    3,
    13,
    2,
    14,
    1,
    15,
  ];
  final codeLengths = List<int>.filled(19, 0);
  for (var i = 0; i < codeCount; i++) {
    codeLengths[order[i]] = reader.readBits(3);
  }
  final codeTable = _Huffman(codeLengths);
  final lengths = <int>[];
  final required = literalCount + distanceCount;
  while (lengths.length < required) {
    final symbol = codeTable.read(reader);
    if (symbol <= 15) {
      lengths.add(symbol);
    } else if (symbol == 16) {
      if (lengths.isEmpty) {
        throw const MalformedAssetFormatException(
          'A FlateDecode repeat code has no previous length.',
        );
      }
      final count = reader.readBits(2) + 3;
      if (count > required - lengths.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode code-length repeat exceeds its table.',
        );
      }
      lengths.addAll(List<int>.filled(count, lengths.last));
    } else if (symbol == 17 || symbol == 18) {
      final count =
          reader.readBits(symbol == 17 ? 3 : 7) + (symbol == 17 ? 3 : 11);
      if (count > required - lengths.length) {
        throw const MalformedAssetFormatException(
          'A FlateDecode zero repeat exceeds its table.',
        );
      }
      lengths.addAll(List<int>.filled(count, 0));
    } else {
      throw const MalformedAssetFormatException(
        'A FlateDecode code-length symbol is invalid.',
      );
    }
  }
  final literals = _Huffman(lengths.sublist(0, literalCount));
  final distances = _Huffman(lengths.sublist(literalCount));
  return (literals, distances);
}

final class _Huffman {
  _Huffman(List<int> lengths) {
    var maximum = 0;
    for (final length in lengths) {
      if (length > maximum) maximum = length;
    }
    if (maximum == 0) {
      throw const MalformedAssetFormatException(
        'A FlateDecode Huffman table is empty.',
      );
    }
    maxLength = maximum;
    final counts = List<int>.filled(maximum + 1, 0);
    for (final length in lengths) {
      if (length < 0 || length > 15) {
        throw const MalformedAssetFormatException(
          'A FlateDecode Huffman code length is invalid.',
        );
      }
      if (length > 0) counts[length]++;
    }
    var remaining = 1;
    for (var bits = 1; bits <= maximum; bits++) {
      remaining = (remaining << 1) - counts[bits];
      if (remaining < 0) {
        throw const MalformedAssetFormatException(
          'A FlateDecode Huffman table is oversubscribed.',
        );
      }
    }
    final next = List<int>.filled(maximum + 1, 0);
    var code = 0;
    for (var bits = 1; bits <= maximum; bits++) {
      code = (code + counts[bits - 1]) << 1;
      next[bits] = code;
    }
    for (var symbol = 0; symbol < lengths.length; symbol++) {
      final length = lengths[symbol];
      if (length == 0) continue;
      final reversed = _reverseBits(next[length]++, length);
      table[(length << 16) | reversed] = symbol;
    }
  }

  late final int maxLength;
  final Map<int, int> table = <int, int>{};

  int read(_BitReader reader) {
    var code = 0;
    for (var length = 1; length <= maxLength; length++) {
      code |= reader.readBits(1) << (length - 1);
      final symbol = table[(length << 16) | code];
      if (symbol != null) return symbol;
    }
    throw const MalformedAssetFormatException(
      'A FlateDecode Huffman code is invalid.',
    );
  }
}

final class _BitReader {
  _BitReader(this.bytes, this.index, this.end);

  final Uint8List bytes;
  int index;
  final int end;
  int _bits = 0;
  int _available = 0;

  int readBits(int count) {
    while (_available < count) {
      if (index >= end) {
        throw const MalformedAssetFormatException(
          'A FlateDecode stream is truncated.',
        );
      }
      _bits |= bytes[index++] << _available;
      _available += 8;
    }
    final mask = count == 0 ? 0 : (1 << count) - 1;
    final value = _bits & mask;
    _bits >>= count;
    _available -= count;
    return value;
  }

  void align() {
    _bits = 0;
    _available = 0;
  }

  int readByte() {
    if (_available != 0) {
      throw const MalformedAssetFormatException(
        'A FlateDecode stored block is not byte-aligned.',
      );
    }
    if (index >= end) {
      throw const MalformedAssetFormatException(
        'A FlateDecode stream is truncated.',
      );
    }
    return bytes[index++];
  }

  bool get onlyPaddingBitsRemain => index == end;
}

int _reverseBits(int value, int count) {
  var result = 0;
  for (var i = 0; i < count; i++) {
    result = (result << 1) | ((value >> i) & 1);
  }
  return result;
}

int _adler32(List<int> bytes) {
  var a = 1;
  var b = 0;
  for (final byte in bytes) {
    a = (a + byte) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

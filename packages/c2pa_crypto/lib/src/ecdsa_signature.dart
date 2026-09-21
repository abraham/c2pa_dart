/// Converts a strictly DER-encoded ECDSA signature to fixed-width IEEE P1363.
List<int> ecdsaDerToP1363(List<int> der, {required int componentLength}) {
  _validateComponentLength(componentLength);
  _validateBytes(der, 'der');
  final reader = _DerReader(der);
  reader.expectTag(0x30);
  final sequenceLength = reader.readLength();
  final sequenceEnd = reader.offset + sequenceLength;
  if (sequenceEnd != der.length) {
    throw const FormatException('Invalid DER sequence length');
  }

  final r = reader.readPositiveInteger(sequenceEnd);
  final s = reader.readPositiveInteger(sequenceEnd);
  if (reader.offset != sequenceEnd) {
    throw const FormatException('Trailing data in ECDSA sequence');
  }

  return [..._leftPad(r, componentLength), ..._leftPad(s, componentLength)];
}

/// Converts a fixed-width IEEE P1363 ECDSA signature to strict DER.
List<int> ecdsaP1363ToDer(List<int> p1363, {required int componentLength}) {
  _validateComponentLength(componentLength);
  _validateBytes(p1363, 'p1363');
  if (p1363.length != componentLength * 2) {
    throw ArgumentError.value(
      p1363.length,
      'p1363',
      'Expected ${componentLength * 2} bytes',
    );
  }

  final r = _encodePositiveInteger(p1363.sublist(0, componentLength));
  final s = _encodePositiveInteger(p1363.sublist(componentLength));
  final body = <int>[
    0x02,
    ..._encodeLength(r.length),
    ...r,
    0x02,
    ..._encodeLength(s.length),
    ...s,
  ];
  return <int>[0x30, ..._encodeLength(body.length), ...body];
}

void _validateBytes(List<int> bytes, String name) {
  if (bytes.any((byte) => byte < 0 || byte > 0xff)) {
    throw FormatException('$name contains a non-byte value');
  }
}

void _validateComponentLength(int componentLength) {
  if (componentLength <= 0) {
    throw ArgumentError.value(
      componentLength,
      'componentLength',
      'Must be positive',
    );
  }
}

List<int> _leftPad(List<int> value, int width) {
  if (value.length > width) {
    throw FormatException('ECDSA integer exceeds $width bytes');
  }
  return <int>[...List<int>.filled(width - value.length, 0), ...value];
}

List<int> _encodePositiveInteger(List<int> fixedWidth) {
  var first = 0;
  while (first < fixedWidth.length && fixedWidth[first] == 0) {
    first++;
  }
  if (first == fixedWidth.length) {
    throw const FormatException('ECDSA integers must be positive');
  }

  final value = fixedWidth.sublist(first);
  return value.first & 0x80 == 0 ? value : <int>[0, ...value];
}

List<int> _encodeLength(int length) {
  if (length < 0x80) {
    return <int>[length];
  }
  final bytes = <int>[];
  var remaining = length;
  while (remaining != 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return <int>[0x80 | bytes.length, ...bytes];
}

final class _DerReader {
  _DerReader(this.bytes);

  final List<int> bytes;
  int offset = 0;

  void expectTag(int tag) {
    if (_readByte() != tag) {
      throw FormatException('Expected DER tag 0x${tag.toRadixString(16)}');
    }
  }

  int readLength() {
    final first = _readByte();
    if (first < 0x80) {
      return first;
    }

    final byteCount = first & 0x7f;
    if (byteCount == 0) {
      throw const FormatException('Indefinite DER length is not allowed');
    }
    if (byteCount > 4 || byteCount > bytes.length - offset) {
      throw const FormatException('Invalid DER length');
    }
    if (bytes[offset] == 0) {
      throw const FormatException('Non-minimal DER length');
    }

    var length = 0;
    for (var i = 0; i < byteCount; i++) {
      length = (length << 8) | _readByte();
    }
    if (length < 0x80) {
      throw const FormatException('Non-minimal DER length');
    }
    if (length > bytes.length - offset) {
      throw const FormatException('DER length exceeds input');
    }
    return length;
  }

  List<int> readPositiveInteger(int limit) {
    if (offset >= limit) {
      throw const FormatException('Missing ECDSA integer');
    }
    expectTag(0x02);
    final length = readLength();
    if (length == 0 || offset + length > limit) {
      throw const FormatException('Invalid ECDSA integer length');
    }

    final encoded = bytes.sublist(offset, offset + length);
    offset += length;
    if (encoded.first & 0x80 != 0) {
      throw const FormatException('ECDSA integers must not be negative');
    }
    if (encoded.length > 1 && encoded.first == 0 && encoded[1] & 0x80 == 0) {
      throw const FormatException('Non-minimal ECDSA integer');
    }

    final value = encoded.first == 0 ? encoded.sublist(1) : encoded;
    if (value.isEmpty || value.every((byte) => byte == 0)) {
      throw const FormatException('ECDSA integers must be positive');
    }
    return value;
  }

  int _readByte() {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated DER input');
    }
    return bytes[offset++];
  }
}

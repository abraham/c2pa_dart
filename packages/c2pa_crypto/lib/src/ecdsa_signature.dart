import 'der_reader.dart';

/// Converts a strictly DER-encoded ECDSA signature to fixed-width IEEE P1363.
List<int> ecdsaDerToP1363(List<int> der, {required int componentLength}) {
  _validateComponentLength(componentLength);
  _validateBytes(der, 'der');
  final reader = DerReader(der);
  final sequence = reader.read(0x30);
  reader.requireEnd();

  final body = sequence.reader();
  final r = _readPositiveInteger(body);
  final s = _readPositiveInteger(body);
  body.requireEnd();

  return [..._leftPad(r, componentLength), ..._leftPad(s, componentLength)];
}

/// Reads one strictly encoded, positive ECDSA `INTEGER` from [reader].
///
/// Strips the single leading zero that DER adds to keep a high bit from
/// reading as a sign bit, and rejects the padded and negative forms that
/// would let two encodings share one signature value.
List<int> _readPositiveInteger(DerReader reader) {
  if (reader.isAtEnd) {
    throw const FormatException('Missing ECDSA integer');
  }
  final encoded = reader.read(0x02).content;
  if (encoded.isEmpty) {
    throw const FormatException('Invalid ECDSA integer length');
  }
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

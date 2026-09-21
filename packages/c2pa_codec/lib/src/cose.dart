import 'dart:collection';
import 'dart:typed_data';

import 'cbor.dart';
import 'errors.dart';

const int _maxSafeInteger = 9007199254740991;
final BigInt _maxSafeIntegerBig = BigInt.from(_maxSafeInteger);

/// An integer COSE header label.
final class CoseHeaderLabel {
  /// Creates a COSE header label with integer [value] and optional [name].
  const CoseHeaderLabel(this.value, [this.name]);

  /// The protected algorithm header label, `1` (`alg`).
  static const algorithm = CoseHeaderLabel(1, 'alg');

  /// Alias for [algorithm].
  static const alg = algorithm;

  /// The content-type header label, `3`.
  static const contentType = CoseHeaderLabel(3, 'content type');

  /// The key identifier header label, `4` (`kid`).
  static const keyId = CoseHeaderLabel(4, 'kid');

  /// Alias for [keyId].
  static const kid = keyId;

  /// The X.509 certificate chain header label, `33` (`x5chain`).
  static const x509Chain = CoseHeaderLabel(33, 'x5chain');

  /// Alias for [x509Chain].
  static const x5chain = x509Chain;

  /// The integer label encoded into the COSE header map.
  final int value;

  /// A display name for diagnostics, or `null` for unnamed labels.
  final String? name;

  /// Creates a label for an extension not defined by this package.
  factory CoseHeaderLabel.custom(int value, {String? name}) =>
      CoseHeaderLabel(value, name);

  @override
  bool operator ==(Object other) =>
      other is CoseHeaderLabel && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => name == null ? 'COSE label $value' : '$name ($value)';
}

/// Standard integer header labels used by C2PA COSE messages.
abstract final class CoseHeaderLabels {
  /// The protected algorithm header label, `1` (`alg`).
  static const alg = CoseHeaderLabel.algorithm;

  /// The content-type header label, `3`.
  static const contentType = CoseHeaderLabel.contentType;

  /// The key identifier header label, `4` (`kid`).
  static const kid = CoseHeaderLabel.keyId;

  /// The X.509 certificate chain header label, `33` (`x5chain`).
  static const x5chain = CoseHeaderLabel.x509Chain;

  /// Creates a label for an extension not defined by this package.
  static CoseHeaderLabel custom(int value, {String? name}) =>
      CoseHeaderLabel.custom(value, name: name);
}

/// An immutable collection of integer-labeled COSE headers.
final class CoseHeaders {
  /// Creates immutable COSE headers from [values].
  CoseHeaders([Map<CoseHeaderLabel, Object?> values = const {}])
    : _values = Map<CoseHeaderLabel, Object?>.unmodifiable(
        values.map(
          (key, value) => MapEntry(
            CoseHeaderLabel.custom(key.value, name: key.name),
            _copyValue(value),
          ),
        ),
      ) {
    _validateHeaders(_values);
  }

  /// Creates immutable COSE headers from integer label [values].
  factory CoseHeaders.fromIntMap(Map<int, Object?> values) => CoseHeaders(
    values.map((key, value) => MapEntry(CoseHeaderLabel.custom(key), value)),
  );

  final Map<CoseHeaderLabel, Object?> _values;

  /// The number of header labels in this collection.
  int get length => _values.length;

  /// Whether this collection contains no header labels.
  bool get isEmpty => _values.isEmpty;

  /// Whether [label] is present in this collection.
  bool contains(CoseHeaderLabel label) => _values.containsKey(label);

  /// A defensive copy of the value for [label], or `null` if absent.
  Object? operator [](CoseHeaderLabel label) => _copyValue(_values[label]);

  /// An immutable copy of all header values keyed by [CoseHeaderLabel].
  Map<CoseHeaderLabel, Object?> get values =>
      Map<CoseHeaderLabel, Object?>.unmodifiable(
        _values.map((key, value) => MapEntry(key, _copyValue(value))),
      );

  Map<int, Object?> _asCborMap() => Map<int, Object?>.fromEntries(
    _values.entries.map(
      (entry) => MapEntry(entry.key.value, _copyValue(entry.value)),
    ),
  );
}

/// An immutable COSE_Sign1 message.
final class CoseSign1 {
  /// Creates a COSE_Sign1 message with protected and unprotected headers.
  CoseSign1({
    required CoseHeaders protectedHeaders,
    CoseHeaders? unprotectedHeaders,
    Uint8List? payload,
    required Uint8List signature,
    this.tagged = true,
  }) : protectedHeaders = protectedHeaders,
       unprotectedHeaders = unprotectedHeaders ?? CoseHeaders(),
       _payload = payload == null ? null : Uint8List.fromList(payload),
       _signature = Uint8List.fromList(signature),
       _protectedBytes = encodeCbor(protectedHeaders._asCborMap()),
       _rawBytes = null {
    _validateHeaderBuckets(this.protectedHeaders, this.unprotectedHeaders);
  }

  CoseSign1._parsed({
    required this.protectedHeaders,
    required this.unprotectedHeaders,
    required Uint8List protectedBytes,
    required Uint8List? payload,
    required Uint8List signature,
    required this.tagged,
    required Uint8List rawBytes,
  }) : _protectedBytes = Uint8List.fromList(protectedBytes),
       _payload = payload == null ? null : Uint8List.fromList(payload),
       _signature = Uint8List.fromList(signature),
       _rawBytes = Uint8List.fromList(rawBytes);

  /// The protected header bucket covered by the COSE signature.
  final CoseHeaders protectedHeaders;

  /// The unprotected header bucket excluded from the COSE signature.
  final CoseHeaders unprotectedHeaders;
  final Uint8List _protectedBytes;
  final Uint8List? _payload;
  final Uint8List _signature;
  final Uint8List? _rawBytes;

  /// Whether the parsed or newly constructed message carries COSE tag 18.
  final bool tagged;

  /// The exact serialized protected header map contained in its byte string.
  Uint8List get protectedBytes => Uint8List.fromList(_protectedBytes);

  /// The embedded payload, or `null` for a detached payload.
  Uint8List? get payload =>
      _payload == null ? null : Uint8List.fromList(_payload);

  /// The signature bytes from the fourth COSE_Sign1 array element.
  Uint8List get signature => Uint8List.fromList(_signature);

  /// Parses one tagged or untagged COSE_Sign1 message.
  factory CoseSign1.parse(
    List<int> bytes, {
    bool allowTagged = true,
    bool allowUntagged = true,
    int maxNestingDepth = 64,
  }) {
    if (maxNestingDepth < 0) {
      throw const CoseException(
        CoseErrorCode.excessiveNesting,
        'maxNestingDepth must not be negative',
      );
    }
    final input = _toBytes(bytes);
    var cursor = 0;
    var tagged = false;
    if (input.isNotEmpty && input[0] == 0xd2) {
      tagged = true;
      cursor++;
      if (!allowTagged) {
        throw const CoseException(
          CoseErrorCode.tagForbidden,
          'Tagged COSE_Sign1 messages are not allowed',
          offset: 0,
        );
      }
    } else if (input.isNotEmpty && input[0] >> 5 == 6) {
      throw const CoseException(
        CoseErrorCode.unsupportedTag,
        'Only canonical COSE_Sign1 tag 18 is supported',
        offset: 0,
      );
    } else if (!allowUntagged) {
      throw const CoseException(
        CoseErrorCode.tagRequired,
        'A COSE_Sign1 tag is required',
        offset: 0,
      );
    }

    if (cursor >= input.length || input[cursor] != 0x84) {
      throw CoseException(
        CoseErrorCode.invalidStructure,
        'COSE_Sign1 must be a definite four-element array',
        offset: cursor,
      );
    }
    cursor++;

    final protectedField = _readByteString(input, cursor);
    cursor = protectedField.$2;
    final protectedBytes = protectedField.$1;
    final protectedHeaders = protectedBytes.isEmpty
        ? CoseHeaders()
        : _decodeHeaders(protectedBytes, maxNestingDepth, cursor);

    final unprotectedEnd = _scanCborItem(
      input,
      cursor,
      maxNestingDepth: maxNestingDepth,
    );
    final unprotectedValue = _decodeCborSlice(
      input,
      cursor,
      unprotectedEnd,
      maxNestingDepth,
    );
    if (unprotectedValue is! Map<Object?, Object?>) {
      throw CoseException(
        CoseErrorCode.invalidType,
        'COSE_Sign1 unprotected headers must be a map',
        offset: cursor,
      );
    }
    final unprotectedHeaders = _headersFromDecoded(unprotectedValue, cursor);
    cursor = unprotectedEnd;

    Uint8List? payload;
    if (cursor < input.length && input[cursor] == 0xf6) {
      cursor++;
    } else {
      final payloadField = _readByteString(input, cursor);
      payload = payloadField.$1;
      cursor = payloadField.$2;
    }

    final signatureField = _readByteString(input, cursor);
    final signature = signatureField.$1;
    cursor = signatureField.$2;
    if (cursor != input.length) {
      throw CoseException(
        CoseErrorCode.trailingData,
        'Trailing data follows the COSE_Sign1 message',
        offset: cursor,
      );
    }

    _validateHeaderBuckets(protectedHeaders, unprotectedHeaders);
    return CoseSign1._parsed(
      protectedHeaders: protectedHeaders,
      unprotectedHeaders: unprotectedHeaders,
      protectedBytes: protectedBytes,
      payload: payload,
      signature: signature,
      tagged: tagged,
      rawBytes: input,
    );
  }

  /// Encodes the message, preserving parsed bytes unless [tagged] is supplied.
  Uint8List encode({bool? tagged}) {
    final original = _rawBytes;
    if (original != null && tagged == null) {
      return Uint8List.fromList(original);
    }
    final includeTag = tagged ?? this.tagged;
    final structure = <Object?>[
      _protectedBytes,
      unprotectedHeaders._asCborMap(),
      _payload,
      _signature,
    ];
    final encoded = encodeCbor(structure);
    return includeTag ? Uint8List.fromList([0xd2, ...encoded]) : encoded;
  }

  /// Builds the bytes to sign or verify for the COSE `Signature1` context.
  Uint8List signatureStructure({
    Uint8List? externalAad,
    Uint8List? detachedPayload,
  }) {
    final embedded = _payload;
    if (embedded == null && detachedPayload == null) {
      throw const CoseException(
        CoseErrorCode.detachedPayloadRequired,
        'A detached payload is required for this COSE_Sign1 message',
      );
    }
    if (embedded != null && detachedPayload != null) {
      throw const CoseException(
        CoseErrorCode.conflictingPayload,
        'A detached payload must not accompany an embedded payload',
      );
    }
    return encodeCbor(<Object?>[
      'Signature1',
      _protectedBytes,
      externalAad ?? Uint8List(0),
      embedded ?? detachedPayload!,
    ]);
  }
}

/// Parses one tagged or untagged COSE_Sign1 message.
CoseSign1 decodeCoseSign1(
  List<int> bytes, {
  bool allowTagged = true,
  bool allowUntagged = true,
  int maxNestingDepth = 64,
}) => CoseSign1.parse(
  bytes,
  allowTagged: allowTagged,
  allowUntagged: allowUntagged,
  maxNestingDepth: maxNestingDepth,
);

/// Encodes a COSE_Sign1 message.
Uint8List encodeCoseSign1(CoseSign1 message, {bool? tagged}) =>
    message.encode(tagged: tagged);

CoseHeaders _decodeHeaders(
  Uint8List encoded,
  int maxNestingDepth,
  int sourceOffset,
) {
  final decoded = _decodeCborSlice(
    encoded,
    0,
    encoded.length,
    maxNestingDepth,
    sourceOffset: sourceOffset - encoded.length,
  );
  if (decoded is! Map<Object?, Object?>) {
    throw CoseException(
      CoseErrorCode.invalidType,
      'COSE protected headers must encode a CBOR map',
      offset: sourceOffset - encoded.length,
    );
  }
  return _headersFromDecoded(decoded, sourceOffset - encoded.length);
}

CoseHeaders _headersFromDecoded(Map<Object?, Object?> decoded, int offset) {
  final values = <CoseHeaderLabel, Object?>{};
  for (final entry in decoded.entries) {
    final key = entry.key;
    if (key is! int) {
      throw CoseException(
        CoseErrorCode.invalidHeaderLabel,
        'COSE header labels must be integers',
        offset: offset,
      );
    }
    values[CoseHeaderLabel.custom(key)] = entry.value;
  }
  try {
    return CoseHeaders(values);
  } on CoseException catch (error) {
    throw CoseException(error.code, error.message, offset: offset);
  }
}

void _validateHeaders(Map<CoseHeaderLabel, Object?> headers) {
  for (final entry in headers.entries) {
    final value = entry.value;
    switch (entry.key.value) {
      case 1:
        if (value is! int) {
          _invalidHeader(entry.key, 'must be an integer algorithm identifier');
        }
      case 3:
        if (value is! int && value is! String) {
          _invalidHeader(entry.key, 'must be an integer or text string');
        }
      case 4:
        if (value is! Uint8List) {
          _invalidHeader(entry.key, 'must be a byte string');
        }
      case 33:
        final validChain =
            value is Uint8List ||
            (value is List &&
                value.isNotEmpty &&
                value.every((item) => item is Uint8List));
        if (!validChain) {
          _invalidHeader(
            entry.key,
            'must be a byte string or non-empty array of byte strings',
          );
        }
    }
  }
}

Never _invalidHeader(CoseHeaderLabel label, String expectation) {
  throw CoseException(
    CoseErrorCode.invalidHeaderValue,
    'COSE header $label $expectation',
  );
}

void _validateHeaderBuckets(CoseHeaders protected, CoseHeaders unprotected) {
  if (!protected.contains(CoseHeaderLabel.algorithm)) {
    throw const CoseException(
      CoseErrorCode.missingProtectedAlgorithm,
      'The alg header must be present in protected headers',
    );
  }
  for (final label in protected._values.keys) {
    if (unprotected._values.containsKey(label)) {
      throw CoseException(
        CoseErrorCode.duplicateHeader,
        'COSE header $label occurs in both protected and unprotected maps',
      );
    }
  }
}

Object? _copyValue(Object? value) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List) {
    return List<Object?>.unmodifiable(value.map(_copyValue));
  }
  if (value is Map) {
    return UnmodifiableMapView<Object?, Object?>(
      value.map((key, item) => MapEntry(_copyValue(key), _copyValue(item))),
    );
  }
  return value;
}

Object? _decodeCborSlice(
  Uint8List input,
  int start,
  int end,
  int maxNestingDepth, {
  int? sourceOffset,
}) {
  try {
    return decodeCbor(
      Uint8List.fromList(input.sublist(start, end)),
      maxNestingDepth: maxNestingDepth,
      // COSE structures are verified against the exact bytes the signer
      // produced, so map key ordering carries no security meaning here.
      // Real-world C2PA signers emit non-canonically ordered header maps, and
      // rejecting them at decode time would discard otherwise valid
      // signatures. Deterministic ordering remains enforced where C2PA
      // requires it, namely claim encoding.
      requireCanonicalMapOrder: false,
    );
  } on CborDecodingException catch (error) {
    throw CoseException(
      error.code == CborDecodingErrorCode.excessiveNesting
          ? CoseErrorCode.excessiveNesting
          : CoseErrorCode.invalidCbor,
      error.message,
      offset: (sourceOffset ?? start) + error.offset,
    );
  }
}

(Uint8List, int) _readByteString(Uint8List input, int offset) {
  if (offset >= input.length) {
    throw CoseException(
      CoseErrorCode.truncated,
      'COSE_Sign1 is truncated',
      offset: offset,
    );
  }
  final initial = input[offset];
  if (initial >> 5 != 2 || (initial & 0x1f) == 31) {
    throw CoseException(
      CoseErrorCode.invalidType,
      'Expected a definite-length byte string',
      offset: offset,
    );
  }
  final argument = _readArgument(input, offset);
  final start = argument.$2;
  if (argument.$1 > _maxSafeIntegerBig) {
    throw CoseException(
      CoseErrorCode.invalidCbor,
      'COSE byte-string length cannot be addressed on this platform',
      offset: offset,
    );
  }
  if (argument.$1 > BigInt.from(input.length - start)) {
    throw CoseException(
      CoseErrorCode.truncated,
      'COSE byte string is truncated',
      offset: start,
    );
  }
  final end = start + argument.$1.toInt();
  return (Uint8List.fromList(input.sublist(start, end)), end);
}

int _scanCborItem(
  Uint8List input,
  int offset, {
  required int maxNestingDepth,
  int depth = 0,
}) {
  if (depth > maxNestingDepth) {
    throw CoseException(
      CoseErrorCode.excessiveNesting,
      'CBOR nesting exceeds the configured limit of $maxNestingDepth',
      offset: offset,
    );
  }
  if (offset >= input.length) {
    throw CoseException(
      CoseErrorCode.truncated,
      'COSE_Sign1 is truncated',
      offset: offset,
    );
  }
  final initial = input[offset];
  final major = initial >> 5;
  final additional = initial & 0x1f;
  if (additional == 31) {
    throw CoseException(
      CoseErrorCode.invalidCbor,
      'Indefinite-length CBOR is not supported',
      offset: offset,
    );
  }
  if (major == 7) {
    final byteCount = switch (additional) {
      < 24 => 0,
      24 => 1,
      25 => 2,
      26 => 4,
      27 => 8,
      _ => throw CoseException(
        CoseErrorCode.invalidCbor,
        'Invalid CBOR simple value',
        offset: offset,
      ),
    };
    if (byteCount > input.length - offset - 1) {
      throw CoseException(
        CoseErrorCode.truncated,
        'CBOR simple value is truncated',
        offset: offset,
      );
    }
    return offset + 1 + byteCount;
  }
  final argument = _readArgument(input, offset);
  var cursor = argument.$2;
  switch (major) {
    case 0:
    case 1:
      return cursor;
    case 2:
    case 3:
      final length = _addressableArgument(argument.$1, offset);
      if (length > input.length - cursor) {
        throw CoseException(
          CoseErrorCode.truncated,
          'CBOR string is truncated',
          offset: cursor,
        );
      }
      return cursor + length;
    case 4:
      final length = _addressableArgument(argument.$1, offset);
      if (length > input.length - cursor) {
        throw CoseException(
          CoseErrorCode.truncated,
          'CBOR array is truncated',
          offset: cursor,
        );
      }
      for (var index = 0; index < length; index++) {
        cursor = _scanCborItem(
          input,
          cursor,
          maxNestingDepth: maxNestingDepth,
          depth: depth + 1,
        );
      }
      return cursor;
    case 5:
      final length = _addressableArgument(argument.$1, offset);
      if (length > (input.length - cursor) ~/ 2) {
        throw CoseException(
          CoseErrorCode.truncated,
          'CBOR map is truncated',
          offset: cursor,
        );
      }
      for (var index = 0; index < length * 2; index++) {
        cursor = _scanCborItem(
          input,
          cursor,
          maxNestingDepth: maxNestingDepth,
          depth: depth + 1,
        );
      }
      return cursor;
    case 6:
      return _scanCborItem(
        input,
        cursor,
        maxNestingDepth: maxNestingDepth,
        depth: depth + 1,
      );
  }
  throw StateError('Unreachable CBOR major type');
}

(BigInt, int) _readArgument(Uint8List input, int offset) {
  final initial = input[offset];
  final additional = initial & 0x1f;
  if (additional < 24) return (BigInt.from(additional), offset + 1);
  final byteCount = switch (additional) {
    24 => 1,
    25 => 2,
    26 => 4,
    27 => 8,
    _ => throw CoseException(
      CoseErrorCode.invalidCbor,
      'Invalid CBOR additional information',
      offset: offset,
    ),
  };
  if (byteCount > input.length - offset - 1) {
    throw CoseException(
      CoseErrorCode.truncated,
      'CBOR item is truncated',
      offset: offset,
    );
  }
  var value = BigInt.zero;
  for (var index = 0; index < byteCount; index++) {
    value = (value << 8) | BigInt.from(input[offset + 1 + index]);
  }
  final minimum = switch (byteCount) {
    1 => BigInt.from(24),
    2 => BigInt.from(0x100),
    4 => BigInt.from(0x10000),
    _ => BigInt.one << 32,
  };
  if (value < minimum) {
    throw CoseException(
      CoseErrorCode.invalidCbor,
      'CBOR argument is not minimally encoded or is out of range',
      offset: offset,
    );
  }
  return (value, offset + 1 + byteCount);
}

int _addressableArgument(BigInt value, int offset) {
  if (value > _maxSafeIntegerBig) {
    throw CoseException(
      CoseErrorCode.invalidCbor,
      'CBOR length cannot be addressed on this platform',
      offset: offset,
    );
  }
  return value.toInt();
}

Uint8List _toBytes(List<int> bytes) {
  try {
    return bytes is Uint8List
        ? Uint8List.fromList(bytes)
        : Uint8List.fromList(bytes);
  } on RangeError {
    throw const CoseException(
      CoseErrorCode.invalidStructure,
      'COSE input contains a value outside the byte range',
    );
  }
}

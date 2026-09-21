/// The kind of failure encountered while encoding CBOR.
enum CborEncodingErrorCode {
  /// A value type outside the supported CBOR model was passed for encoding.
  unsupportedType,

  /// An integer or encoded argument cannot fit the supported 64-bit range.
  integerOutOfRange,

  /// A `double.nan` or infinite double was passed for encoding.
  nonFiniteDouble,

  /// Two map keys have identical deterministic CBOR encodings.
  duplicateMapKey,

  /// The value graph exceeds the configured nesting limit.
  excessiveNesting,
}

/// An immutable error raised while encoding CBOR.
final class CborEncodingException implements Exception {
  /// Creates a CBOR encoding exception with [code] and [message].
  const CborEncodingException(this.code, this.message);

  /// The specific CBOR encoding failure.
  final CborEncodingErrorCode code;

  /// A human-readable description of the failed encoding condition.
  final String message;

  @override
  String toString() => 'CborEncodingException(${code.name}): $message';
}

/// The kind of failure encountered while decoding CBOR.
enum CborDecodingErrorCode {
  /// Bytes remain after the top-level CBOR data item.
  trailingData,

  /// A declared CBOR item length exceeds the available input.
  truncated,

  /// An indefinite-length item appears when it is disallowed or malformed.
  indefiniteLength,

  /// A text string contains bytes that are not valid UTF-8.
  invalidUtf8,

  /// A map contains duplicate canonical keys or Dart-equal keys.
  duplicateMapKey,

  /// Map keys are not sorted by deterministic CBOR ordering.
  nonCanonicalMapOrder,

  /// An integer or length uses a non-minimal CBOR representation.
  nonMinimalInteger,

  /// The decoded item exceeds the configured nesting limit.
  excessiveNesting,

  /// A CBOR semantic tag appears in strict decoding.
  unsupportedTag,

  /// A simple value other than `false`, `true`, `null`, or a float appears.
  unsupportedSimpleValue,

  /// A length cannot be represented as an addressable Dart integer.
  integerOutOfRange,

  /// A decoded floating-point value is `NaN` or infinite.
  nonFiniteDouble,

  /// The initial byte contains a reserved additional-information value.
  invalidAdditionalInformation,
}

/// An immutable error raised while decoding CBOR.
final class CborDecodingException implements Exception {
  /// Creates a CBOR decoding exception with [code], [message], and [offset].
  const CborDecodingException(this.code, this.message, {required this.offset});

  /// The specific CBOR decoding failure.
  final CborDecodingErrorCode code;

  /// A human-readable description of the failed decoding condition.
  final String message;

  /// The byte offset at which decoding failed.
  final int offset;

  @override
  String toString() =>
      'CborDecodingException(${code.name}, offset: $offset): $message';
}

/// The kind of failure encountered while reading or writing an ISO box header.
enum IsoBoxErrorCode {
  /// The supplied bounds or write offset are outside the byte buffer.
  invalidOffset,

  /// A header field or declared box body extends beyond the available bytes.
  truncated,

  /// A box type is not exactly four printable ASCII characters.
  invalidType,

  /// A payload size is negative or a declared size is smaller than the header.
  invalidSize,

  /// A 64-bit box size cannot be addressed as a safe Dart integer.
  sizeOutOfRange,

  /// A `uuid` box was created without a 16-byte user type.
  missingUserType,

  /// A non-`uuid` box was created with a user type.
  unexpectedUserType,
}

/// An immutable error raised while reading or writing an ISO box header.
final class IsoBoxException implements Exception {
  /// Creates an ISO box exception with [code], [message], and [offset].
  const IsoBoxException(this.code, this.message, {this.offset});

  /// The specific ISO box failure.
  final IsoBoxErrorCode code;

  /// A human-readable description of the failed box condition.
  final String message;

  /// The byte offset at which parsing failed, or `null` if unavailable.
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'IsoBoxException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while reading or writing JUMBF.
enum JumbfErrorCode {
  /// Parser limits are invalid or a child box crosses its parent bounds.
  invalidBounds,

  /// A byte value or ISO box header is invalid for JUMBF parsing.
  invalidBox,

  /// A parsed root or child that must be a `jumb` superbox is not one.
  expectedSuperBox,

  /// A required first-child `jumd` box is missing or has the wrong type.
  expectedDescriptionBox,

  /// A `jumd` field has an invalid length, value, or trailing data.
  invalidDescription,

  /// A `jumd` toggles byte sets feature bits this decoder does not support.
  unsupportedDescriptionFeature,

  /// A JUMBF label or embedded-file string is not valid UTF-8.
  invalidUtf8,

  /// A `bfdb` embedded-file description is malformed.
  invalidEmbeddedFileDescription,

  /// Two sibling superboxes have the same non-null label.
  duplicateLabel,

  /// The superbox tree exceeds the configured nesting limit.
  excessiveNesting,

  /// The parsed box count exceeds the configured box-count limit.
  excessiveBoxCount,

  /// Bytes remain after a standalone JUMBF superbox.
  trailingData,

  /// A compressed manifest is not one valid `c2cm` box with one `brob` child.
  invalidCompressedManifest,

  /// The outer compressed manifest label and expanded manifest label differ.
  compressedManifestLabelMismatch,
}

/// An immutable error raised while reading or writing JUMBF.
final class JumbfException implements Exception {
  /// Creates a JUMBF exception with [code], [message], and [offset].
  const JumbfException(this.code, this.message, {this.offset});

  /// The specific JUMBF failure.
  final JumbfErrorCode code;

  /// A human-readable description of the failed JUMBF condition.
  final String message;

  /// The byte offset at which parsing failed, or `null` if unavailable.
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'JumbfException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while reading or writing COSE.
enum CoseErrorCode {
  /// The input is not a byte list or definite four-element COSE_Sign1 array.
  invalidStructure,

  /// A COSE field has the wrong CBOR major type or decoded Dart type.
  invalidType,

  /// Embedded CBOR is malformed, non-minimal, indefinite, or unaddressable.
  invalidCbor,

  /// A decoded COSE header label is not an integer.
  invalidHeaderLabel,

  /// A standard COSE header has a value type this package rejects.
  invalidHeaderValue,

  /// The same header label appears in protected and unprotected headers.
  duplicateHeader,

  /// The protected header map does not contain the `alg` header.
  missingProtectedAlgorithm,

  /// A semantic tag other than canonical COSE_Sign1 tag 18 appears.
  unsupportedTag,

  /// An untagged COSE_Sign1 message appears when a tag is required.
  tagRequired,

  /// A tagged COSE_Sign1 message appears when tags are forbidden.
  tagForbidden,

  /// Bytes remain after the COSE_Sign1 message.
  trailingData,

  /// A COSE or embedded CBOR field ends before its declared length.
  truncated,

  /// The COSE or embedded CBOR structure exceeds the nesting limit.
  excessiveNesting,

  /// A Sig_structure is requested for a detached payload with no bytes.
  detachedPayloadRequired,

  /// A detached payload is supplied for a message with an embedded payload.
  conflictingPayload,
}

/// An immutable error raised while reading or writing COSE.
final class CoseException implements Exception {
  /// Creates a COSE exception with [code], [message], and [offset].
  const CoseException(this.code, this.message, {this.offset});

  /// The specific COSE failure.
  final CoseErrorCode code;

  /// A human-readable description of the failed COSE condition.
  final String message;

  /// The byte offset at which parsing failed, or `null` if unavailable.
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'CoseException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while decoding Brotli.
enum BrotliDecodingErrorCode {
  /// The requested maximum decoded size is negative.
  invalidLimit,

  /// The Brotli stream ended while more input was required.
  truncated,

  /// The input bytes or Brotli coding are malformed.
  malformed,

  /// Decoding produced more than the configured maximum output bytes.
  outputLimitExceeded,
}

/// An immutable error raised while decoding Brotli.
final class BrotliDecodingException implements Exception {
  /// Creates a Brotli decoding exception with [code] and [message].
  const BrotliDecodingException(this.code, this.message);

  /// The specific Brotli decoding failure.
  final BrotliDecodingErrorCode code;

  /// A human-readable description of the failed Brotli condition.
  final String message;

  @override
  String toString() => 'BrotliDecodingException(${code.name}): $message';
}

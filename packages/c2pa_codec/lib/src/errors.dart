/// The kind of failure encountered while encoding CBOR.
enum CborEncodingErrorCode {
  unsupportedType,
  integerOutOfRange,
  nonFiniteDouble,
  duplicateMapKey,
  excessiveNesting,
}

/// An immutable error raised while encoding CBOR.
final class CborEncodingException implements Exception {
  const CborEncodingException(this.code, this.message);

  final CborEncodingErrorCode code;
  final String message;

  @override
  String toString() => 'CborEncodingException(${code.name}): $message';
}

/// The kind of failure encountered while decoding CBOR.
enum CborDecodingErrorCode {
  trailingData,
  truncated,
  indefiniteLength,
  invalidUtf8,
  duplicateMapKey,
  nonCanonicalMapOrder,
  nonMinimalInteger,
  excessiveNesting,
  unsupportedTag,
  unsupportedSimpleValue,
  integerOutOfRange,
  nonFiniteDouble,
  invalidAdditionalInformation,
}

/// An immutable error raised while decoding CBOR.
final class CborDecodingException implements Exception {
  const CborDecodingException(this.code, this.message, {required this.offset});

  final CborDecodingErrorCode code;
  final String message;
  final int offset;

  @override
  String toString() =>
      'CborDecodingException(${code.name}, offset: $offset): $message';
}

/// The kind of failure encountered while reading or writing an ISO box header.
enum IsoBoxErrorCode {
  invalidOffset,
  truncated,
  invalidType,
  invalidSize,
  sizeOutOfRange,
  missingUserType,
  unexpectedUserType,
}

/// An immutable error raised while reading or writing an ISO box header.
final class IsoBoxException implements Exception {
  const IsoBoxException(this.code, this.message, {this.offset});

  final IsoBoxErrorCode code;
  final String message;
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'IsoBoxException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while reading or writing JUMBF.
enum JumbfErrorCode {
  invalidBounds,
  invalidBox,
  expectedSuperBox,
  expectedDescriptionBox,
  invalidDescription,
  unsupportedDescriptionFeature,
  invalidUtf8,
  invalidEmbeddedFileDescription,
  duplicateLabel,
  excessiveNesting,
  excessiveBoxCount,
  trailingData,
  invalidCompressedManifest,
  compressedManifestLabelMismatch,
}

/// An immutable error raised while reading or writing JUMBF.
final class JumbfException implements Exception {
  const JumbfException(this.code, this.message, {this.offset});

  final JumbfErrorCode code;
  final String message;
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'JumbfException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while reading or writing COSE.
enum CoseErrorCode {
  invalidStructure,
  invalidType,
  invalidCbor,
  invalidHeaderLabel,
  invalidHeaderValue,
  duplicateHeader,
  missingProtectedAlgorithm,
  unsupportedTag,
  tagRequired,
  tagForbidden,
  trailingData,
  truncated,
  excessiveNesting,
  detachedPayloadRequired,
  conflictingPayload,
}

/// An immutable error raised while reading or writing COSE.
final class CoseException implements Exception {
  const CoseException(this.code, this.message, {this.offset});

  final CoseErrorCode code;
  final String message;
  final int? offset;

  @override
  String toString() {
    final location = offset == null ? '' : ', offset: $offset';
    return 'CoseException(${code.name}$location): $message';
  }
}

/// The kind of failure encountered while decoding Brotli.
enum BrotliDecodingErrorCode {
  invalidLimit,
  truncated,
  malformed,
  outputLimitExceeded,
}

/// An immutable error raised while decoding Brotli.
final class BrotliDecodingException implements Exception {
  const BrotliDecodingException(this.code, this.message);

  final BrotliDecodingErrorCode code;
  final String message;

  @override
  String toString() => 'BrotliDecodingException(${code.name}): $message';
}

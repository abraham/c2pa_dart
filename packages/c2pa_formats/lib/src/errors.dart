import 'asset_format.dart';

/// A failure while detecting, reading, or mutating an asset format.
sealed class AssetFormatException implements Exception {
  /// Creates a format exception with a human-readable [message].
  const AssetFormatException(this.message);

  /// Human-readable diagnostic text describing the failing condition.
  final String message;

  /// A diagnostic string containing the exception type and [message].
  @override
  String toString() => '$runtimeType: $message';
}

/// An asset whose format no registered handler can identify.
final class UnknownAssetFormatException extends AssetFormatException {
  /// Creates an exception for failed MIME, extension, and magic detection.
  const UnknownAssetFormatException()
    : super('The asset format could not be identified.');
}

/// A request to extract a manifest from a format that cannot carry one.
final class UnsupportedManifestExtractionException
    extends AssetFormatException {
  /// Creates an exception for unsupported extraction from [format].
  const UnsupportedManifestExtractionException(this.format)
    : super('Manifest extraction is not supported for the detected format.');

  /// The detected format whose handler cannot extract manifests.
  final AssetFormat format;
}

/// Asset bytes that violate the expected container structure.
final class MalformedAssetFormatException extends AssetFormatException {
  /// Creates an exception with a container-specific parse [message].
  const MalformedAssetFormatException(super.message);
}

/// Asset bytes that end before a required structure is complete.
final class TruncatedAssetException extends AssetFormatException {
  /// Creates an exception for a byte range shorter than [expectedLength].
  const TruncatedAssetException({
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'The asset is truncated: expected $expectedLength bytes, '
         'but only $actualLength are available.',
       );

  /// The minimum byte length or absolute byte position required.
  final int expectedLength;

  /// The byte length that was actually available.
  final int actualLength;
}

/// A parsed asset that does not contain a C2PA manifest store.
final class ManifestNotFoundException extends AssetFormatException {
  /// Creates an exception for a missing manifest in [format].
  const ManifestNotFoundException(this.format)
    : super('No C2PA manifest store was found in the asset.');

  /// The format that was parsed without finding a manifest store.
  final AssetFormat format;
}

/// Declared or observed asset data that exceeds a configured byte limit.
final class AssetLimitExceededException extends AssetFormatException {
  /// Creates an exception with the supported [limit] and [actual] bytes.
  const AssetLimitExceededException({required this.limit, required this.actual})
    : super(
        'The declared asset data size $actual exceeds the supported '
        'limit of $limit bytes.',
      );

  /// The maximum supported value, in bytes unless noted by the caller.
  final int limit;

  /// The declared or observed value that exceeded [limit].
  final int actual;
}

/// A segment, box, chunk, rule, or entry count above a safety limit.
final class SegmentLimitExceededException extends AssetFormatException {
  /// Creates an exception with the supported [limit] and [actual] count.
  const SegmentLimitExceededException({
    required this.limit,
    required this.actual,
  }) : super(
         'The segment count $actual exceeds the supported limit of $limit.',
       );

  /// The maximum supported count for the parsed structure.
  final int limit;

  /// The count that exceeded [limit].
  final int actual;
}

/// A PNG chunk whose stored CRC-32 does not match its bytes.
final class InvalidChunkCrcException extends AssetFormatException {
  /// Creates an exception for [chunkType] with mismatched CRC values.
  const InvalidChunkCrcException({
    required this.chunkType,
    required this.expected,
    required this.actual,
  }) : super('The $chunkType chunk has an invalid CRC-32 value.');

  /// The four-byte PNG chunk type whose CRC check failed.
  final String chunkType;

  /// The CRC-32 value stored in the chunk trailer.
  final int expected;

  /// The CRC-32 value computed from the chunk type and payload.
  final int actual;
}

/// A requested mutation of an embedded C2PA manifest store.
///
/// [embed] adds a new store, [replace] rewrites an existing store, and
/// [remove] deletes an existing store.
enum ManifestMutationOperation {
  /// Embedding a new manifest store into an asset.
  embed,

  /// Replacing an existing manifest store in an asset.
  replace,

  /// Removing an existing manifest store from an asset.
  remove,
}

/// A manifest mutation requested for a format that cannot perform it.
final class UnsupportedManifestMutationException extends AssetFormatException {
  /// Creates an exception for [operation] on [format].
  const UnsupportedManifestMutationException(this.format, this.operation)
    : super('The requested manifest mutation is not supported.');

  /// The format whose handler rejected the manifest mutation.
  final AssetFormat format;

  /// The requested mutation that the handler does not support.
  final ManifestMutationOperation operation;
}

/// An embed request for an asset that already has a manifest store.
final class ManifestAlreadyExistsException extends AssetFormatException {
  /// Creates an exception for an existing manifest in [format].
  const ManifestAlreadyExistsException(this.format)
    : super('The asset already contains a C2PA manifest store.');

  /// The format that already contains a manifest store.
  final AssetFormat format;
}

/// A TIFF variant outside the classic TIFF structures this SDK parses.
final class UnsupportedTiffVariantException extends AssetFormatException {
  /// Creates an exception for BigTIFF input.
  const UnsupportedTiffVariantException()
    : super('BigTIFF is not supported by this TIFF handler.');
}

/// A C2PA hash assertion layout requested from a format handler.
///
/// [dataHash] covers byte ranges, [boxHash] covers structured boxes, and
/// [bmffHash] covers ISO BMFF box-exclusion hashing.
enum HashLayoutKind {
  /// C2PA data-hash layout over byte ranges.
  dataHash,

  /// C2PA box-hash layout over structured container boxes.
  boxHash,

  /// C2PA BMFF hash layout over ISO BMFF box exclusions.
  bmffHash,
}

/// A hash layout requested from a format that cannot provide it.
final class UnsupportedHashLayoutException extends AssetFormatException {
  /// Creates an exception for unsupported [layout] metadata on [format].
  const UnsupportedHashLayoutException(this.format, this.layout)
    : super('The requested hash layout metadata is not supported.');

  /// The format whose handler cannot provide the requested layout.
  final AssetFormat format;

  /// The requested hash layout kind that is unavailable.
  final HashLayoutKind layout;
}

/// An XMP metadata operation requested from a format handler.
enum XmpOperation {
  /// Reading an asset's embedded XMP packet.
  read,

  /// Reading the C2PA remote manifest reference from XMP.
  readRemoteReference,

  /// Adding a C2PA remote manifest reference to XMP.
  embedRemoteReference,

  /// Rewriting an existing C2PA remote manifest reference in XMP.
  updateRemoteReference,

  /// Removing a C2PA remote manifest reference from XMP.
  removeRemoteReference,
}

/// XMP metadata that lacks a C2PA remote manifest reference.
final class RemoteManifestReferenceNotFoundException
    extends AssetFormatException {
  /// Creates an exception for a missing remote reference in [format].
  const RemoteManifestReferenceNotFoundException(this.format)
    : super('No C2PA remote manifest reference was found.');

  /// The format whose XMP lacks the remote reference.
  final AssetFormat format;
}

/// An XMP operation requested from a format that cannot perform it.
final class UnsupportedXmpOperationException extends AssetFormatException {
  /// Creates an exception for unsupported [operation] on [format].
  const UnsupportedXmpOperationException(this.format, this.operation)
    : super('The requested XMP operation is not supported.');

  /// The format whose handler cannot perform the XMP operation.
  final AssetFormat format;

  /// The XMP operation that is unavailable.
  final XmpOperation operation;
}

/// XMP content that uses a feature this SDK deliberately rejects.
final class UnsupportedXmpFeatureException extends AssetFormatException {
  /// Creates an exception naming the unsupported XMP [feature].
  const UnsupportedXmpFeatureException(this.feature)
    : super('The XMP feature "$feature" is not supported.');

  /// The XMP feature or syntax condition that is not supported.
  final String feature;
}

/// A top-level ISO BMFF box listing requested from another format.
final class UnsupportedIsoBmffBoxListingException extends AssetFormatException {
  /// Creates an exception for box listing on non-BMFF [format].
  const UnsupportedIsoBmffBoxListingException(this.format)
    : super('Top-level ISO BMFF box listing is not supported.');

  /// The format whose handler cannot list ISO BMFF boxes.
  final AssetFormat format;
}

/// ISO BMFF data or options outside the supported C2PA profile.
final class UnsupportedIsoBmffFeatureException extends AssetFormatException {
  /// Creates an exception naming the unsupported ISO BMFF [feature].
  const UnsupportedIsoBmffFeatureException(this.feature)
    : super('The ISO BMFF feature "$feature" is not supported.');

  /// The BMFF feature or option that cannot be processed.
  final String feature;
}

/// BMFF hash-exclusion metadata that violates layout invariants.
final class MalformedBmffHashLayoutException extends AssetFormatException {
  /// Creates an exception with a hash-layout validation [message].
  const MalformedBmffHashLayoutException(super.message);
}

/// A raw JPEG XL codestream requested for embedded manifest handling.
final class UnsupportedJpegXlCodestreamException extends AssetFormatException {
  /// Creates an exception for JPEG XL input without a container box layer.
  const UnsupportedJpegXlCodestreamException()
    : super(
        'A raw JPEG XL codestream cannot contain an embedded C2PA manifest.',
      );
}

/// JPEG XL data or options outside the supported C2PA box profile.
final class UnsupportedJpegXlFeatureException extends AssetFormatException {
  /// Creates an exception naming the unsupported JPEG XL [feature].
  const UnsupportedJpegXlFeatureException(this.feature)
    : super('The JPEG XL feature "$feature" is not supported.');

  /// The JPEG XL feature that cannot be processed.
  final String feature;
}

/// ZIP archive data outside the supported deterministic rewrite profile.
final class UnsupportedZipFeatureException extends AssetFormatException {
  /// Creates an exception naming the unsupported ZIP [feature].
  const UnsupportedZipFeatureException(this.feature)
    : super('The ZIP feature "$feature" is not supported.');

  /// The ZIP feature that cannot be processed.
  final String feature;
}

/// PDF data or requested mutations outside the supported PDF profile.
final class UnsupportedPdfFeatureException extends AssetFormatException {
  /// Creates an exception naming the unsupported PDF [feature].
  const UnsupportedPdfFeatureException(this.feature)
    : super('The PDF feature "$feature" is not supported.');

  /// The PDF feature that cannot be processed.
  final String feature;
}

/// A ZIP collection hash layout requested from a non-collection format.
final class UnsupportedCollectionHashLayoutException
    extends AssetFormatException {
  /// Creates an exception for collection hashing on [format].
  const UnsupportedCollectionHashLayoutException(this.format)
    : super('Collection hash layout metadata is not supported.');

  /// The format that is not a ZIP-style collection.
  final AssetFormat format;
}

import 'asset_format.dart';

sealed class AssetFormatException implements Exception {
  const AssetFormatException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

final class UnknownAssetFormatException extends AssetFormatException {
  const UnknownAssetFormatException()
    : super('The asset format could not be identified.');
}

final class UnsupportedManifestExtractionException
    extends AssetFormatException {
  const UnsupportedManifestExtractionException(this.format)
    : super('Manifest extraction is not supported for the detected format.');

  final AssetFormat format;
}

final class MalformedAssetFormatException extends AssetFormatException {
  const MalformedAssetFormatException(super.message);
}

final class TruncatedAssetException extends AssetFormatException {
  const TruncatedAssetException({
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'The asset is truncated: expected $expectedLength bytes, '
         'but only $actualLength are available.',
       );

  final int expectedLength;
  final int actualLength;
}

final class ManifestNotFoundException extends AssetFormatException {
  const ManifestNotFoundException(this.format)
    : super('No C2PA manifest store was found in the asset.');

  final AssetFormat format;
}

final class AssetLimitExceededException extends AssetFormatException {
  const AssetLimitExceededException({required this.limit, required this.actual})
    : super(
        'The declared asset data size $actual exceeds the supported '
        'limit of $limit bytes.',
      );

  final int limit;
  final int actual;
}

final class SegmentLimitExceededException extends AssetFormatException {
  const SegmentLimitExceededException({
    required this.limit,
    required this.actual,
  }) : super(
         'The segment count $actual exceeds the supported limit of $limit.',
       );

  final int limit;
  final int actual;
}

final class InvalidChunkCrcException extends AssetFormatException {
  const InvalidChunkCrcException({
    required this.chunkType,
    required this.expected,
    required this.actual,
  }) : super('The $chunkType chunk has an invalid CRC-32 value.');

  final String chunkType;
  final int expected;
  final int actual;
}

enum ManifestMutationOperation { embed, replace, remove }

final class UnsupportedManifestMutationException extends AssetFormatException {
  const UnsupportedManifestMutationException(this.format, this.operation)
    : super('The requested manifest mutation is not supported.');

  final AssetFormat format;
  final ManifestMutationOperation operation;
}

final class ManifestAlreadyExistsException extends AssetFormatException {
  const ManifestAlreadyExistsException(this.format)
    : super('The asset already contains a C2PA manifest store.');

  final AssetFormat format;
}

final class UnsupportedTiffVariantException extends AssetFormatException {
  const UnsupportedTiffVariantException()
    : super('BigTIFF is not supported by this TIFF handler.');
}

enum HashLayoutKind { dataHash, boxHash, bmffHash }

final class UnsupportedHashLayoutException extends AssetFormatException {
  const UnsupportedHashLayoutException(this.format, this.layout)
    : super('The requested hash layout metadata is not supported.');

  final AssetFormat format;
  final HashLayoutKind layout;
}

enum XmpOperation {
  read,
  readRemoteReference,
  embedRemoteReference,
  updateRemoteReference,
  removeRemoteReference,
}

final class RemoteManifestReferenceNotFoundException
    extends AssetFormatException {
  const RemoteManifestReferenceNotFoundException(this.format)
    : super('No C2PA remote manifest reference was found.');

  final AssetFormat format;
}

final class UnsupportedXmpOperationException extends AssetFormatException {
  const UnsupportedXmpOperationException(this.format, this.operation)
    : super('The requested XMP operation is not supported.');

  final AssetFormat format;
  final XmpOperation operation;
}

final class UnsupportedXmpFeatureException extends AssetFormatException {
  const UnsupportedXmpFeatureException(this.feature)
    : super('The XMP feature "$feature" is not supported.');

  final String feature;
}

final class UnsupportedIsoBmffBoxListingException extends AssetFormatException {
  const UnsupportedIsoBmffBoxListingException(this.format)
    : super('Top-level ISO BMFF box listing is not supported.');

  final AssetFormat format;
}

final class UnsupportedIsoBmffFeatureException extends AssetFormatException {
  const UnsupportedIsoBmffFeatureException(this.feature)
    : super('The ISO BMFF feature "$feature" is not supported.');

  final String feature;
}

final class MalformedBmffHashLayoutException extends AssetFormatException {
  const MalformedBmffHashLayoutException(super.message);
}

final class UnsupportedJpegXlCodestreamException extends AssetFormatException {
  const UnsupportedJpegXlCodestreamException()
    : super(
        'A raw JPEG XL codestream cannot contain an embedded C2PA manifest.',
      );
}

final class UnsupportedJpegXlFeatureException extends AssetFormatException {
  const UnsupportedJpegXlFeatureException(this.feature)
    : super('The JPEG XL feature "$feature" is not supported.');

  final String feature;
}

final class UnsupportedZipFeatureException extends AssetFormatException {
  const UnsupportedZipFeatureException(this.feature)
    : super('The ZIP feature "$feature" is not supported.');

  final String feature;
}

final class UnsupportedPdfFeatureException extends AssetFormatException {
  const UnsupportedPdfFeatureException(this.feature)
    : super('The PDF feature "$feature" is not supported.');

  final String feature;
}

final class UnsupportedCollectionHashLayoutException
    extends AssetFormatException {
  const UnsupportedCollectionHashLayoutException(this.format)
    : super('Collection hash layout metadata is not supported.');

  final AssetFormat format;
}

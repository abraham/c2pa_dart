import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'asset_format.dart';
import 'asset_handler.dart';
import 'errors.dart';
import 'handlers/flac_handler.dart';
import 'handlers/gif_handler.dart';
import 'handlers/isobmff_handler.dart';
import 'handlers/jpeg_handler.dart';
import 'handlers/jpeg_xl_handler.dart';
import 'handlers/mp3_handler.dart';
import 'handlers/pdf_handler.dart';
import 'handlers/png_handler.dart';
import 'handlers/riff_handler.dart';
import 'handlers/standalone_c2pa_handler.dart';
import 'handlers/svg_handler.dart';
import 'handlers/tiff_handler.dart';
import 'handlers/zip_handler.dart';
import 'hash_layout.dart';
import 'isobmff.dart';
import 'isobmff_hash_layout.dart';
import 'xmp.dart';
import 'zip_collection.dart';

/// A format-dispatch registry for C2PA asset handlers.
final class AssetHandlerRegistry {
  /// Creates a registry using [handlers] or the built-in handler order.
  ///
  /// The first handler whose MIME type, file extension, or magic bytes match is
  /// used for all subsequent operations.
  AssetHandlerRegistry({Iterable<AssetHandler>? handlers})
    : _handlers = List<AssetHandler>.unmodifiable(
        handlers ??
            const <AssetHandler>[
              StandaloneC2paHandler(),
              JpegHandler(),
              PngHandler(),
              GifAssetHandler(),
              RiffAssetHandler(format: AssetFormat.webp),
              RiffAssetHandler(format: AssetFormat.wav),
              RiffAssetHandler(format: AssetFormat.avi),
              TiffAssetHandler(),
              SvgAssetHandler(),
              JpegXlAssetHandler(),
              IsoBmffAssetHandler(format: AssetFormat.avif),
              IsoBmffAssetHandler(format: AssetFormat.heic),
              IsoBmffAssetHandler(format: AssetFormat.heif),
              IsoBmffAssetHandler(format: AssetFormat.mov),
              IsoBmffAssetHandler(format: AssetFormat.m4a),
              IsoBmffAssetHandler(format: AssetFormat.mp4),
              ZipAssetHandler(format: AssetFormat.epub),
              ZipAssetHandler(format: AssetFormat.openXps),
              ZipAssetHandler(format: AssetFormat.ooxml),
              ZipAssetHandler(format: AssetFormat.openDocument),
              ZipAssetHandler(format: AssetFormat.zip),
              PdfAssetHandler(),
              FlacAssetHandler(),
              Mp3AssetHandler(),
            ],
      );

  final List<AssetHandler> _handlers;

  /// Registered handlers in detection priority order.
  List<AssetHandler> get handlers => _handlers;

  /// Detects the asset format for [source].
  ///
  /// Non-null [mimeType] is tried first, then [fileExtension], then handler
  /// magic-byte detection. Unknown assets return an unknown
  /// [AssetDetectionResult],
  /// rather than throwing.
  Future<AssetDetectionResult> detect(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final normalizedMimeType = _normalizeMimeType(mimeType);
    if (normalizedMimeType != null) {
      final handler = _firstHandlerMatchingMimeType(normalizedMimeType);
      if (handler != null) {
        return AssetDetectionResult(
          format: handler.format,
          method: AssetDetectionMethod.mimeType,
          handler: handler,
        );
      }
    }

    final normalizedExtension = _normalizeExtension(fileExtension);
    if (normalizedExtension != null) {
      final handler = _firstHandlerMatchingExtension(normalizedExtension);
      if (handler != null) {
        return AssetDetectionResult(
          format: handler.format,
          method: AssetDetectionMethod.fileExtension,
          handler: handler,
        );
      }
    }

    for (final handler in _handlers) {
      if (handler.capabilities.canDetect && await handler.detect(source)) {
        return AssetDetectionResult(
          format: handler.format,
          method: AssetDetectionMethod.magicBytes,
          handler: handler,
        );
      }
    }

    return const AssetDetectionResult.unknown();
  }

  /// Extracts the embedded C2PA manifest store from [source].
  ///
  /// Throws [UnknownAssetFormatException] when no handler matches and
  /// [UnsupportedManifestExtractionException] when the detected handler cannot
  /// extract manifests.
  Future<Uint8List> extractManifest(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final result = await detect(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    final handler = result.handler;
    if (handler == null) {
      throw const UnknownAssetFormatException();
    }
    if (!handler.capabilities.canExtractManifest) {
      throw UnsupportedManifestExtractionException(result.format);
    }
    return handler.extractManifest(source);
  }

  /// Embeds [manifest] in [source] and writes the new asset to [output].
  ///
  /// Throws [UnknownAssetFormatException] when no handler matches and
  /// [UnsupportedManifestMutationException] when embedding is unsupported.
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canEmbedManifest) {
      throw UnsupportedManifestMutationException(
        handler.format,
        ManifestMutationOperation.embed,
      );
    }
    await handler.embedManifest(source, manifest, output);
  }

  /// Replaces the embedded C2PA [manifest] and writes to [output].
  ///
  /// Throws [UnknownAssetFormatException] when no handler matches and
  /// [UnsupportedManifestMutationException] when replacement is unsupported.
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canReplaceManifest) {
      throw UnsupportedManifestMutationException(
        handler.format,
        ManifestMutationOperation.replace,
      );
    }
    await handler.replaceManifest(source, manifest, output);
  }

  /// Removes the embedded C2PA manifest and writes the asset to [output].
  ///
  /// Throws [UnknownAssetFormatException] when no handler matches and
  /// [UnsupportedManifestMutationException] when removal is unsupported.
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canRemoveManifest) {
      throw UnsupportedManifestMutationException(
        handler.format,
        ManifestMutationOperation.remove,
      );
    }
    await handler.removeManifest(source, output);
  }

  /// Gets the C2PA data-hash layout for [source].
  ///
  /// Throws [UnsupportedHashLayoutException] when the detected format has no
  /// data-hash layout provider.
  Future<DataHashLayout> getDataHashLayout(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideDataHashLayout ||
        handler is! DataHashLayoutProvider) {
      throw UnsupportedHashLayoutException(
        handler.format,
        HashLayoutKind.dataHash,
      );
    }
    return (handler as DataHashLayoutProvider).getDataHashLayout(source);
  }

  /// Gets the C2PA box-hash layout for [source].
  ///
  /// Throws [UnsupportedHashLayoutException] when the detected format has no
  /// box-hash layout provider.
  Future<BoxHashLayout> getBoxHashLayout(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideBoxHashLayout ||
        handler is! BoxHashLayoutProvider) {
      throw UnsupportedHashLayoutException(
        handler.format,
        HashLayoutKind.boxHash,
      );
    }
    return (handler as BoxHashLayoutProvider).getBoxHashLayout(source);
  }

  /// Reads XMP metadata from [source], or `null` when none exists.
  ///
  /// Throws [UnsupportedXmpOperationException] when the detected handler cannot
  /// read XMP metadata.
  Future<String?> readXmp(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canReadXmp || handler is! XmpMetadataProvider) {
      throw UnsupportedXmpOperationException(handler.format, XmpOperation.read);
    }

    return (handler as XmpMetadataProvider).readXmp(source);
  }

  /// Lists top-level ISO BMFF boxes in [source].
  ///
  /// Throws [UnsupportedIsoBmffBoxListingException] when the detected format is
  /// not an ISO BMFF box provider.
  Future<List<IsoBmffBox>> getTopLevelBoxes(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canListTopLevelBoxes ||
        handler is! IsoBmffBoxProvider) {
      throw UnsupportedIsoBmffBoxListingException(handler.format);
    }

    return (handler as IsoBmffBoxProvider).getTopLevelBoxes(source);
  }

  /// Builds C2PA BMFF hash metadata for [source].
  ///
  /// [logicalOffset] and [segmentIndex] describe the segment's position in a
  /// fragmented asset. Throws [UnsupportedHashLayoutException] when unsupported.
  Future<IsoBmffHashLayout> getBmffHashLayout(
    RandomAccessByteSource source,
    List<IsoBmffExclusion> exclusions, {
    String? mimeType,
    String? fileExtension,
    int version = 2,
    int logicalOffset = 0,
    int segmentIndex = 0,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideBmffHashLayout ||
        handler is! IsoBmffHashLayoutProvider) {
      throw UnsupportedHashLayoutException(
        handler.format,
        HashLayoutKind.bmffHash,
      );
    }
    return (handler as IsoBmffHashLayoutProvider).getBmffHashLayout(
      source,
      exclusions,
      version: version,
      logicalOffset: logicalOffset,
      segmentIndex: segmentIndex,
    );
  }

  /// Builds C2PA BMFF hash metadata for a fragmented BMFF [source].
  ///
  /// Detection uses the initialization segment. Throws
  /// [UnsupportedHashLayoutException] when the detected handler cannot describe
  /// BMFF hash layouts.
  Future<FragmentedIsoBmffLayout> getFragmentedBmffLayout(
    FragmentedIsoBmffSource source,
    List<IsoBmffExclusion> exclusions, {
    String? mimeType,
    String? fileExtension,
    int version = 2,
  }) async {
    final handler = await _handlerFor(
      source.initializationSegment,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideBmffHashLayout ||
        handler is! IsoBmffHashLayoutProvider) {
      throw UnsupportedHashLayoutException(
        handler.format,
        HashLayoutKind.bmffHash,
      );
    }
    return (handler as IsoBmffHashLayoutProvider).getFragmentedBmffLayout(
      source,
      exclusions,
      version: version,
    );
  }

  /// Gets the collection-hash layout for a ZIP-like [source].
  ///
  /// Throws [UnsupportedCollectionHashLayoutException] when the detected format
  /// does not expose ZIP collection hash metadata.
  Future<ZipCollectionLayout> getCollectionHashLayout(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideCollectionHashLayout ||
        handler is! ZipCollectionLayoutProvider) {
      throw UnsupportedCollectionHashLayoutException(handler.format);
    }
    return (handler as ZipCollectionLayoutProvider).getCollectionHashLayout(
      source,
    );
  }

  /// Reads central-directory bytes used by ZIP collection hashing.
  ///
  /// The returned bytes concatenate all ranges from
  /// `ZipCollectionLayout.centralDirectoryHashRanges`.
  Future<Uint8List> readCentralDirectoryHashMaterial(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canProvideCollectionHashLayout ||
        handler is! ZipCollectionLayoutProvider) {
      throw UnsupportedCollectionHashLayoutException(handler.format);
    }
    return (handler as ZipCollectionLayoutProvider)
        .readCentralDirectoryHashMaterial(source);
  }

  /// Embeds a remote manifest [reference] in XMP metadata.
  ///
  /// Throws [UnsupportedXmpOperationException] when the detected handler cannot
  /// add a remote reference.
  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canEmbedRemoteReference ||
        handler is! XmpMetadataProvider) {
      throw UnsupportedXmpOperationException(
        handler.format,
        XmpOperation.embedRemoteReference,
      );
    }
    await (handler as XmpMetadataProvider).embedRemoteReference(
      source,
      reference,
      output,
    );
  }

  /// Reads the XMP `dcterms:provenance` remote manifest reference.
  ///
  /// Returns `null` when the asset has no XMP packet or no provenance value.
  /// Throws [UnsupportedXmpOperationException] when reading is unsupported.
  Future<String?> readRemoteManifestReference(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canReadRemoteReference ||
        handler is! RemoteManifestReferenceProvider) {
      throw UnsupportedXmpOperationException(
        handler.format,
        XmpOperation.readRemoteReference,
      );
    }
    return (handler as RemoteManifestReferenceProvider)
        .readRemoteManifestReference(source);
  }

  /// Updates the XMP `dcterms:provenance` remote manifest [reference].
  ///
  /// Throws [UnsupportedXmpOperationException] when the detected handler cannot
  /// update remote references.
  Future<void> updateRemoteManifestReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canEmbedRemoteReference ||
        handler is! RemoteManifestReferenceProvider) {
      throw UnsupportedXmpOperationException(
        handler.format,
        XmpOperation.updateRemoteReference,
      );
    }
    await (handler as RemoteManifestReferenceProvider)
        .updateRemoteManifestReference(source, reference, output);
  }

  /// Removes the XMP `dcterms:provenance` remote manifest reference.
  ///
  /// Throws [UnsupportedXmpOperationException] when the detected handler cannot
  /// remove remote references.
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final handler = await _handlerFor(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    if (!handler.capabilities.canRemoveRemoteReference ||
        handler is! RemoteManifestReferenceProvider) {
      throw UnsupportedXmpOperationException(
        handler.format,
        XmpOperation.removeRemoteReference,
      );
    }
    await (handler as RemoteManifestReferenceProvider)
        .removeRemoteManifestReference(source, output);
  }

  Future<AssetHandler> _handlerFor(
    RandomAccessByteSource source, {
    String? mimeType,
    String? fileExtension,
  }) async {
    final result = await detect(
      source,
      mimeType: mimeType,
      fileExtension: fileExtension,
    );
    final handler = result.handler;
    if (handler == null) throw const UnknownAssetFormatException();
    return handler;
  }

  AssetHandler? _firstHandlerMatchingMimeType(String mimeType) {
    for (final handler in _handlers) {
      if (handler.capabilities.mimeTypes.any(
        (candidate) => candidate.toLowerCase() == mimeType,
      )) {
        return handler;
      }
    }
    return null;
  }

  AssetHandler? _firstHandlerMatchingExtension(String extension) {
    for (final handler in _handlers) {
      if (handler.capabilities.fileExtensions.any(
        (candidate) => _normalizeExtension(candidate) == extension,
      )) {
        return handler;
      }
    }
    return null;
  }

  static String? _normalizeMimeType(String? mimeType) {
    if (mimeType == null) return null;
    final normalized = mimeType.split(';').first.trim().toLowerCase();
    return normalized.isEmpty ? null : normalized;
  }

  static String? _normalizeExtension(String? extension) {
    if (extension == null) return null;
    var normalized = extension.trim().toLowerCase();
    while (normalized.startsWith('.')) {
      normalized = normalized.substring(1);
    }
    return normalized.isEmpty ? null : normalized;
  }
}

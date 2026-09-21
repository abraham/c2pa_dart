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

final class AssetHandlerRegistry {
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

  List<AssetHandler> get handlers => _handlers;

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

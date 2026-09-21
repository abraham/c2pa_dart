import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'asset_format.dart';

/// Feature flags and metadata advertised by an [AssetHandler].
final class AssetHandlerCapabilities {
  /// Creates a capability set for one concrete handler implementation.
  const AssetHandlerCapabilities({
    required this.canDetect,
    required this.canExtractManifest,
    this.canEmbedManifest = false,
    this.canReplaceManifest = false,
    this.canRemoveManifest = false,
    this.canProvideDataHashLayout = false,
    this.canProvideBoxHashLayout = false,
    this.canReadXmp = false,
    this.canEmbedRemoteReference = false,
    this.canReadRemoteReference = false,
    this.canRemoveRemoteReference = false,
    this.canListTopLevelBoxes = false,
    this.canProvideCollectionHashLayout = false,
    this.canProvideBmffHashLayout = false,
    this.mimeTypes = const <String>[],
    this.fileExtensions = const <String>[],
  });

  /// Whether `AssetHandler.detect` can probe magic bytes for this format.
  final bool canDetect;

  /// Whether `AssetHandler.extractManifest` is supported.
  final bool canExtractManifest;

  /// Whether `AssetHandler.embedManifest` can add a new manifest store.
  final bool canEmbedManifest;

  /// Whether `AssetHandler.replaceManifest` can rewrite an existing store.
  final bool canReplaceManifest;

  /// Whether `AssetHandler.removeManifest` can delete an existing store.
  final bool canRemoveManifest;

  /// Whether the handler can provide C2PA data-hash byte ranges.
  final bool canProvideDataHashLayout;

  /// Whether the handler can provide C2PA box-hash layout metadata.
  final bool canProvideBoxHashLayout;

  /// Whether the handler can return the embedded XMP packet, if any.
  final bool canReadXmp;

  /// Whether the handler can add or update an XMP remote reference.
  final bool canEmbedRemoteReference;

  /// Whether the handler can read a C2PA remote reference from XMP.
  final bool canReadRemoteReference;

  /// Whether the handler can remove a C2PA remote reference from XMP.
  final bool canRemoveRemoteReference;

  /// Whether the handler can list top-level ISO BMFF boxes.
  final bool canListTopLevelBoxes;

  /// Whether the handler can provide ZIP collection hash metadata.
  final bool canProvideCollectionHashLayout;

  /// Whether the handler can provide ISO BMFF hash layout metadata.
  final bool canProvideBmffHashLayout;

  /// Lowercase MIME types that should select this handler without probing.
  final List<String> mimeTypes;

  /// File extensions, without leading dots, that should select this handler.
  final List<String> fileExtensions;
}

/// The selected handler, format, and evidence from asset detection.
final class AssetDetectionResult {
  /// Creates a detection result from a known [format] and [method].
  const AssetDetectionResult({
    required this.format,
    required this.method,
    this.handler,
  });

  /// Creates a detection result for an asset no handler recognized.
  const AssetDetectionResult.unknown()
    : format = AssetFormat.unknown,
      method = AssetDetectionMethod.none,
      handler = null;

  /// The detected format, or `AssetFormat.unknown` when not recognized.
  final AssetFormat format;

  /// The evidence that selected [format].
  final AssetDetectionMethod method;

  /// The handler that matched the asset, or `null` when unknown.
  final AssetHandler? handler;

  /// Whether detection found both a non-unknown [format] and [handler].
  bool get isKnown => handler != null && format != AssetFormat.unknown;
}

/// Format-specific parser and manifest mutator used by the registry.
abstract interface class AssetHandler {
  /// Human-readable handler name used in diagnostics.
  String get name;

  /// The single asset format this handler implements.
  AssetFormat get format;

  /// The operations this handler promises to support.
  AssetHandlerCapabilities get capabilities;

  /// Tests whether [source] appears to be this handler's [format].
  ///
  /// Implementations may read from [source] but must not consume global state
  /// or write output. Return `false` for a clean mismatch; throw
  /// `MalformedAssetFormatException` only when enough signature bytes match
  /// that malformed input for this format is a better diagnosis.
  Future<bool> detect(RandomAccessByteSource source);

  /// Extracts the embedded C2PA manifest store from [source].
  ///
  /// Throws `ManifestNotFoundException` when the asset is valid but has no
  /// embedded store, and `MalformedAssetFormatException` when container parsing
  /// fails. The returned [Uint8List] is exactly the serialized store bytes.
  Future<Uint8List> extractManifest(RandomAccessByteSource source);

  /// Writes [source] to [output] with [manifest] embedded as a new store.
  ///
  /// Implementations must preserve all unrelated asset bytes and throw
  /// `ManifestAlreadyExistsException` if embedding would create a duplicate
  /// store. [output] receives the complete rewritten asset.
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  );

  /// Writes [source] to [output] with the existing store replaced.
  ///
  /// Throws `ManifestNotFoundException` when no store exists. Implementations
  /// must not append a second store, and [output] receives the complete asset.
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  );

  /// Writes [source] to [output] with the existing manifest store removed.
  ///
  /// Throws `ManifestNotFoundException` when no store exists. Implementations
  /// must preserve unrelated bytes and write a complete asset to [output].
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  );
}

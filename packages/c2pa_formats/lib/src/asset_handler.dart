import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'asset_format.dart';

final class AssetHandlerCapabilities {
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

  final bool canDetect;
  final bool canExtractManifest;
  final bool canEmbedManifest;
  final bool canReplaceManifest;
  final bool canRemoveManifest;
  final bool canProvideDataHashLayout;
  final bool canProvideBoxHashLayout;
  final bool canReadXmp;
  final bool canEmbedRemoteReference;
  final bool canReadRemoteReference;
  final bool canRemoveRemoteReference;
  final bool canListTopLevelBoxes;
  final bool canProvideCollectionHashLayout;
  final bool canProvideBmffHashLayout;
  final List<String> mimeTypes;
  final List<String> fileExtensions;
}

final class AssetDetectionResult {
  const AssetDetectionResult({
    required this.format,
    required this.method,
    this.handler,
  });

  const AssetDetectionResult.unknown()
    : format = AssetFormat.unknown,
      method = AssetDetectionMethod.none,
      handler = null;

  final AssetFormat format;
  final AssetDetectionMethod method;
  final AssetHandler? handler;

  bool get isKnown => handler != null && format != AssetFormat.unknown;
}

abstract interface class AssetHandler {
  String get name;

  AssetFormat get format;

  AssetHandlerCapabilities get capabilities;

  Future<bool> detect(RandomAccessByteSource source);

  Future<Uint8List> extractManifest(RandomAccessByteSource source);

  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  );

  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  );

  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  );
}

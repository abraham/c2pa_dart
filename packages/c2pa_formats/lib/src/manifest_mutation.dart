import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';

import 'asset_handler.dart';

/// The change a handler applies to an asset's manifest store during a rewrite.
enum ManifestMutation {
  /// Add a manifest store to an asset that does not already have one.
  embed,

  /// Replace the manifest store of an asset that already has one.
  replace,

  /// Strip the manifest store from an asset that already has one.
  remove,
}

/// Implements [AssetHandler.embedManifest], [AssetHandler.replaceManifest],
/// and [AssetHandler.removeManifest] in terms of a single [rewriteManifest].
///
/// Every container format rewrites an asset the same way — copy the parts
/// before the manifest store, write the new one, then copy the rest — and the
/// three entry points differ only in which [ManifestMutation] they request.
/// Handlers therefore implement the rewrite once and mix in the dispatch.
mixin ManifestRewrite implements AssetHandler {
  /// Streams [source] to [output], applying [operation] to the manifest store.
  ///
  /// [manifest] carries the new manifest store for
  /// [ManifestMutation.embed] and [ManifestMutation.replace], and is `null`
  /// for [ManifestMutation.remove].
  Future<void> rewriteManifest(
    RandomAccessByteSource source,
    WritableByteSink output, {
    required ManifestMutation operation,
    Uint8List? manifest,
  });

  @override
  Future<void> embedManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => rewriteManifest(
    source,
    output,
    manifest: manifest,
    operation: ManifestMutation.embed,
  );

  @override
  Future<void> replaceManifest(
    RandomAccessByteSource source,
    Uint8List manifest,
    WritableByteSink output,
  ) => rewriteManifest(
    source,
    output,
    manifest: manifest,
    operation: ManifestMutation.replace,
  );

  @override
  Future<void> removeManifest(
    RandomAccessByteSource source,
    WritableByteSink output,
  ) => rewriteManifest(source, output, operation: ManifestMutation.remove);
}

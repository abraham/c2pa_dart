import 'package:c2pa_io/c2pa_io.dart';

/// A handler capability for reading and editing embedded XMP metadata.
abstract interface class XmpMetadataProvider {
  /// Reads the full XMP packet from [source], or `null` when absent.
  Future<String?> readXmp(RandomAccessByteSource source);

  /// Embeds a remote manifest [reference] in `dcterms:provenance`.
  Future<void> embedRemoteReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  );
}

/// A handler capability for editing C2PA remote manifest references in XMP.
abstract interface class RemoteManifestReferenceProvider {
  /// Reads the XMP `dcterms:provenance` value, or `null` when absent.
  Future<String?> readRemoteManifestReference(RandomAccessByteSource source);

  /// Adds or replaces the XMP `dcterms:provenance` [reference].
  Future<void> updateRemoteManifestReference(
    RandomAccessByteSource source,
    String reference,
    WritableByteSink output,
  );

  /// Removes the XMP `dcterms:provenance` value from [source].
  Future<void> removeRemoteManifestReference(
    RandomAccessByteSource source,
    WritableByteSink output,
  );
}

enum C2paManifestCompression { none, brotli, invalid }

/// Compression support exposed by this SDK build.
final class C2paCompressionCapabilities {
  const C2paCompressionCapabilities({
    required this.canReadBrotli,
    required this.canWriteBrotli,
    required this.maximumDecompressedBytes,
  });

  final bool canReadBrotli;
  final bool canWriteBrotli;
  final int maximumDecompressedBytes;
}

abstract final class C2paCapabilities {
  static const compressedManifests = C2paCompressionCapabilities(
    canReadBrotli: true,
    canWriteBrotli: false,
    maximumDecompressedBytes: 1024 * 1024 * 1024,
  );
}

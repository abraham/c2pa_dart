/// Compression state for a C2PA manifest store entry.
enum C2paManifestCompression {
  /// Manifest bytes are stored uncompressed.
  none,

  /// Manifest bytes use Brotli compression.
  brotli,

  /// Compression metadata is malformed or unsupported.
  invalid,
}

/// Compression support exposed by this SDK build.
final class C2paCompressionCapabilities {
  /// Creates a compression capability descriptor.
  const C2paCompressionCapabilities({
    required this.canReadBrotli,
    required this.canWriteBrotli,
    required this.maximumDecompressedBytes,
  });

  /// Whether Brotli-compressed manifests can be decoded.
  final bool canReadBrotli;

  /// Whether new manifests can be written with Brotli compression.
  final bool canWriteBrotli;

  /// Maximum decompressed manifest size in bytes.
  final int maximumDecompressedBytes;
}

/// Static feature capabilities for this SDK build.
abstract final class C2paCapabilities {
  /// Compression support available for C2PA manifest stores.
  static const compressedManifests = C2paCompressionCapabilities(
    canReadBrotli: true,
    canWriteBrotli: false,
    maximumDecompressedBytes: 1024 * 1024 * 1024,
  );
}

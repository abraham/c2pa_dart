/// Conservative limits used while reading and validating C2PA data.
final class C2paSettings {
  /// Default decompressed manifest limit: 32 MiB.
  static const int defaultMaxDecompressedManifestBytes = 32 * 1024 * 1024;

  /// Hard decompressed manifest limit: 1 GiB.
  static const int maximumDecompressedManifestBytes = 1024 * 1024 * 1024;

  /// Creates settings with conservative resource and network defaults.
  const C2paSettings({
    this.maxResourceBytes = 50 * 1024 * 1024,
    this.maxTotalResourceBytes = 200 * 1024 * 1024,
    this.maxResourceCount = 1024,
    this.allowNetworkAccess = false,
    this.maxNetworkBytes = 10 * 1024 * 1024,
    this.networkTimeout = const Duration(seconds: 10),
    this.maxRedirects = 3,
    this.enableOcspFetch = false,
    this.maxOcspRequestBytes = 16 * 1024,
    this.maxOcspResponseBytes = 1024 * 1024,
    this.ocspMaxAgeWithoutNextUpdate = const Duration(hours: 24),
    this.ocspClockSkew = const Duration(minutes: 5),
    this.maxRecursionDepth = 16,
    this.maxManifestBytes = 64 * 1024 * 1024,
    int maxDecompressedManifestBytes = defaultMaxDecompressedManifestBytes,
    this.maxJumbfBoxCount = 10000,
    this.maxIngredientDepth = 8,
    this.maxIngredientCount = 1024,
  }) : maxDecompressedManifestBytes =
           maxDecompressedManifestBytes > maximumDecompressedManifestBytes
           ? maximumDecompressedManifestBytes
           : maxDecompressedManifestBytes,
       assert(maxResourceBytes >= 0),
       assert(maxTotalResourceBytes >= maxResourceBytes),
       assert(maxResourceCount >= 0),
       assert(maxNetworkBytes >= 0),
       assert(maxRedirects >= 0),
       assert(maxOcspRequestBytes > 0),
       assert(maxOcspResponseBytes > 0),
       assert(maxRecursionDepth >= 0),
       assert(maxManifestBytes > 0),
       assert(
         maxDecompressedManifestBytes > 0 &&
             maxDecompressedManifestBytes <= maximumDecompressedManifestBytes,
       ),
       assert(maxJumbfBoxCount > 0),
       assert(maxIngredientDepth >= 0),
       assert(maxIngredientCount >= 0);

  /// Creates settings from JSON, using defaults for missing or mistyped values.
  factory C2paSettings.fromJson(Map<String, Object?> json) {
    int integer(String key, int fallback) => switch (json[key]) {
      final int value => value,
      _ => fallback,
    };

    bool boolean(String key, bool fallback) => switch (json[key]) {
      final bool value => value,
      _ => fallback,
    };

    return C2paSettings(
      maxResourceBytes: integer('maxResourceBytes', 50 * 1024 * 1024),
      maxTotalResourceBytes: integer(
        'maxTotalResourceBytes',
        200 * 1024 * 1024,
      ),
      maxResourceCount: integer('maxResourceCount', 1024),
      allowNetworkAccess: boolean('allowNetworkAccess', false),
      maxNetworkBytes: integer('maxNetworkBytes', 10 * 1024 * 1024),
      networkTimeout: Duration(
        milliseconds: integer('networkTimeoutMilliseconds', 10000),
      ),
      maxRedirects: integer('maxRedirects', 3),
      enableOcspFetch: boolean('enableOcspFetch', false),
      maxOcspRequestBytes: integer('maxOcspRequestBytes', 16 * 1024),
      maxOcspResponseBytes: integer('maxOcspResponseBytes', 1024 * 1024),
      ocspMaxAgeWithoutNextUpdate: Duration(
        milliseconds: integer(
          'ocspMaxAgeWithoutNextUpdateMilliseconds',
          const Duration(hours: 24).inMilliseconds,
        ),
      ),
      ocspClockSkew: Duration(
        milliseconds: integer(
          'ocspClockSkewMilliseconds',
          const Duration(minutes: 5).inMilliseconds,
        ),
      ),
      maxRecursionDepth: integer('maxRecursionDepth', 16),
      maxManifestBytes: integer('maxManifestBytes', 64 * 1024 * 1024),
      maxDecompressedManifestBytes: integer(
        'maxDecompressedManifestBytes',
        32 * 1024 * 1024,
      ),
      maxJumbfBoxCount: integer('maxJumbfBoxCount', 10000),
      maxIngredientDepth: integer('maxIngredientDepth', 8),
      maxIngredientCount: integer('maxIngredientCount', 1024),
    );
  }

  /// Maximum bytes allowed for one embedded resource; default 50 MiB.
  final int maxResourceBytes;

  /// Maximum combined embedded resource bytes; default 200 MiB.
  final int maxTotalResourceBytes;

  /// Maximum embedded resource count; default 1024.
  final int maxResourceCount;

  /// Whether remote manifest and OCSP network fetches are allowed.
  final bool allowNetworkAccess;

  /// Maximum bytes read from one network response; default 10 MiB.
  final int maxNetworkBytes;

  /// Overall timeout for network requests; default 10 seconds.
  final Duration networkTimeout;

  /// Maximum HTTP redirects followed for remote manifests; default 3.
  final int maxRedirects;

  /// Whether missing OCSP responses may be fetched over the network.
  final bool enableOcspFetch;

  /// Maximum OCSP request size in bytes; default 16 KiB.
  final int maxOcspRequestBytes;

  /// Maximum OCSP response size in bytes; default 1 MiB.
  final int maxOcspResponseBytes;

  /// Maximum OCSP age without `nextUpdate`; default 24 hours.
  final Duration ocspMaxAgeWithoutNextUpdate;

  /// Allowed OCSP clock skew; default 5 minutes.
  final Duration ocspClockSkew;

  /// Maximum nested JUMBF recursion depth; default 16.
  final int maxRecursionDepth;

  /// Maximum compressed or stored manifest bytes; default 64 MiB.
  final int maxManifestBytes;

  /// Maximum decompressed manifest bytes, capped at 1 GiB.
  final int maxDecompressedManifestBytes;

  /// Maximum JUMBF boxes parsed from one manifest; default 10000.
  final int maxJumbfBoxCount;

  /// Maximum ingredient traversal depth; default 8.
  final int maxIngredientDepth;

  /// Maximum ingredient count traversed; default 1024.
  final int maxIngredientCount;

  /// Creates a copy with the provided settings replaced.
  C2paSettings copyWith({
    int? maxResourceBytes,
    int? maxTotalResourceBytes,
    int? maxResourceCount,
    bool? allowNetworkAccess,
    int? maxNetworkBytes,
    Duration? networkTimeout,
    int? maxRedirects,
    bool? enableOcspFetch,
    int? maxOcspRequestBytes,
    int? maxOcspResponseBytes,
    Duration? ocspMaxAgeWithoutNextUpdate,
    Duration? ocspClockSkew,
    int? maxRecursionDepth,
    int? maxManifestBytes,
    int? maxDecompressedManifestBytes,
    int? maxJumbfBoxCount,
    int? maxIngredientDepth,
    int? maxIngredientCount,
  }) => C2paSettings(
    maxResourceBytes: maxResourceBytes ?? this.maxResourceBytes,
    maxTotalResourceBytes: maxTotalResourceBytes ?? this.maxTotalResourceBytes,
    maxResourceCount: maxResourceCount ?? this.maxResourceCount,
    allowNetworkAccess: allowNetworkAccess ?? this.allowNetworkAccess,
    maxNetworkBytes: maxNetworkBytes ?? this.maxNetworkBytes,
    networkTimeout: networkTimeout ?? this.networkTimeout,
    maxRedirects: maxRedirects ?? this.maxRedirects,
    enableOcspFetch: enableOcspFetch ?? this.enableOcspFetch,
    maxOcspRequestBytes: maxOcspRequestBytes ?? this.maxOcspRequestBytes,
    maxOcspResponseBytes: maxOcspResponseBytes ?? this.maxOcspResponseBytes,
    ocspMaxAgeWithoutNextUpdate:
        ocspMaxAgeWithoutNextUpdate ?? this.ocspMaxAgeWithoutNextUpdate,
    ocspClockSkew: ocspClockSkew ?? this.ocspClockSkew,
    maxRecursionDepth: maxRecursionDepth ?? this.maxRecursionDepth,
    maxManifestBytes: maxManifestBytes ?? this.maxManifestBytes,
    maxDecompressedManifestBytes:
        maxDecompressedManifestBytes ?? this.maxDecompressedManifestBytes,
    maxJumbfBoxCount: maxJumbfBoxCount ?? this.maxJumbfBoxCount,
    maxIngredientDepth: maxIngredientDepth ?? this.maxIngredientDepth,
    maxIngredientCount: maxIngredientCount ?? this.maxIngredientCount,
  );

  /// Encodes these settings as JSON-compatible values.
  Map<String, Object?> toJson() => {
    'maxResourceBytes': maxResourceBytes,
    'maxTotalResourceBytes': maxTotalResourceBytes,
    'maxResourceCount': maxResourceCount,
    'allowNetworkAccess': allowNetworkAccess,
    'maxNetworkBytes': maxNetworkBytes,
    'networkTimeoutMilliseconds': networkTimeout.inMilliseconds,
    'maxRedirects': maxRedirects,
    'enableOcspFetch': enableOcspFetch,
    'maxOcspRequestBytes': maxOcspRequestBytes,
    'maxOcspResponseBytes': maxOcspResponseBytes,
    'ocspMaxAgeWithoutNextUpdateMilliseconds':
        ocspMaxAgeWithoutNextUpdate.inMilliseconds,
    'ocspClockSkewMilliseconds': ocspClockSkew.inMilliseconds,
    'maxRecursionDepth': maxRecursionDepth,
    'maxManifestBytes': maxManifestBytes,
    'maxDecompressedManifestBytes': maxDecompressedManifestBytes,
    'maxJumbfBoxCount': maxJumbfBoxCount,
    'maxIngredientDepth': maxIngredientDepth,
    'maxIngredientCount': maxIngredientCount,
  };

  @override
  bool operator ==(Object other) =>
      other is C2paSettings &&
      maxResourceBytes == other.maxResourceBytes &&
      maxTotalResourceBytes == other.maxTotalResourceBytes &&
      maxResourceCount == other.maxResourceCount &&
      allowNetworkAccess == other.allowNetworkAccess &&
      maxNetworkBytes == other.maxNetworkBytes &&
      networkTimeout == other.networkTimeout &&
      maxRedirects == other.maxRedirects &&
      enableOcspFetch == other.enableOcspFetch &&
      maxOcspRequestBytes == other.maxOcspRequestBytes &&
      maxOcspResponseBytes == other.maxOcspResponseBytes &&
      ocspMaxAgeWithoutNextUpdate == other.ocspMaxAgeWithoutNextUpdate &&
      ocspClockSkew == other.ocspClockSkew &&
      maxRecursionDepth == other.maxRecursionDepth &&
      maxManifestBytes == other.maxManifestBytes &&
      maxDecompressedManifestBytes == other.maxDecompressedManifestBytes &&
      maxJumbfBoxCount == other.maxJumbfBoxCount &&
      maxIngredientDepth == other.maxIngredientDepth &&
      maxIngredientCount == other.maxIngredientCount;

  @override
  int get hashCode => Object.hash(
    maxResourceBytes,
    maxTotalResourceBytes,
    maxResourceCount,
    allowNetworkAccess,
    maxNetworkBytes,
    networkTimeout,
    maxRedirects,
    enableOcspFetch,
    maxOcspRequestBytes,
    maxOcspResponseBytes,
    ocspMaxAgeWithoutNextUpdate,
    ocspClockSkew,
    maxRecursionDepth,
    maxManifestBytes,
    maxDecompressedManifestBytes,
    maxJumbfBoxCount,
    maxIngredientDepth,
    maxIngredientCount,
  );
}

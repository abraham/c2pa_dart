/// Conservative limits used while reading and validating C2PA data.
final class C2paSettings {
  static const int defaultMaxDecompressedManifestBytes = 32 * 1024 * 1024;
  static const int maximumDecompressedManifestBytes = 1024 * 1024 * 1024;

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

  final int maxResourceBytes;
  final int maxTotalResourceBytes;
  final int maxResourceCount;
  final bool allowNetworkAccess;
  final int maxNetworkBytes;
  final Duration networkTimeout;
  final int maxRedirects;
  final bool enableOcspFetch;
  final int maxOcspRequestBytes;
  final int maxOcspResponseBytes;
  final Duration ocspMaxAgeWithoutNextUpdate;
  final Duration ocspClockSkew;
  final int maxRecursionDepth;
  final int maxManifestBytes;
  final int maxDecompressedManifestBytes;
  final int maxJumbfBoxCount;
  final int maxIngredientDepth;
  final int maxIngredientCount;

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

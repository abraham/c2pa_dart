import 'dart:async';
import 'dart:typed_data';

import 'exceptions.dart';
import 'http_remote_types.dart';
import 'settings.dart';

/// Legacy single-request resolver retained for source compatibility.
abstract interface class RemoteManifestResolver {
  /// Fetches the remote manifest bytes for [uri].
  ///
  /// Performs caller-defined network I/O. A `null` result means the manifest
  /// was not found; transport failures should throw an [Exception].
  Future<Uint8List?> resolve(Uri uri);
}

/// A transport request for a remote C2PA manifest.
///
/// The SDK validates URI policy before creating this request; transports still
/// report resolved addresses so redirects and DNS results can be checked.
final class C2paRemoteRequest {
  /// Creates an immutable remote manifest request.
  C2paRemoteRequest({
    required this.uri,
    required this.redirectCount,
    required this.maximumBytes,
    Iterable<String> acceptedContentTypes = const {},
  }) : acceptedContentTypes = Set<String>.unmodifiable(
         acceptedContentTypes.map((value) => value.toLowerCase()),
       );

  /// Absolute URI to fetch for the current request or redirect hop.
  /// URI being fetched when the transport failure occurred.
  /// URI rejected by policy validation.
  final Uri uri;

  /// Number of redirects already followed before this request.
  final int redirectCount;

  /// Maximum response body size in bytes allowed by policy.
  final int maximumBytes;

  /// Lower-case MIME types accepted for the manifest response.
  final Set<String> acceptedContentTypes;

  /// HTTP `Accept` header value suitable for this request.
  String get acceptHeader => acceptedContentTypes.isEmpty
      ? 'application/c2pa, application/octet-stream;q=0.9'
      : acceptedContentTypes.join(', ');
}

/// A transport response containing either manifest bytes or a redirect.
///
/// Exactly one of [bytes] and [redirectUri] should be non-null.
final class C2paRemoteResponse {
  /// Creates a successful byte response from a transport.
  ///
  /// [bytes] are copied defensively. [resolvedAddresses] must contain the IP
  /// literals contacted by transports that expose DNS metadata.
  C2paRemoteResponse.bytes({
    required List<int> bytes,
    Iterable<String> resolvedAddresses = const [],
    this.statusCode = 200,
    this.contentLength,
    this.contentType,
  }) : bytes = Uint8List.fromList(bytes).asUnmodifiableView(),
       redirectUri = null,
       resolvedAddresses = List<String>.unmodifiable(resolvedAddresses);

  /// Creates an HTTP redirect response from a transport.
  ///
  /// [redirectUri] may be relative; policy is revalidated after resolution.
  C2paRemoteResponse.redirect({
    required this.redirectUri,
    Iterable<String> resolvedAddresses = const [],
    this.statusCode = 302,
    this.contentType,
  }) : bytes = null,
       contentLength = null,
       resolvedAddresses = List<String>.unmodifiable(resolvedAddresses);

  /// Manifest bytes, or `null` when this response is a redirect.
  final Uint8List? bytes;

  /// Redirect target, or `null` when this response carries bytes.
  final Uri? redirectUri;

  /// HTTP-like status code used to validate success or redirect semantics.
  final int statusCode;

  /// Declared body length in bytes, or `null` when unknown.
  final int? contentLength;

  /// Response MIME type, or `null` when the transport did not provide one.
  final String? contentType;

  /// IP literals reached while resolving or fetching this response.
  final List<String> resolvedAddresses;
}

/// Caller-injected transport for remote manifests.
abstract interface class C2paRemoteResolver {
  /// Performs network I/O for [request] and returns bytes or a redirect.
  ///
  /// Throw an [Exception] for transport failures; the SDK wraps it as a
  /// [C2paRemoteTransportException] unless it is already a C2PA network error.
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request);
}

/// Resolver alias for DID-style remote identity documents.
typedef DidResolver = C2paRemoteResolver;

/// Transport-level failure categories for remote manifest fetches.
enum C2paRemoteTransportFailure {
  /// The resolver threw an unexpected transport exception.
  transport,

  /// The resolver reported that no manifest bytes were available.
  notFound,

  /// The resolver returned a structurally inconsistent response.
  invalidResponse,

  /// The response status was not valid for bytes or redirect handling.
  httpStatus,

  /// Redirect processing revisited a previously seen URI.
  redirectLoop,

  /// The response body length did not match the declared length.
  truncated,

  /// The caller's cancellation callback requested termination.
  cancelled,

  /// The resolver did not complete before the configured timeout.
  timeout,
}

/// Exception thrown when a remote manifest transport fails.
final class C2paRemoteTransportException extends C2paNetworkException {
  /// Creates a categorized transport exception for [uri].
  const C2paRemoteTransportException(
    super.message, {
    required this.failure,
    required this.uri,
    super.cause,
    super.stackTrace,
  });

  /// Machine-readable reason for the transport failure.
  final C2paRemoteTransportFailure failure;

  /// URI being fetched when the transport failure occurred.
  final Uri uri;
}

/// Policy violations that can reject a remote manifest URI or response.
enum RemoteManifestPolicyViolation {
  /// Remote manifest access is disabled.
  disabled,

  /// The URI is not absolute, lacks a host, or contains user info.
  invalidUri,

  /// The URI scheme is not in the allowed [RemoteManifestPolicy] schemes.
  schemeNotAllowed,

  /// The URI host is not allowed by the policy.
  hostNotAllowed,

  /// The URI port is neither default nor explicitly allowed.
  portNotAllowed,

  /// The URI host is local, private, link-local, or otherwise blocked.
  localAddress,

  /// A resolved IP literal is missing or not allowed by the policy.
  resolvedAddressNotAllowed,

  /// The redirect count exceeded the [RemoteManifestPolicy] maximum.
  tooManyRedirects,

  /// The body or declared length exceeded the [RemoteManifestPolicy] maximum.
  responseTooLarge,
}

/// Exception thrown when remote manifest policy rejects a URI or response.
final class C2paUriPolicyException extends C2paNetworkException {
  /// Creates a policy exception for [uri].
  const C2paUriPolicyException(
    super.message, {
    required this.violation,
    required this.uri,
    super.cause,
    super.stackTrace,
  });

  /// Machine-readable policy rule that was violated.
  final RemoteManifestPolicyViolation violation;

  /// URI rejected by policy validation.
  final Uri uri;
}

/// Validation-only policy for future remote manifest fetching.
///
/// The default policy denies every URI. It performs no DNS or network access.
final class RemoteManifestPolicy {
  /// Creates a validation-only remote manifest policy.
  ///
  /// Throws [ArgumentError] if [maxRedirects] or [maxBytes] is negative.
  RemoteManifestPolicy({
    this.enabled = false,
    Iterable<String> allowedSchemes = const {'https'},
    Iterable<String> allowedHosts = const {},
    Iterable<int> allowedPorts = const {},
    this.allowSubdomains = false,
    this.allowSameOrigin = false,
    this.allowPrivateAddresses = false,
    this.maxRedirects = 0,
    this.maxBytes = 0,
  }) : allowedSchemes = Set<String>.unmodifiable(
         allowedSchemes.map((value) => value.toLowerCase()),
       ),
       allowedHosts = Set<String>.unmodifiable(
         allowedHosts.map(_normalizeHost),
       ),
       allowedPorts = Set<int>.unmodifiable(allowedPorts) {
    if (maxRedirects < 0) {
      throw ArgumentError.value(maxRedirects, 'maxRedirects');
    }
    if (maxBytes < 0) {
      throw ArgumentError.value(maxBytes, 'maxBytes');
    }
  }

  /// Creates a policy from SDK [settings] and explicit allow lists.
  factory RemoteManifestPolicy.fromSettings(
    C2paSettings settings, {
    Iterable<String> allowedSchemes = const {'https'},
    Iterable<String> allowedHosts = const {},
    bool allowSubdomains = false,
    Iterable<int> allowedPorts = const {},
  }) => RemoteManifestPolicy(
    enabled: settings.allowNetworkAccess,
    allowedSchemes: allowedSchemes,
    allowedHosts: allowedHosts,
    allowedPorts: allowedPorts,
    allowSubdomains: allowSubdomains,
    maxRedirects: settings.maxRedirects,
    maxBytes: settings.maxNetworkBytes,
  );

  /// Opt-in browser policy: the current HTTP(S) origin plus allowed hosts.
  factory RemoteManifestPolicy.browser({
    Iterable<String> allowedHosts = const {},
    bool allowSubdomains = false,
    Iterable<int> allowedPorts = const {},
    int maxRedirects = 0,
    int maxBytes = 0,
  }) => RemoteManifestPolicy(
    enabled: true,
    allowedSchemes: {
      if (Uri.base.scheme == 'http' || Uri.base.scheme == 'https')
        Uri.base.scheme
      else
        'https',
    },
    allowedHosts: allowedHosts,
    allowedPorts: allowedPorts,
    allowSubdomains: allowSubdomains,
    allowSameOrigin: true,
    maxRedirects: maxRedirects,
    maxBytes: maxBytes,
  );

  /// Whether remote manifest access is permitted at all.
  final bool enabled;

  /// Lower-case URI schemes accepted by the policy.
  final Set<String> allowedSchemes;

  /// Normalized host names accepted by the policy.
  final Set<String> allowedHosts;

  /// Non-default TCP ports accepted by the policy.
  final Set<int> allowedPorts;

  /// Whether subdomains of [allowedHosts] are accepted.
  final bool allowSubdomains;

  /// Whether the current `Uri.base` origin is accepted.
  final bool allowSameOrigin;

  /// Explicit opt-in for private networks. Public network policies should
  /// leave this false.
  final bool allowPrivateAddresses;

  /// Maximum number of redirects that may be followed.
  final int maxRedirects;

  /// Maximum allowed remote manifest size in bytes.
  final int maxBytes;

  /// Checks whether [uri] and optional response metadata satisfy the policy.
  ///
  /// This method performs no network I/O and returns `false` instead of
  /// throwing [C2paUriPolicyException].
  bool allows(Uri uri, {int redirectCount = 0, int? byteCount}) {
    try {
      validate(uri, redirectCount: redirectCount, byteCount: byteCount);
      return true;
    } on C2paUriPolicyException {
      return false;
    }
  }

  /// Validates [uri], redirect count, byte count, and resolved addresses.
  ///
  /// This method performs no network I/O. Throws [C2paUriPolicyException] when
  /// any policy rule is violated.
  void validate(
    Uri uri, {
    int redirectCount = 0,
    int? byteCount,
    Iterable<String> resolvedAddresses = const [],
  }) {
    if (!enabled) {
      throw C2paUriPolicyException(
        'Remote manifest access is disabled',
        violation: RemoteManifestPolicyViolation.disabled,
        uri: uri,
      );
    }
    if (!uri.isAbsolute || uri.host.isEmpty || uri.userInfo.isNotEmpty) {
      throw C2paUriPolicyException(
        'Remote manifest URI must be absolute and must not contain user info',
        violation: RemoteManifestPolicyViolation.invalidUri,
        uri: uri,
      );
    }

    final scheme = uri.scheme.toLowerCase();
    if (!allowedSchemes.contains(scheme)) {
      throw C2paUriPolicyException(
        'URI scheme "$scheme" is not allowed',
        violation: RemoteManifestPolicyViolation.schemeNotAllowed,
        uri: uri,
      );
    }

    final host = _normalizeHost(uri.host);
    if (!allowPrivateAddresses &&
        (_isLocalHost(host) || _isBlockedIpLiteral(host))) {
      throw C2paUriPolicyException(
        'Local, private, and link-local addresses are not allowed',
        violation: RemoteManifestPolicyViolation.localAddress,
        uri: uri,
      );
    }
    if (!_hostIsAllowed(host)) {
      throw C2paUriPolicyException(
        'URI host "$host" is not allowed',
        violation: RemoteManifestPolicyViolation.hostNotAllowed,
        uri: uri,
      );
    }
    if (uri.hasPort &&
        uri.port != _defaultPort(scheme) &&
        !_isSameOrigin(uri) &&
        !allowedPorts.contains(uri.port)) {
      throw C2paUriPolicyException(
        'URI port ${uri.port} is not allowed',
        violation: RemoteManifestPolicyViolation.portNotAllowed,
        uri: uri,
      );
    }
    for (final address in resolvedAddresses) {
      final normalizedAddress = _normalizeHost(address);
      if (!_isIpLiteral(normalizedAddress) ||
          (!allowPrivateAddresses && _isBlockedIpLiteral(normalizedAddress))) {
        throw C2paUriPolicyException(
          'Resolved address "$address" is not allowed',
          violation: RemoteManifestPolicyViolation.resolvedAddressNotAllowed,
          uri: uri,
        );
      }
    }
    if (redirectCount < 0 || redirectCount > maxRedirects) {
      throw C2paUriPolicyException(
        'Redirect limit of $maxRedirects exceeded',
        violation: RemoteManifestPolicyViolation.tooManyRedirects,
        uri: uri,
      );
    }

    if (byteCount != null && (byteCount < 0 || byteCount > maxBytes)) {
      throw C2paUriPolicyException(
        'Remote manifest exceeds the $maxBytes byte limit',
        violation: RemoteManifestPolicyViolation.responseTooLarge,
        uri: uri,
      );
    }
  }

  static int? _defaultPort(String scheme) => switch (scheme) {
    'https' => 443,
    'http' => 80,
    _ => null,
  };

  bool _hostIsAllowed(String host) {
    if (allowedHosts.contains(host)) return true;
    if (allowSameOrigin) {
      final base = Uri.base;
      if (base.host.isNotEmpty &&
          _normalizeHost(base.host) == host &&
          allowedSchemes.contains(base.scheme.toLowerCase())) {
        return true;
      }
    }
    return allowSubdomains &&
        allowedHosts.any((allowed) => host.endsWith('.$allowed'));
  }

  bool _isSameOrigin(Uri uri) {
    if (!allowSameOrigin) return false;
    final base = Uri.base;
    if (base.host.isEmpty) return false;
    final uriPort = uri.hasPort ? uri.port : _defaultPort(uri.scheme);
    final basePort = base.hasPort ? base.port : _defaultPort(base.scheme);
    return uri.scheme.toLowerCase() == base.scheme.toLowerCase() &&
        _normalizeHost(uri.host) == _normalizeHost(base.host) &&
        uriPort == basePort;
  }

  static String _normalizeHost(String host) {
    var normalized = host.trim().toLowerCase();
    if (normalized.startsWith('[') && normalized.endsWith(']')) {
      normalized = normalized.substring(1, normalized.length - 1);
    }
    while (normalized.endsWith('.')) {
      normalized = normalized.substring(0, normalized.length - 1);
    }
    return normalized;
  }

  static bool _isLocalHost(String host) =>
      host == 'localhost' || host.endsWith('.localhost');

  static bool _isBlockedIpLiteral(String host) {
    final ipv4 = _parseIpv4(host);
    if (ipv4 != null) return _isBlockedIpv4(ipv4);
    if (!host.contains(':')) return false;
    final words = _parseIpv6(host);
    if (words == null) return true;
    final allZero = words.every((word) => word == 0);
    final loopback =
        words.take(7).every((word) => word == 0) && words.last == 1;
    if (allZero || loopback) return true;
    final first = words.first;
    if ((first & 0xfe00) == 0xfc00 ||
        (first & 0xffc0) == 0xfe80 ||
        (first & 0xffc0) == 0xfec0 ||
        (first & 0xff00) == 0xff00) {
      return true;
    }
    if ((first == 0x2001 &&
            (words[1] == 0x0db8 ||
                words[1] == 0x0002 ||
                (words[1] & 0xfff0) == 0x0010 ||
                (words[1] & 0xfff0) == 0x0020)) ||
        (first == 0x0100 && words[1] == 0 && words[2] == 0 && words[3] == 0)) {
      return true;
    }
    final ipv4Mapped =
        words.take(5).every((word) => word == 0) &&
        (words[5] == 0 || words[5] == 0xffff);
    if (ipv4Mapped) {
      return _isBlockedIpv4([
        words[6] >> 8,
        words[6] & 0xff,
        words[7] >> 8,
        words[7] & 0xff,
      ]);
    }
    return false;
  }

  static bool _isIpLiteral(String host) =>
      _parseIpv4(host) != null || host.contains(':');

  static List<int>? _parseIpv4(String host) {
    final parts = host.split('.');
    if (parts.length != 4) return null;
    final values = <int>[];
    for (final part in parts) {
      if (part.isEmpty || (part.length > 1 && part.startsWith('0'))) {
        return null;
      }
      final value = int.tryParse(part);
      if (value == null || value < 0 || value > 255) return null;
      values.add(value);
    }
    return values;
  }

  static List<int>? _parseIpv6(String host) {
    var normalized = host.toLowerCase();
    if (normalized.contains('%') ||
        normalized.indexOf('::') != normalized.lastIndexOf('::')) {
      return null;
    }
    final ipv4Tail = normalized.split(':').last;
    final ipv4 = _parseIpv4(ipv4Tail);
    if (ipv4 != null) {
      normalized =
          '${normalized.substring(0, normalized.length - ipv4Tail.length)}'
          '${((ipv4[0] << 8) | ipv4[1]).toRadixString(16)}:'
          '${((ipv4[2] << 8) | ipv4[3]).toRadixString(16)}';
    }
    final halves = normalized.split('::');
    List<int>? parseWords(String value) {
      if (value.isEmpty) return <int>[];
      final words = <int>[];
      for (final part in value.split(':')) {
        if (part.isEmpty || part.length > 4) return null;
        final word = int.tryParse(part, radix: 16);
        if (word == null || word > 0xffff) return null;
        words.add(word);
      }
      return words;
    }

    final left = parseWords(halves.first);
    final right = halves.length == 2 ? parseWords(halves.last) : <int>[];
    if (left == null || right == null) return null;
    if (halves.length == 1) return left.length == 8 ? left : null;
    final omitted = 8 - left.length - right.length;
    if (omitted < 1) return null;
    return [...left, ...List<int>.filled(omitted, 0), ...right];
  }

  static bool _isBlockedIpv4(List<int> value) {
    final first = value[0];
    final second = value[1];
    return first == 0 ||
        first == 10 ||
        first == 127 ||
        (first == 100 && second >= 64 && second <= 127) ||
        (first == 169 && second == 254) ||
        (first == 172 && second >= 16 && second <= 31) ||
        (first == 192 && second == 0) ||
        (first == 192 && second == 2) ||
        (first == 192 && second == 168) ||
        (first == 192 && second == 88) ||
        (first == 198 && (second == 18 || second == 19)) ||
        (first == 198 && second == 51) ||
        (first == 203 && second == 0 && value[2] == 113) ||
        first >= 224;
  }

  @override
  bool operator ==(Object other) =>
      other is RemoteManifestPolicy &&
      enabled == other.enabled &&
      _setsEqual(allowedSchemes, other.allowedSchemes) &&
      _setsEqual(allowedHosts, other.allowedHosts) &&
      _setsEqual(allowedPorts, other.allowedPorts) &&
      allowSubdomains == other.allowSubdomains &&
      allowSameOrigin == other.allowSameOrigin &&
      allowPrivateAddresses == other.allowPrivateAddresses &&
      maxRedirects == other.maxRedirects &&
      maxBytes == other.maxBytes;

  @override
  int get hashCode => Object.hash(
    enabled,
    Object.hashAll(allowedSchemes.toList()..sort()),
    Object.hashAll(allowedHosts.toList()..sort()),
    Object.hashAll(allowedPorts.toList()..sort()),
    allowSubdomains,
    allowSameOrigin,
    allowPrivateAddresses,
    maxRedirects,
    maxBytes,
  );
}

/// Resolves and validates remote C2PA manifest bytes.
///
/// Performs network I/O through [resolver] or [legacyResolver], follows policy-
/// checked redirects, enforces byte limits, and times each request with
/// [timeout]. Throws [C2paUriPolicyException] for policy failures and
/// [C2paRemoteTransportException] for transport, timeout, cancellation, HTTP,
/// redirect, and truncation failures.
Future<Uint8List> resolveRemoteManifest({
  required Uri uri,
  required RemoteManifestPolicy policy,
  required Duration timeout,
  C2paRemoteResolver? resolver,
  RemoteManifestResolver? legacyResolver,
  FutureOr<bool> Function()? isCancelled,
  Set<String> acceptedContentTypes = const {},
}) async {
  policy.validate(uri);
  if (resolver == null && legacyResolver == null) {
    throw C2paRemoteTransportException(
      'No remote manifest resolver is configured',
      failure: C2paRemoteTransportFailure.transport,
      uri: uri,
    );
  }

  var current = uri;
  var redirectCount = 0;
  final visited = <String>{};
  while (true) {
    if (await isCancelled?.call() ?? false) {
      throw C2paRemoteTransportException(
        'Remote manifest resolution was cancelled',
        failure: C2paRemoteTransportFailure.cancelled,
        uri: current,
      );
    }
    policy.validate(current, redirectCount: redirectCount);
    final key = current.normalizePath().toString();
    if (!visited.add(key)) {
      throw C2paRemoteTransportException(
        'Remote manifest redirect loop detected',
        failure: C2paRemoteTransportFailure.redirectLoop,
        uri: current,
      );
    }

    if (resolver == null) {
      try {
        final bytes = await legacyResolver!.resolve(current).timeout(timeout);
        if (bytes == null) {
          throw C2paRemoteTransportException(
            'Remote manifest was not found',
            failure: C2paRemoteTransportFailure.notFound,
            uri: current,
          );
        }
        policy.validate(current, byteCount: bytes.length);
        return Uint8List.fromList(bytes);
      } on TimeoutException catch (error, stackTrace) {
        throw C2paRemoteTransportException(
          'Remote manifest request timed out',
          failure: C2paRemoteTransportFailure.timeout,
          uri: current,
          cause: error,
          stackTrace: stackTrace,
        );
      }
    }

    late C2paRemoteResponse response;
    try {
      response = await resolver
          .resolve(
            C2paRemoteRequest(
              uri: current,
              redirectCount: redirectCount,
              maximumBytes: policy.maxBytes,
              acceptedContentTypes: acceptedContentTypes,
            ),
          )
          .timeout(timeout);
    } on TimeoutException catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'Remote manifest request timed out',
        failure: C2paRemoteTransportFailure.timeout,
        uri: current,
        cause: error,
        stackTrace: stackTrace,
      );
    } on C2paNetworkException {
      rethrow;
    } on Exception catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'Remote manifest transport failed: $error',
        failure: C2paRemoteTransportFailure.transport,
        uri: current,
        cause: error,
        stackTrace: stackTrace,
      );
    }
    policy.validate(
      current,
      redirectCount: redirectCount,
      resolvedAddresses: response.resolvedAddresses,
    );
    final capabilities = resolver is C2paResolverCapabilities
        ? (resolver as C2paResolverCapabilities).capabilities
        : null;
    final exposesResolvedAddresses =
        capabilities?.resolvedAddressMetadata ?? true;
    if (exposesResolvedAddresses &&
        !_looksLikeIpLiteral(current.host) &&
        response.resolvedAddresses.isEmpty) {
      throw C2paRemoteTransportException(
        'Remote manifest response omitted resolved-address metadata',
        failure: C2paRemoteTransportFailure.invalidResponse,
        uri: current,
      );
    }

    final redirect = response.redirectUri;
    if (redirect != null) {
      if (response.statusCode < 300 || response.statusCode > 399) {
        throw C2paRemoteTransportException(
          'Redirect response used HTTP status ${response.statusCode}',
          failure: C2paRemoteTransportFailure.httpStatus,
          uri: current,
        );
      }
      if (response.bytes != null) {
        throw C2paRemoteTransportException(
          'Redirect response must not contain manifest bytes',
          failure: C2paRemoteTransportFailure.invalidResponse,
          uri: current,
        );
      }
      redirectCount++;
      current = current.resolveUri(redirect);
      continue;
    }

    final bytes = response.bytes;
    if (response.statusCode < 200 || response.statusCode > 299) {
      throw C2paRemoteTransportException(
        'Remote manifest request returned HTTP status ${response.statusCode}',
        failure: C2paRemoteTransportFailure.httpStatus,
        uri: current,
      );
    }
    if (bytes == null) {
      throw C2paRemoteTransportException(
        'Remote manifest response contained no bytes',
        failure: C2paRemoteTransportFailure.notFound,
        uri: current,
      );
    }
    policy.validate(current, byteCount: bytes.length);
    final declaredLength = response.contentLength;
    if (declaredLength != null) {
      policy.validate(current, byteCount: declaredLength);
    }
    if (declaredLength != null && declaredLength != bytes.length) {
      throw C2paRemoteTransportException(
        'Remote manifest response was truncated',
        failure: C2paRemoteTransportFailure.truncated,
        uri: current,
      );
    }
    return Uint8List.fromList(bytes);
  }
}

bool _setsEqual<T>(Set<T> left, Set<T> right) =>
    left.length == right.length && left.containsAll(right);

bool _looksLikeIpLiteral(String host) =>
    host.contains(':') ||
    (host.split('.').length == 4 &&
        host.split('.').every((part) => int.tryParse(part) != null));

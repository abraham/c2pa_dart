import 'dart:async';

import 'remote_manifest.dart';

/// Timeout configuration for HTTP remote manifest resolution.
final class C2paHttpTimeouts {
  /// Creates HTTP timeouts with positive default durations.
  const C2paHttpTimeouts({
    this.connect = const Duration(seconds: 10),
    this.read = const Duration(seconds: 30),
    this.overall = const Duration(seconds: 60),
  });

  /// Timeout for DNS resolution and connection establishment.
  final Duration connect;

  /// Timeout for each HTTP response read operation.
  final Duration read;

  /// Overall timeout for one HTTP resolution attempt.
  final Duration overall;

  /// Throws [ArgumentError] if any timeout is not positive.
  void validate() {
    if (connect <= Duration.zero ||
        read <= Duration.zero ||
        overall <= Duration.zero) {
      throw ArgumentError('HTTP timeouts must be positive');
    }
  }
}

/// Security capabilities exposed by an HTTP resolver implementation.
final class C2paHttpResolverCapabilities {
  /// Creates a capability descriptor for an HTTP resolver.
  const C2paHttpResolverCapabilities({
    required this.resolvedAddressMetadata,
    required this.pinsValidatedAddress,
    required this.validatesRedirectBeforeConnect,
  });

  /// Whether responses include resolved IP address metadata.
  final bool resolvedAddressMetadata;

  /// Whether connections are pinned to policy-validated IP addresses.
  final bool pinsValidatedAddress;

  /// Whether redirects are policy-checked before connecting.
  final bool validatesRedirectBeforeConnect;
}

/// Interface for resolvers that report runtime capabilities.
abstract interface class C2paResolverCapabilities {
  /// Capabilities guaranteed by this resolver.
  C2paHttpResolverCapabilities get capabilities;
}

/// HTTP implementation of [C2paRemoteResolver].
abstract interface class C2paHttpRemoteResolver
    implements C2paRemoteResolver, C2paResolverCapabilities {}

/// Callback polled to cancel in-flight HTTP work.
typedef C2paHttpCancellationCallback = FutureOr<bool> Function();

/// Resolver that maps a host name to IP address strings.
typedef C2paHostResolver = Future<List<String>> Function(String host);

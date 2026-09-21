import 'dart:async';

import 'remote_manifest.dart';

final class C2paHttpTimeouts {
  const C2paHttpTimeouts({
    this.connect = const Duration(seconds: 10),
    this.read = const Duration(seconds: 30),
    this.overall = const Duration(seconds: 60),
  });

  final Duration connect;
  final Duration read;
  final Duration overall;

  void validate() {
    if (connect <= Duration.zero ||
        read <= Duration.zero ||
        overall <= Duration.zero) {
      throw ArgumentError('HTTP timeouts must be positive');
    }
  }
}

final class C2paHttpResolverCapabilities {
  const C2paHttpResolverCapabilities({
    required this.resolvedAddressMetadata,
    required this.pinsValidatedAddress,
    required this.validatesRedirectBeforeConnect,
  });

  final bool resolvedAddressMetadata;
  final bool pinsValidatedAddress;
  final bool validatesRedirectBeforeConnect;
}

abstract interface class C2paResolverCapabilities {
  C2paHttpResolverCapabilities get capabilities;
}

abstract interface class C2paHttpRemoteResolver
    implements C2paRemoteResolver, C2paResolverCapabilities {}

typedef C2paHttpCancellationCallback = FutureOr<bool> Function();
typedef C2paHostResolver = Future<List<String>> Function(String host);

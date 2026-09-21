import 'http_remote_resolver_stub.dart'
    if (dart.library.io) 'http_remote_resolver_io.dart'
    if (dart.library.html) 'http_remote_resolver_web.dart'
    as platform;
import 'http_remote_types.dart';
import 'remote_manifest.dart';

export 'http_remote_types.dart';

/// Creates an opt-in HTTP resolver for the current platform.
///
/// No resolver is installed by default. Callers must also install this
/// resolver and the same policy on [C2paContext].
C2paHttpRemoteResolver createC2paHttpRemoteResolver({
  required RemoteManifestPolicy policy,
  C2paHttpTimeouts timeouts = const C2paHttpTimeouts(),
  C2paHttpCancellationCallback? isCancelled,
  C2paHostResolver? hostResolver,
}) => platform.createC2paHttpRemoteResolver(
  policy: policy,
  timeouts: timeouts,
  isCancelled: isCancelled,
  hostResolver: hostResolver,
);

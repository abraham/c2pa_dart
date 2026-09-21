import 'http_remote_types.dart';
import 'remote_manifest.dart';

/// Creates the unsupported-platform HTTP remote resolver stub.
///
/// Throws [UnsupportedError] because this conditional import target has no
/// network implementation.
C2paHttpRemoteResolver createC2paHttpRemoteResolver({
  required RemoteManifestPolicy policy,
  required C2paHttpTimeouts timeouts,
  C2paHttpCancellationCallback? isCancelled,
  C2paHostResolver? hostResolver,
}) {
  throw UnsupportedError(
    'The C2PA HTTP resolver is unavailable on this platform',
  );
}

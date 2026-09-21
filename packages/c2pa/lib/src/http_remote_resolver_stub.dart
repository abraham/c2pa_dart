import 'http_remote_types.dart';
import 'remote_manifest.dart';

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

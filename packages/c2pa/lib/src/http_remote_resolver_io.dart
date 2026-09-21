import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'exceptions.dart';
import 'http_remote_types.dart';
import 'remote_manifest.dart';

/// Creates the VM and Flutter IO HTTP remote manifest resolver.
///
/// The resolver performs network I/O and enforces [policy] and [timeouts].
C2paHttpRemoteResolver createC2paHttpRemoteResolver({
  required RemoteManifestPolicy policy,
  required C2paHttpTimeouts timeouts,
  C2paHttpCancellationCallback? isCancelled,
  C2paHostResolver? hostResolver,
}) => _VmHttpRemoteResolver(
  policy: policy,
  timeouts: timeouts,
  isCancelled: isCancelled,
  hostResolver: hostResolver,
);

final class _VmHttpRemoteResolver implements C2paHttpRemoteResolver {
  _VmHttpRemoteResolver({
    required this.policy,
    required this.timeouts,
    required this.isCancelled,
    required this.hostResolver,
  }) {
    timeouts.validate();
  }

  final RemoteManifestPolicy policy;
  final C2paHttpTimeouts timeouts;
  final C2paHttpCancellationCallback? isCancelled;
  final C2paHostResolver? hostResolver;

  @override
  C2paHttpResolverCapabilities get capabilities =>
      const C2paHttpResolverCapabilities(
        resolvedAddressMetadata: true,
        pinsValidatedAddress: true,
        validatesRedirectBeforeConnect: true,
      );

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    try {
      return await _resolve(request).timeout(timeouts.overall);
    } on C2paNetworkException {
      rethrow;
    } on TimeoutException catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'HTTP request exceeded its overall timeout',
        failure: C2paRemoteTransportFailure.timeout,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    } on Object catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'HTTP transport failed: $error',
        failure: C2paRemoteTransportFailure.transport,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  Future<C2paRemoteResponse> _resolve(C2paRemoteRequest request) async {
    await _checkCancelled(request.uri);
    policy.validate(request.uri, redirectCount: request.redirectCount);
    final addresses = hostResolver == null
        ? await InternetAddress.lookup(request.uri.host)
              .timeout(timeouts.connect)
        : (await hostResolver!(request.uri.host).timeout(timeouts.connect))
              .map(InternetAddress.tryParse)
              .whereType<InternetAddress>()
              .toList(growable: false);
    final addressStrings = addresses
        .map((address) => address.address)
        .toList(growable: false);
    policy.validate(
      request.uri,
      redirectCount: request.redirectCount,
      resolvedAddresses: addressStrings,
    );
    if (addresses.isEmpty) {
      throw C2paRemoteTransportException(
        'DNS returned no addresses',
        failure: C2paRemoteTransportFailure.transport,
        uri: request.uri,
      );
    }
    final selected = addresses.first;
    final client = HttpClient()
      ..autoUncompress = false
      ..connectionTimeout = timeouts.connect
      ..findProxy = (_) => 'DIRECT';
    client.connectionFactory = (uri, proxyHost, proxyPort) async {
      if (proxyHost != null) {
        throw C2paRemoteTransportException(
          'Proxy connections are not permitted',
          failure: C2paRemoteTransportFailure.transport,
          uri: request.uri,
        );
      }
      final port = uri.hasPort
          ? uri.port
          : uri.scheme == 'https'
          ? 443
          : 80;
      if (uri.scheme == 'https') {
        final connection = await Socket.startConnect(selected, port);
        return ConnectionTask.fromSocket(
          connection.socket.then(
            (Socket socket) => SecureSocket.secure(socket, host: uri.host),
          ),
          connection.cancel,
        );
      }
      return Socket.startConnect(selected, port);
    };
    // The request is closed below; it is nullable only so timeout/cancel hooks
    // can abort it while connection setup is in progress.
    // ignore: close_sinks
    HttpClientRequest? outgoing;
    Timer? cancellationTimer;
    Timer? overallTimer;
    var cancellationCheckRunning = false;
    var cancellationRequested = false;
    var overallExpired = false;
    try {
      overallTimer = Timer(timeouts.overall, () {
        overallExpired = true;
        outgoing?.abort();
        client.close(force: true);
      });
      outgoing = await client.getUrl(request.uri).timeout(timeouts.connect);
      final activeRequest = outgoing;
      if (isCancelled != null) {
        cancellationTimer = Timer.periodic(const Duration(milliseconds: 10), (
          _,
        ) async {
          if (cancellationCheckRunning || cancellationRequested) return;
          cancellationCheckRunning = true;
          try {
            if (await isCancelled!.call()) {
              cancellationRequested = true;
              outgoing?.abort();
              client.close(force: true);
            }
          } finally {
            cancellationCheckRunning = false;
          }
        });
      }
      activeRequest
        ..followRedirects = false
        ..persistentConnection = false;
      activeRequest.headers
        ..set(HttpHeaders.acceptHeader, request.acceptHeader)
        ..removeAll(HttpHeaders.cookieHeader)
        ..removeAll(HttpHeaders.authorizationHeader)
        ..removeAll(HttpHeaders.proxyAuthorizationHeader);
      final incoming = await activeRequest.close().timeout(timeouts.read);
      await _checkCancelled(request.uri);
      final contentType = incoming.headers.contentType?.mimeType.toLowerCase();
      if (incoming.statusCode >= 200 &&
          incoming.statusCode <= 299 &&
          request.acceptedContentTypes.isNotEmpty &&
          (contentType == null ||
              !request.acceptedContentTypes
                  .map((value) => value.toLowerCase())
                  .contains(contentType))) {
        throw C2paRemoteTransportException(
          'HTTP response has an unsupported content type',
          failure: C2paRemoteTransportFailure.invalidResponse,
          uri: request.uri,
        );
      }
      final contentLength = incoming.contentLength < 0
          ? null
          : incoming.contentLength;
      if (contentLength != null && contentLength > request.maximumBytes) {
        throw C2paUriPolicyException(
          'HTTP content length exceeds the configured byte limit',
          violation: RemoteManifestPolicyViolation.responseTooLarge,
          uri: request.uri,
        );
      }
      final location = incoming.headers.value(HttpHeaders.locationHeader);
      if (incoming.isRedirect && location != null) {
        return C2paRemoteResponse.redirect(
          redirectUri: Uri.parse(location),
          resolvedAddresses: addressStrings,
          statusCode: incoming.statusCode,
          contentType: contentType,
        );
      }
      final builder = BytesBuilder(copy: false);
      await for (final chunk in incoming.timeout(timeouts.read)) {
        await _checkCancelled(request.uri);
        if (builder.length + chunk.length > request.maximumBytes) {
          throw C2paUriPolicyException(
            'HTTP response exceeds the configured byte limit',
            violation: RemoteManifestPolicyViolation.responseTooLarge,
            uri: request.uri,
          );
        }
        builder.add(chunk);
      }
      return C2paRemoteResponse.bytes(
        bytes: builder.takeBytes(),
        resolvedAddresses: addressStrings,
        statusCode: incoming.statusCode,
        contentLength: contentLength,
        contentType: contentType,
      );
    } on C2paNetworkException {
      rethrow;
    } on TimeoutException catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'HTTP request timed out',
        failure: C2paRemoteTransportFailure.timeout,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    } on Object catch (error, stackTrace) {
      if (cancellationRequested) {
        throw C2paRemoteTransportException(
          'HTTP request was cancelled',
          failure: C2paRemoteTransportFailure.cancelled,
          uri: request.uri,
          cause: error,
          stackTrace: stackTrace,
        );
      }
      if (overallExpired) {
        throw C2paRemoteTransportException(
          'HTTP request exceeded its overall timeout',
          failure: C2paRemoteTransportFailure.timeout,
          uri: request.uri,
          cause: error,
          stackTrace: stackTrace,
        );
      }
      throw C2paRemoteTransportException(
        'HTTP transport failed: $error',
        failure: C2paRemoteTransportFailure.transport,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    } finally {
      cancellationTimer?.cancel();
      overallTimer?.cancel();
      client.close(force: true);
    }
  }

  Future<void> _checkCancelled(Uri uri) async {
    if (await isCancelled?.call() ?? false) {
      throw C2paRemoteTransportException(
        'HTTP request was cancelled',
        failure: C2paRemoteTransportFailure.cancelled,
        uri: uri,
      );
    }
  }
}

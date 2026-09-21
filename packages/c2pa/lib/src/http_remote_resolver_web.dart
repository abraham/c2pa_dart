// ignore_for_file: deprecated_member_use

import 'dart:async';
import 'dart:html';
import 'dart:typed_data';

import 'exceptions.dart';
import 'http_remote_types.dart';
import 'remote_manifest.dart';

/// Creates the browser HTTP remote manifest resolver.
///
/// The resolver performs network I/O and enforces [policy] and [timeouts].
C2paHttpRemoteResolver createC2paHttpRemoteResolver({
  required RemoteManifestPolicy policy,
  required C2paHttpTimeouts timeouts,
  C2paHttpCancellationCallback? isCancelled,
  C2paHostResolver? hostResolver,
}) => _BrowserHttpRemoteResolver(
  policy: policy,
  timeouts: timeouts,
  isCancelled: isCancelled,
  hostResolver: hostResolver,
);

final class _BrowserHttpRemoteResolver implements C2paHttpRemoteResolver {
  _BrowserHttpRemoteResolver({
    required this.policy,
    required this.timeouts,
    required this.isCancelled,
    required C2paHostResolver? hostResolver,
  }) {
    timeouts.validate();
    if (hostResolver != null) {
      throw UnsupportedError(
        'Browser HTTP resolvers cannot expose or override DNS resolution',
      );
    }
  }

  final RemoteManifestPolicy policy;
  final C2paHttpTimeouts timeouts;
  final C2paHttpCancellationCallback? isCancelled;

  @override
  C2paHttpResolverCapabilities get capabilities =>
      const C2paHttpResolverCapabilities(
        resolvedAddressMetadata: false,
        pinsValidatedAddress: false,
        validatesRedirectBeforeConnect: false,
      );

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    if (await isCancelled?.call() ?? false) {
      throw C2paRemoteTransportException(
        'Browser HTTP request was cancelled',
        failure: C2paRemoteTransportFailure.cancelled,
        uri: request.uri,
      );
    }
    policy.validate(request.uri, redirectCount: request.redirectCount);
    try {
      final response = await HttpRequest.request(
        request.uri.toString(),
        method: 'GET',
        requestHeaders: {'Accept': request.acceptHeader},
        responseType: 'arraybuffer',
        withCredentials: false,
      ).timeout(timeouts.overall);
      if (await isCancelled?.call() ?? false) {
        throw C2paRemoteTransportException(
          'Browser HTTP request was cancelled',
          failure: C2paRemoteTransportFailure.cancelled,
          uri: request.uri,
        );
      }
      final responseUri = response.responseUrl == null
          ? request.uri
          : Uri.parse(response.responseUrl!);
      policy.validate(responseUri, redirectCount: request.redirectCount);
      if (_requestKey(responseUri) != _requestKey(request.uri)) {
        policy.validate(responseUri, redirectCount: request.redirectCount + 1);
        return C2paRemoteResponse.redirect(
          redirectUri: responseUri,
          statusCode: 302,
        );
      }
      final contentType = (response.getResponseHeader('content-type') ?? '')
          .split(';')
          .first
          .trim()
          .toLowerCase();
      final status = response.status ?? 0;
      if (status >= 200 &&
          status <= 299 &&
          request.acceptedContentTypes.isNotEmpty &&
          !request.acceptedContentTypes
              .map((value) => value.toLowerCase())
              .contains(contentType)) {
        throw C2paRemoteTransportException(
          'HTTP response has an unsupported content type',
          failure: C2paRemoteTransportFailure.invalidResponse,
          uri: responseUri,
        );
      }
      final contentLength = int.tryParse(
        response.getResponseHeader('content-length') ?? '',
      );
      if (contentLength != null && contentLength > request.maximumBytes) {
        throw C2paUriPolicyException(
          'HTTP content length exceeds the configured byte limit',
          violation: RemoteManifestPolicyViolation.responseTooLarge,
          uri: responseUri,
        );
      }
      final bytes = Uint8List.view(response.response as ByteBuffer);
      if (bytes.length > request.maximumBytes) {
        throw C2paUriPolicyException(
          'HTTP response exceeds the configured byte limit',
          violation: RemoteManifestPolicyViolation.responseTooLarge,
          uri: responseUri,
        );
      }
      return C2paRemoteResponse.bytes(
        bytes: bytes,
        statusCode: status,
        contentLength: contentLength == bytes.length ? contentLength : null,
        contentType: contentType.isEmpty ? null : contentType,
      );
    } on C2paNetworkException {
      rethrow;
    } on TimeoutException catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'Browser HTTP request timed out',
        failure: C2paRemoteTransportFailure.timeout,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    } on Object catch (error, stackTrace) {
      throw C2paRemoteTransportException(
        'Browser HTTP transport failed: $error',
        failure: C2paRemoteTransportFailure.transport,
        uri: request.uri,
        cause: error,
        stackTrace: stackTrace,
      );
    }
  }

  String _requestKey(Uri uri) =>
      uri.replace(fragment: '').normalizePath().toString();
}

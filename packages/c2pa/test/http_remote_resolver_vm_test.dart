@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('VM HTTP resolver', () {
    test('reports address pinning capabilities', () {
      final resolver = createC2paHttpRemoteResolver(
        policy: RemoteManifestPolicy(
          enabled: true,
          allowedSchemes: const {'http'},
          allowedHosts: const {'example.test'},
          maxBytes: 10,
        ),
      );

      expect(resolver.capabilities.resolvedAddressMetadata, isTrue);
      expect(resolver.capabilities.pinsValidatedAddress, isTrue);
      expect(resolver.capabilities.validatesRedirectBeforeConnect, isTrue);
    });

    test('blocks a private resolution before opening a connection', () async {
      var requests = 0;
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final subscription = server.listen((request) async {
        requests++;
        await request.response.close();
      });
      addTearDown(() async {
        await server.close(force: true);
        await subscription.cancel();
      });
      final uri = Uri.parse('http://assets.example:${server.port}/manifest');
      final policy = RemoteManifestPolicy(
        enabled: true,
        allowedSchemes: const {'http'},
        allowedHosts: const {'assets.example'},
        allowedPorts: {server.port},
        maxBytes: 32,
      );
      final resolver = createC2paHttpRemoteResolver(
        policy: policy,
        hostResolver: (_) async => ['127.0.0.1'],
      );

      await expectLater(
        resolver.resolve(
          C2paRemoteRequest(uri: uri, redirectCount: 0, maximumBytes: 32),
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.resolvedAddressNotAllowed,
          ),
        ),
      );
      expect(requests, 0);
    });

    test(
      'pins the validated address and sends no ambient credentials',
      () async {
        HttpHeaders? headers;
        String? host;
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final subscription = server.listen((request) async {
          headers = request.headers;
          host = request.headers.value(HttpHeaders.hostHeader);
          request.response
            ..headers.contentType = ContentType('application', 'c2pa')
            ..contentLength = 3
            ..add([1, 2, 3]);
          await request.response.close();
        });
        addTearDown(() async {
          await server.close(force: true);
          await subscription.cancel();
        });
        final policy = _localPolicy(server.port, host: 'assets.example');
        final resolver = createC2paHttpRemoteResolver(
          policy: policy,
          hostResolver: (_) async => ['127.0.0.1'],
        );
        final response = await resolver.resolve(
          C2paRemoteRequest(
            uri: Uri.parse('http://assets.example:${server.port}/manifest'),
            redirectCount: 0,
            maximumBytes: 16,
            acceptedContentTypes: const {'application/c2pa'},
          ),
        );

        expect(response.bytes, [1, 2, 3]);
        expect(response.resolvedAddresses, contains('127.0.0.1'));
        expect(headers!.value(HttpHeaders.acceptHeader), 'application/c2pa');
        expect(headers!.value(HttpHeaders.cookieHeader), isNull);
        expect(headers!.value(HttpHeaders.authorizationHeader), isNull);
        expect(headers!.value(HttpHeaders.proxyAuthorizationHeader), isNull);
        expect(host, 'assets.example:${server.port}');
      },
    );

    test(
      'follows validated redirects and rejects loops and statuses',
      () async {
        late HttpServer server;
        server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final subscription = server.listen((request) async {
          switch (request.uri.path) {
            case '/start':
              request.response
                ..statusCode = HttpStatus.found
                ..headers.set(HttpHeaders.locationHeader, '/final');
            case '/loop':
              request.response
                ..statusCode = HttpStatus.found
                ..headers.set(HttpHeaders.locationHeader, '/loop');
            case '/missing':
              request.response.statusCode = HttpStatus.notFound;
            default:
              request.response
                ..headers.contentType = ContentType(
                  'application',
                  'octet-stream',
                )
                ..add([9, 8]);
          }
          await request.response.close();
        });
        addTearDown(() async {
          await server.close(force: true);
          await subscription.cancel();
        });
        final policy = _localPolicy(server.port, maxRedirects: 2);
        final resolver = createC2paHttpRemoteResolver(policy: policy);
        final origin = 'http://127.0.0.1:${server.port}';

        expect(
          await resolveRemoteManifest(
            uri: Uri.parse('$origin/start'),
            policy: policy,
            timeout: const Duration(seconds: 2),
            resolver: resolver,
          ),
          [9, 8],
        );
        await expectLater(
          resolveRemoteManifest(
            uri: Uri.parse('$origin/loop'),
            policy: policy,
            timeout: const Duration(seconds: 2),
            resolver: resolver,
          ),
          throwsA(
            isA<C2paRemoteTransportException>().having(
              (error) => error.failure,
              'failure',
              C2paRemoteTransportFailure.redirectLoop,
            ),
          ),
        );
        await expectLater(
          resolveRemoteManifest(
            uri: Uri.parse('$origin/missing'),
            policy: policy,
            timeout: const Duration(seconds: 2),
            resolver: resolver,
          ),
          throwsA(
            isA<C2paRemoteTransportException>().having(
              (error) => error.failure,
              'failure',
              C2paRemoteTransportFailure.httpStatus,
            ),
          ),
        );
      },
    );

    test('enforces MIME, length, streaming, timeout, and cancellation', () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final subscription = server.listen((request) async {
        try {
          if (request.uri.path == '/slow') {
            await Future<void>.delayed(const Duration(milliseconds: 100));
          }
          request.response
            ..headers.contentType = ContentType.text
            ..add(List<int>.filled(32, 1));
          await request.response.close();
        } on Object {
          // The timeout and cancellation cases intentionally abort the client.
        }
      });
      addTearDown(() async {
        await server.close(force: true);
        await subscription.cancel();
      });
      final policy = _localPolicy(server.port, maxBytes: 64);
      final origin = 'http://127.0.0.1:${server.port}';

      await expectLater(
        createC2paHttpRemoteResolver(policy: policy).resolve(
          C2paRemoteRequest(
            uri: Uri.parse('$origin/value'),
            redirectCount: 0,
            maximumBytes: 64,
            acceptedContentTypes: const {'application/did+json'},
          ),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.invalidResponse,
          ),
        ),
      );
      await expectLater(
        createC2paHttpRemoteResolver(policy: policy).resolve(
          C2paRemoteRequest(
            uri: Uri.parse('$origin/value'),
            redirectCount: 0,
            maximumBytes: 8,
          ),
        ),
        throwsA(isA<C2paUriPolicyException>()),
      );
      await expectLater(
        createC2paHttpRemoteResolver(
          policy: policy,
          timeouts: const C2paHttpTimeouts(
            connect: Duration(seconds: 1),
            read: Duration(milliseconds: 10),
            overall: Duration(seconds: 1),
          ),
        ).resolve(
          C2paRemoteRequest(
            uri: Uri.parse('$origin/slow'),
            redirectCount: 0,
            maximumBytes: 64,
          ),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.timeout,
          ),
        ),
      );
      var cancelled = false;
      unawaited(
        Future<void>.delayed(
          const Duration(milliseconds: 20),
          () => cancelled = true,
        ),
      );
      await expectLater(
        createC2paHttpRemoteResolver(
          policy: policy,
          isCancelled: () => cancelled,
        ).resolve(
          C2paRemoteRequest(
            uri: Uri.parse('$origin/slow'),
            redirectCount: 0,
            maximumBytes: 64,
          ),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.cancelled,
          ),
        ),
      );
      await expectLater(
        createC2paHttpRemoteResolver(
          policy: policy,
          isCancelled: () => true,
        ).resolve(
          C2paRemoteRequest(
            uri: Uri.parse('$origin/value'),
            redirectCount: 0,
            maximumBytes: 64,
          ),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.cancelled,
          ),
        ),
      );
    });
  });
}

RemoteManifestPolicy _localPolicy(
  int port, {
  String host = '127.0.0.1',
  int maxRedirects = 0,
  int maxBytes = 1024,
}) => RemoteManifestPolicy(
  enabled: true,
  allowedSchemes: const {'http'},
  allowedHosts: {host},
  allowedPorts: {port},
  allowPrivateAddresses: true,
  maxRedirects: maxRedirects,
  maxBytes: maxBytes,
);

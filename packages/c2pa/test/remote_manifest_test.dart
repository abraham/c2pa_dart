import 'dart:async';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('RemoteManifestPolicy', () {
    test('is default deny and exposes immutable allowlists', () {
      final schemes = {'https'};
      final hosts = {'Assets.Example.'};
      final policy = RemoteManifestPolicy(
        allowedSchemes: schemes,
        allowedHosts: hosts,
      );
      schemes.add('http');
      hosts.clear();

      expect(policy.enabled, isFalse);
      expect(policy.allowedSchemes, {'https'});
      expect(policy.allowedHosts, {'assets.example'});
      expect(
        () => policy.allowedHosts.add('other.example'),
        throwsUnsupportedError,
      );
      expect(
        () => policy.validate(Uri.parse('https://assets.example/a.c2pa')),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.disabled,
          ),
        ),
      );
    });

    test('allows only configured schemes and hosts', () {
      final policy = RemoteManifestPolicy(
        enabled: true,
        allowedHosts: const {'assets.example'},
        allowSubdomains: true,
        maxBytes: 100,
        maxRedirects: 1,
      );

      expect(
        policy.allows(
          Uri.parse('https://cdn.assets.example/manifest.c2pa'),
          byteCount: 100,
          redirectCount: 1,
        ),
        isTrue,
      );
      expect(
        policy.allows(Uri.parse('http://assets.example/manifest.c2pa')),
        isFalse,
      );
      expect(
        policy.allows(Uri.parse('https://not-assets.example/manifest.c2pa')),
        isFalse,
      );
      expect(
        policy.allows(
          Uri.parse('https://assets.example/manifest.c2pa'),
          redirectCount: 2,
        ),
        isFalse,
      );
      expect(
        policy.allows(
          Uri.parse('https://assets.example/manifest.c2pa'),
          byteCount: 101,
        ),
        isFalse,
      );
    });

    test('blocks localhost, private, and link-local literals', () {
      final policy = RemoteManifestPolicy(
        enabled: true,
        allowedHosts: const {
          'localhost',
          '127.0.0.1',
          '10.0.0.1',
          '169.254.1.2',
          '192.168.1.1',
          '172.16.0.1',
          '::1',
          'fc00::1',
          'fe80::1',
          '203.0.113.10',
          '8.8.8.8',
        },
        maxBytes: 1024,
      );

      for (final host in [
        'localhost',
        '127.0.0.1',
        '10.0.0.1',
        '169.254.1.2',
        '192.168.1.1',
        '172.16.0.1',
        '0.0.0.0',
        '100.64.0.1',
        '192.0.2.1',
        '198.51.100.1',
        '224.0.0.1',
        '[::1]',
        '[::]',
        '[0:0:0:0:0:0:0:1]',
        '[::ffff:127.0.0.1]',
        '[fc00::1]',
        '[fe80::1]',
        '[fec0::1]',
        '[ff02::1]',
        '[2001:db8::1]',
      ]) {
        expect(
          policy.allows(Uri.parse('https://$host/manifest.c2pa')),
          isFalse,
          reason: host,
        );
      }
      expect(
        policy.allows(Uri.parse('https://203.0.113.10/manifest.c2pa')),
        isFalse,
      );
      expect(policy.allows(Uri.parse('https://8.8.8.8/manifest.c2pa')), isTrue);
    });

    test('rejects credentials and non-absolute URIs', () {
      final policy = RemoteManifestPolicy(
        enabled: true,
        allowedHosts: const {'assets.example'},
        maxBytes: 10,
      );

      expect(policy.allows(Uri.parse('/relative.c2pa')), isFalse);
      expect(
        policy.allows(
          Uri.parse('https://user:secret@assets.example/manifest.c2pa'),
        ),
        isFalse,
      );
    });

    test('validates explicit ports and resolved addresses', () {
      final policy = RemoteManifestPolicy(
        enabled: true,
        allowedHosts: const {'assets.example'},
        allowedPorts: const {8443},
        maxBytes: 10,
      );

      expect(
        policy.allows(Uri.parse('https://assets.example:8443/a.c2pa')),
        isTrue,
      );
      expect(
        policy.allows(Uri.parse('https://assets.example:9443/a.c2pa')),
        isFalse,
      );
      expect(
        () => policy.validate(
          Uri.parse('https://assets.example/a.c2pa'),
          resolvedAddresses: const {'192.168.1.2'},
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.resolvedAddressNotAllowed,
          ),
        ),
      );
    });

    test('browser policy is opt-in and request MIME types are immutable', () {
      final policy = RemoteManifestPolicy.browser(
        allowedHosts: const {'assets.example'},
        maxBytes: 1024,
      );
      final accepted = {'application/did+json'};
      final request = C2paRemoteRequest(
        uri: Uri.parse('https://assets.example/did.json'),
        redirectCount: 0,
        maximumBytes: 1024,
        acceptedContentTypes: accepted,
      );
      accepted.clear();

      expect(policy.enabled, isTrue);
      expect(policy.allowSameOrigin, isTrue);
      expect(request.acceptedContentTypes, {'application/did+json'});
      expect(request.acceptHeader, 'application/did+json');
      expect(
        () => request.acceptedContentTypes.add('application/json'),
        throwsUnsupportedError,
      );
    });
  });

  group('resolveRemoteManifest', () {
    final policy = RemoteManifestPolicy(
      enabled: true,
      allowedHosts: const {'assets.example', 'cdn.example'},
      maxRedirects: 3,
      maxBytes: 4,
    );

    test('revalidates redirects and resolved addresses', () async {
      final resolver = _QueueResolver([
        C2paRemoteResponse.redirect(
          redirectUri: Uri.parse('https://cdn.example/final.c2pa'),
          resolvedAddresses: const {'93.184.216.34'},
        ),
        C2paRemoteResponse.bytes(
          bytes: const [1, 2, 3],
          contentLength: 3,
          resolvedAddresses: const {'93.184.216.35'},
        ),
      ]);

      final bytes = await resolveRemoteManifest(
        uri: Uri.parse('https://assets.example/start.c2pa'),
        policy: policy,
        timeout: const Duration(seconds: 1),
        resolver: resolver,
      );

      expect(bytes, [1, 2, 3]);
      expect(resolver.requests.map((request) => request.uri.host), [
        'assets.example',
        'cdn.example',
      ]);
      expect(resolver.requests.last.redirectCount, 1);
      expect(resolver.requests.last.maximumBytes, 4);
    });

    test('rejects loops, rebinding, oversized, and truncated responses', () {
      Future<Uint8List> resolve(C2paRemoteResolver resolver) =>
          resolveRemoteManifest(
            uri: Uri.parse('https://assets.example/start.c2pa'),
            policy: policy,
            timeout: const Duration(seconds: 1),
            resolver: resolver,
          );

      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.redirect(
              redirectUri: Uri.parse('/start.c2pa'),
              resolvedAddresses: const {'93.184.216.34'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.redirectLoop,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.redirect(
              redirectUri: Uri.parse('https://evil.example/a.c2pa'),
              resolvedAddresses: const {'93.184.216.34'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.hostNotAllowed,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.bytes(
              bytes: const [],
              statusCode: 404,
              resolvedAddresses: const {'93.184.216.34'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.httpStatus,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.bytes(bytes: const [1]),
          ]),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.invalidResponse,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.bytes(
              bytes: const [1],
              resolvedAddresses: const {'127.0.0.1'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.resolvedAddressNotAllowed,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.bytes(
              bytes: const [1, 2, 3, 4, 5],
              resolvedAddresses: const {'93.184.216.34'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.responseTooLarge,
          ),
        ),
      );
      expect(
        resolve(
          _QueueResolver([
            C2paRemoteResponse.bytes(
              bytes: const [1, 2],
              contentLength: 3,
              resolvedAddresses: const {'93.184.216.34'},
            ),
          ]),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.truncated,
          ),
        ),
      );
    });

    test('supports cancellation and bounded timeouts', () {
      expect(
        resolveRemoteManifest(
          uri: Uri.parse('https://assets.example/a.c2pa'),
          policy: policy,
          timeout: const Duration(seconds: 1),
          resolver: _QueueResolver(const []),
          isCancelled: () => true,
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.cancelled,
          ),
        ),
      );
      expect(
        resolveRemoteManifest(
          uri: Uri.parse('https://assets.example/a.c2pa'),
          policy: policy,
          timeout: const Duration(milliseconds: 1),
          resolver: _DelayedResolver(),
        ),
        throwsA(
          isA<C2paRemoteTransportException>().having(
            (error) => error.failure,
            'failure',
            C2paRemoteTransportFailure.timeout,
          ),
        ),
      );
    });
  });
}

final class _QueueResolver implements C2paRemoteResolver {
  _QueueResolver(Iterable<C2paRemoteResponse> responses)
    : _responses = List<C2paRemoteResponse>.of(responses);

  final List<C2paRemoteResponse> _responses;
  final List<C2paRemoteRequest> requests = [];

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    requests.add(request);
    if (_responses.isEmpty) throw StateError('No response');
    return _responses.removeAt(0);
  }
}

final class _DelayedResolver implements C2paRemoteResolver {
  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    await Future<void>.delayed(const Duration(milliseconds: 100));
    return C2paRemoteResponse.bytes(
      bytes: const [1],
      resolvedAddresses: const {'93.184.216.34'},
    );
  }
}

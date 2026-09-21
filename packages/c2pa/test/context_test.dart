import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('C2paContext', () {
    test('composes immutable configuration and callbacks', () async {
      final anchors = [
        Uint8List.fromList([1, 2, 3]),
      ];
      final intermediates = [
        Uint8List.fromList([4, 5, 6]),
      ];
      final leafHashes = [Uint8List.fromList(List<int>.filled(32, 7))];
      final trustUris = [Uri.parse('https://trust.example/list')];
      final events = <C2paProgressEvent>[];
      final signer = CallbackC2paSigner(
        algorithm: 'es256',
        callback: (data) async => Uint8List.fromList(data),
      );
      final verifier = CallbackC2paVerifier(
        ({
          required algorithm,
          required data,
          required signature,
          required publicKey,
        }) async => algorithm == 'es256',
      );
      final resolver = _Resolver();
      final context = C2paContext(
        settings: const C2paSettings(allowNetworkAccess: true),
        trust: C2paTrustConfig(
          verifyTrust: true,
          trustAnchors: anchors,
          intermediates: intermediates,
          allowedEndEntitySha256Hashes: leafHashes,
          allowedEkuOids: const {'1.2.3'},
          evaluationTime: DateTime.utc(2027),
          maxPathDepth: 4,
          trustListUris: trustUris,
        ),
        onProgress: (event) async => events.add(event),
        remoteManifestResolver: resolver,
        remoteManifestPolicy: RemoteManifestPolicy(
          enabled: true,
          allowedHosts: const {'assets.example'},
          maxBytes: 1024,
        ),
        signer: signer,
        verifier: verifier,
      );

      anchors.add(Uint8List.fromList([4]));
      intermediates.single[0] = 0;
      leafHashes.single[0] = 0;
      trustUris.clear();
      await context.reportProgress(
        const C2paProgressEvent(
          phase: C2paProgressPhase.validating,
          completed: 1,
          total: 2,
        ),
      );

      expect(context.trust.trustAnchors.single, [1, 2, 3]);
      expect(context.trust.intermediates.single, [4, 5, 6]);
      expect(
        context.trust.allowedEndEntitySha256Hashes.single,
        List<int>.filled(32, 7),
      );
      expect(context.trust.allowedEkuOids, {'1.2.3'});
      expect(context.trust.evaluationTime, DateTime.utc(2027));
      expect(context.trust.maxPathDepth, 4);
      expect(context.trust.trustListUris, hasLength(1));
      expect(
        () => context.trust.trustAnchors.add(Uint8List(1)),
        throwsUnsupportedError,
      );
      expect(
        () => context.trust.intermediates.single[0] = 0,
        throwsUnsupportedError,
      );
      expect(context.remoteManifestResolver, same(resolver));
      expect(context.signer, same(signer));
      expect(context.verifier, same(verifier));
      expect(events.single.phase, C2paProgressPhase.validating);
    });

    test('derives a default-deny remote policy from settings', () {
      final disabled = C2paContext();
      final enabled = C2paContext(
        settings: const C2paSettings(
          allowNetworkAccess: true,
          maxNetworkBytes: 123,
          maxRedirects: 2,
        ),
      );

      expect(disabled.remoteManifestPolicy.enabled, isFalse);
      expect(enabled.remoteManifestPolicy.enabled, isTrue);
      expect(enabled.remoteManifestPolicy.maxBytes, 123);
      expect(enabled.remoteManifestPolicy.maxRedirects, 2);
      expect(
        enabled.remoteManifestPolicy.allows(
          Uri.parse('https://unlisted.example/manifest.c2pa'),
        ),
        isFalse,
      );
    });
  });
}

final class _Resolver implements RemoteManifestResolver {
  @override
  Future<Uint8List?> resolve(Uri uri) async => Uint8List.fromList([1]);
}

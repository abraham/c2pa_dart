import 'dart:typed_data';

import 'package:c2pa/src/compressed_manifest.dart';
import 'package:c2pa/src/http_remote_resolver.dart';
import 'package:c2pa/src/remote_manifest.dart';
import 'package:c2pa/src/resource_store.dart';
import 'package:c2pa/src/settings.dart';
import 'package:c2pa/src/timestamping.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  test('bounded Brotli compressed manifests are browser-safe', () {
    final outer = JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paCompressedManifest,
        label: 'manifest',
      ),
      children: [JumbfBrotliNode(_compressedManifest)],
    ).encode();
    final decoded = decodeCompressedJumbf(
      outer,
      maxOutputBytes: const C2paSettings().maxDecompressedManifestBytes,
    );
    expect(decoded.manifest.label, 'manifest');
    expect(C2paCapabilities.compressedManifests.canReadBrotli, isTrue);
    expect(C2paCapabilities.compressedManifests.canWriteBrotli, isFalse);
    final timestamp = C2paTimestampConfig.callback(
      callback: (request) async => Uint8List.fromList(request),
      reservedSize: 1024,
    );
    final resources = ResourceStore()..add('/browser-resource', Uint8List(3));
    final resolver = createC2paHttpRemoteResolver(
      policy: RemoteManifestPolicy(
        enabled: true,
        allowedSchemes: const {'https'},
        allowSameOrigin: true,
        maxBytes: 1024,
      ),
    );
    expect(timestamp.usesCallback, isTrue);
    expect(resources.length, 1);
    expect(resolver.capabilities, isNotNull);
  });
}

Uint8List get _compressedManifest => _hex(
  '21a400040000002a6a756d62000000226a756d6463326d6100110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List _hex(String value) => Uint8List.fromList(
  List<int>.generate(
    value.length ~/ 2,
    (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
    growable: false,
  ),
);

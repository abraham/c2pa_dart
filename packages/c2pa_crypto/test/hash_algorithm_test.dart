import 'dart:convert';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('HashAlgorithm', () {
    final vectors = <HashAlgorithm, String>{
      HashAlgorithm.sha256:
          'ba7816bf8f01cfea414140de5dae2223'
          'b00361a396177a9cb410ff61f20015ad',
      HashAlgorithm.sha384:
          'cb00753f45a35e8bb5a03d699ac65007'
          '272c32ab0eded1631a8b605a43ff5bed'
          '8086072ba1e7cc2358baeca134c825a7',
      HashAlgorithm.sha512:
          'ddaf35a193617abacc417349ae204131'
          '12e6fa4e89a97ea20a9eeee64b55d39a'
          '2192992a274fc1a836ba3c23a3feebbd'
          '454d4423643ce80e2a9ac94fa54ca49f',
    };

    for (final entry in vectors.entries) {
      test('${entry.key.name} known-answer vector', () async {
        final digest = await entry.key.digest(utf8.encode('abc'));
        expect(_hex(digest), entry.value);
        expect(digest, hasLength(entry.key.digestLength));
      });
    }
  });
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('maps signing algorithms to COSE IDs and digest properties', () {
    final expected = {
      SigningAlgorithm.es256: (-7, HashAlgorithm.sha256, 32, 64),
      SigningAlgorithm.es384: (-35, HashAlgorithm.sha384, 48, 96),
      SigningAlgorithm.es512: (-36, HashAlgorithm.sha512, 66, 132),
      SigningAlgorithm.ps256: (-37, HashAlgorithm.sha256, null, null),
      SigningAlgorithm.ps384: (-38, HashAlgorithm.sha384, null, null),
      SigningAlgorithm.ps512: (-39, HashAlgorithm.sha512, null, null),
      SigningAlgorithm.ed25519: (-8, null, null, null),
    };

    for (final entry in expected.entries) {
      final (coseId, hash, componentLength, signatureLength) = entry.value;
      expect(entry.key.coseId, coseId);
      expect(entry.key.hashAlgorithm, hash);
      expect(entry.key.p1363ComponentLength, componentLength);
      expect(entry.key.p1363SignatureLength, signatureLength);
      expect(SigningAlgorithm.fromCoseId(coseId), entry.key);
    }
  });

  test('strict lookup rejects unknown COSE IDs', () {
    expect(() => SigningAlgorithm.fromCoseId(7), throwsA(isA<ArgumentError>()));
    expect(
      () => SigningAlgorithm.fromCoseId(-40),
      throwsA(isA<ArgumentError>()),
    );
  });
}

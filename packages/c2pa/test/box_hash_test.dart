import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  test('BoxHash v1 has deterministic CBOR and owned immutable bytes', () {
    final hash = Uint8List.fromList([1, 2, 3]);
    final assertion = BoxHashAssertion(
      boxes: [
        BoxHashBox(
          names: const ['SOI', 'APP0'],
          algorithm: 'sha256',
          hash: hash,
        ),
        BoxHashBox(names: const ['C2PA'], hash: const [0], excluded: true),
      ],
    );
    hash[0] = 9;

    final encoded = encodeCbor(assertion.toCborMap());
    final decoded = BoxHashAssertion.fromCbor(decodeCbor(encoded));

    expect(decoded, assertion);
    expect(decoded.boxes.first.hash, [1, 2, 3]);
    expect(() => decoded.boxes.first.hash[0] = 0, throwsUnsupportedError);
    expect(encoded, encodeCbor(assertion.toCborMap()));
    expect(BoxHashAssertion.label, 'c2pa.hash.boxes');
    expect(BoxHashAssertion.version, 1);
  });

  test('BoxHash rejects malformed entries', () {
    expect(
      () => BoxHashAssertion.fromCbor({
        'boxes': [
          {
            'names': ['SOI'],
            'alg': 'sha256',
            'hash': 'not bytes',
            'pad': Uint8List(0),
          },
        ],
      }),
      throwsFormatException,
    );
    expect(
      () => BoxHashAssertion.fromCbor({'boxes': <Object?>[]}),
      throwsFormatException,
    );
  });
}

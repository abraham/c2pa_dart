import 'dart:typed_data';

import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('fake signer records owned inputs and copies callback output', () async {
    late Uint8List callbackResult;
    final signer = FakeC2paSigner(
      algorithm: 'es256',
      callback: (data) {
        data[0] = 9;
        return callbackResult = Uint8List.fromList([4, 5]);
      },
    );
    final source = Uint8List.fromList([1, 2]);

    final signature = await signer.sign(source);
    callbackResult[0] = 8;
    source[0] = 7;

    expect(signer.algorithm, 'es256');
    expect(signature, [4, 5]);
    expect(signer.invocations.single.data, [1, 2]);
    expect(() => signer.invocations.clear(), throwsUnsupportedError);
  });

  test('fake verifier records calls and isolates callback inputs', () async {
    final verifier = FakeC2paVerifier(({
      required algorithm,
      required data,
      required signature,
      required publicKey,
    }) async {
      data[0] = 9;
      return algorithm == 'ps256' &&
          signature.single == 2 &&
          publicKey.single == 3;
    });
    final data = Uint8List.fromList([1]);

    expect(
      await verifier.verify(
        algorithm: 'ps256',
        data: data,
        signature: Uint8List.fromList([2]),
        publicKey: Uint8List.fromList([3]),
      ),
      isTrue,
    );
    data[0] = 8;

    final invocation = verifier.invocations.single;
    expect(invocation.algorithm, 'ps256');
    expect(invocation.data, [1]);
    expect(invocation.signature, [2]);
    expect(invocation.publicKey, [3]);
  });
}

import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  test('callback signer exposes algorithm and signs asynchronously', () async {
    final signer = CallbackC2paSigner(
      algorithm: 'es256',
      callback: (data) async => Uint8List.fromList(data.reversed.toList()),
    );

    expect(signer.algorithm, 'es256');
    expect(await signer.sign(Uint8List.fromList([1, 2, 3])), [3, 2, 1]);
  });

  test('callback verifier receives algorithm and byte inputs', () async {
    String? receivedAlgorithm;
    final verifier = CallbackC2paVerifier(({
      required algorithm,
      required data,
      required signature,
      required publicKey,
    }) async {
      receivedAlgorithm = algorithm;
      return data.length == signature.length && publicKey.isNotEmpty;
    });

    final valid = await verifier.verify(
      algorithm: 'ps256',
      data: Uint8List.fromList([1]),
      signature: Uint8List.fromList([2]),
      publicKey: Uint8List.fromList([3]),
    );

    expect(valid, isTrue);
    expect(receivedAlgorithm, 'ps256');
  });

  test('exception hierarchy retains diagnostic context', () {
    final results = ValidationResults.fromIssues([
      ValidationIssue(code: 'bad'),
    ]);
    final exception = C2paValidationException(
      'Validation failed',
      results: results,
      cause: const FormatException('bad input'),
    );

    expect(exception, isA<C2paException>());
    expect(exception.results, results);
    expect(exception.toString(), contains('Validation failed'));
  });
}

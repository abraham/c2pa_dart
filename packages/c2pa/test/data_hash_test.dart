import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  test('DataHash owns bytes and round-trips its CBOR map', () {
    final hash = Uint8List.fromList([1, 2, 3]);
    final assertion = DataHashAssertion(
      exclusions: const [DataHashExclusionRange(start: 7, length: 11)],
      name: 'asset',
      algorithm: 'sha256',
      hash: hash,
      pad: const [0, 0],
      pad2: const [0],
    );
    hash[0] = 9;

    expect(assertion.hash, [1, 2, 3]);
    expect(DataHashAssertion.fromCbor(assertion.toCborMap()), assertion);
    expect(() => assertion.hash[0] = 4, throwsUnsupportedError);
  });

  test('DataHash state machine rejects out-of-order transitions', () {
    final machine = DataHashBuildStateMachine();
    expect(
      () => machine.advance(DataHashBuildState.placeholderEmbedded),
      throwsA(isA<C2paSigningException>()),
    );
    for (final state in DataHashBuildState.values.skip(1)) {
      machine.advance(state);
    }
    expect(machine.state, DataHashBuildState.patched);
  });
}

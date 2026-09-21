@TestOn('vm')
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

/// Seeds are fixed so a failure is reproducible and CI cannot go flaky.
const List<int> _seeds = [1, 7, 42, 1337, 90210];
const int _casesPerSeed = 400;

void main() {
  group('decoding arbitrary bytes', () {
    test('only ever throws CborDecodingException', () {
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final bytes = _randomBytes(random);
          try {
            decodeCbor(bytes);
          } on CborDecodingException {
            continue;
          } catch (error) {
            fail(
              'seed $seed case $case_ threw ${error.runtimeType} ($error) '
              'for ${_hex(bytes)}',
            );
          }
        }
      }
    });

    test('only ever throws CborDecodingException with indefinite lengths', () {
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final bytes = _randomBytes(random);
          try {
            decodeCbor(
              bytes,
              allowIndefiniteLength: true,
              requireCanonicalMapOrder: false,
            );
          } on CborDecodingException {
            continue;
          } catch (error) {
            fail(
              'seed $seed case $case_ threw ${error.runtimeType} ($error) '
              'for ${_hex(bytes)}',
            );
          }
        }
      }
    });

    test('only ever throws CborDecodingException for a mutated encoding', () {
      // Purely random bytes are rejected by the first byte most of the time.
      // Corrupting a valid encoding reaches the length, nesting, and string
      // paths that a real malformed manifest would exercise.
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final encoded = encodeCbor(_randomValue(random, 0));
          final mutated = Uint8List.fromList(encoded);
          final mutations = 1 + random.nextInt(3);
          for (var index = 0; index < mutations; index++) {
            mutated[random.nextInt(mutated.length)] = random.nextInt(256);
          }
          try {
            decodeCbor(
              mutated,
              allowIndefiniteLength: random.nextBool(),
              requireCanonicalMapOrder: random.nextBool(),
            );
          } on CborDecodingException {
            continue;
          } catch (error) {
            fail(
              'seed $seed case $case_ threw ${error.runtimeType} ($error) '
              'for ${_hex(mutated)}',
            );
          }
        }
      }
    });

    test('rejects every truncated prefix of a valid encoding', () {
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final encoded = encodeCbor(_randomValue(random, 0));
          for (var length = 0; length < encoded.length; length++) {
            final prefix = Uint8List.sublistView(encoded, 0, length);
            expect(
              () => decodeCbor(prefix),
              throwsA(isA<CborDecodingException>()),
              reason:
                  'seed $seed case $case_ accepted the first $length bytes '
                  'of ${_hex(encoded)}',
            );
          }
        }
      }
    });
  });

  group('round-tripping generated values', () {
    test('decode(encode(value)) preserves the value', () {
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final value = _randomValue(random, 0);
          final encoded = encodeCbor(value);

          expect(
            decodeCbor(encoded),
            _matches(value),
            reason: 'seed $seed case $case_ for ${_hex(encoded)}',
          );
        }
      }
    });

    test('encoding is deterministic and canonical', () {
      for (final seed in _seeds) {
        final random = Random(seed);
        for (var case_ = 0; case_ < _casesPerSeed; case_++) {
          final value = _randomValue(random, 0);
          final encoded = encodeCbor(value);

          // Re-encoding the decoded value must reproduce the exact bytes,
          // which is the property the manifest signature depends on.
          expect(
            encodeCbor(decodeCbor(encoded)),
            encoded,
            reason: 'seed $seed case $case_ for ${_hex(encoded)}',
          );
        }
      }
    });
  });

  test('rejects nesting past the configured depth without overflowing', () {
    // Each byte opens a one-element array, so the input nests 10000 deep.
    final deep = Uint8List.fromList([...List<int>.filled(10000, 0x81), 0x00]);

    expect(
      () => decodeCbor(deep),
      throwsA(
        isA<CborDecodingException>().having(
          (error) => error.code,
          'code',
          CborDecodingErrorCode.excessiveNesting,
        ),
      ),
    );
  });
}

Uint8List _randomBytes(Random random) {
  final length = random.nextInt(24);
  return Uint8List.fromList([
    for (var index = 0; index < length; index++) random.nextInt(256),
  ]);
}

Object? _randomValue(Random random, int depth) {
  // Past the depth budget only scalars are produced, so generation ends.
  final choice = depth >= 3 ? random.nextInt(7) : random.nextInt(9);
  switch (choice) {
    case 0:
      return null;
    case 1:
      return random.nextBool();
    case 2:
      return random.nextInt(1 << 32) - (1 << 31);
    case 3:
      return random.nextDouble() * 1e6 - 5e5;
    case 4:
      return String.fromCharCodes([
        for (var index = 0; index < random.nextInt(8); index++)
          random.nextInt(0x400) + 0x20,
      ]);
    case 5:
      return Uint8List.fromList([
        for (var index = 0; index < random.nextInt(8); index++)
          random.nextInt(256),
      ]);
    case 6:
      // Kept above the safe integer range, since a BigInt that fits in an int
      // is documented to decode back as an int.
      return (BigInt.one << 60) + BigInt.from(random.nextInt(1 << 32));
    case 7:
      return [
        for (var index = 0; index < random.nextInt(4); index++)
          _randomValue(random, depth + 1),
      ];
    default:
      return <Object?, Object?>{
        for (var index = 0; index < random.nextInt(4); index++)
          _randomKey(random): _randomValue(random, depth + 1),
      };
  }
}

/// Returns a scalar usable as a map key.
///
/// Byte strings and collections are excluded because they use identity
/// equality in Dart, so a decoded copy would never match the original key
/// even when the encoding round-tripped exactly.
Object? _randomKey(Random random) {
  switch (random.nextInt(4)) {
    case 0:
      return null;
    case 1:
      return random.nextBool();
    case 2:
      return random.nextInt(1 << 32) - (1 << 31);
    default:
      return String.fromCharCodes([
        for (var index = 0; index < random.nextInt(8); index++)
          random.nextInt(0x400) + 0x20,
      ]);
  }
}

/// Builds a matcher that compares [value] structurally.
///
/// [Uint8List] does not define value equality, so byte strings are compared
/// element-wise rather than by identity.
Matcher _matches(Object? value) => switch (value) {
  final Uint8List bytes => orderedEquals(bytes),
  final List<Object?> list => equals([for (final item in list) _matches(item)]),
  final Map<Object?, Object?> map => equals({
    for (final entry in map.entries) entry.key: _matches(entry.value),
  }),
  _ => equals(value),
};

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

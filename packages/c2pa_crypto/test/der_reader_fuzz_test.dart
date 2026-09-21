@TestOn('vm')
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:c2pa_crypto/src/der_reader.dart';
import 'package:test/test.dart';

/// Seeds are fixed so a failure is reproducible and CI cannot go flaky.
const List<int> _seeds = [3, 11, 64, 2024, 55555];
const int _casesPerSeed = 400;

void main() {
  group('reading arbitrary bytes', () {
    test('only ever throws FormatException', () {
      _forEachCase((random, label) {
        final bytes = _randomBytes(random);
        _expectOnlyFormatException(() => _walk(DerReader(bytes)), label, bytes);
      });
    });

    test('only ever throws FormatException for a mutated encoding', () {
      // Random bytes are usually rejected by the identifier octet. Corrupting
      // a well-formed encoding reaches the length and container checks that a
      // hostile certificate would actually exercise.
      _forEachCase((random, label) {
        final encoded = _randomDer(random, 0);
        final mutated = Uint8List.fromList(encoded);
        final mutations = 1 + random.nextInt(3);
        for (var index = 0; index < mutations; index++) {
          mutated[random.nextInt(mutated.length)] = random.nextInt(256);
        }
        _expectOnlyFormatException(
          () => _walk(DerReader(mutated)),
          label,
          mutated,
        );
      });
    });

    test('rejects every truncated prefix of a valid encoding', () {
      _forEachCase((random, label) {
        final encoded = _randomDer(random, 0);
        // A zero-length prefix holds no triples at all, which the reader is
        // right to accept, so truncation starts at one byte.
        for (var length = 1; length < encoded.length; length++) {
          final prefix = Uint8List.sublistView(encoded, 0, length);
          expect(
            () {
              final reader = DerReader(prefix);
              _walk(reader);
              reader.requireEnd();
            },
            throwsFormatException,
            reason:
                '$label accepted the first $length bytes of '
                '${_hex(encoded)}',
          );
        }
      });
    });
  });

  group('reading generated values', () {
    test('accepts well-formed input and consumes it exactly', () {
      _forEachCase((random, label) {
        final encoded = _randomDer(random, 0);
        final reader = DerReader(encoded);
        final value = reader.read();

        expect(reader.isAtEnd, isTrue, reason: label);
        expect(value.encoded, orderedEquals(encoded), reason: label);
      });
    });

    test('re-reading a value encoding yields the same triple', () {
      _forEachCase((random, label) {
        final encoded = _randomDer(random, 0);
        final value = DerReader(encoded).read();
        final reparsed = DerReader(value.encoded).read();

        expect(reparsed.tag, value.tag, reason: label);
        expect(reparsed.encoded, orderedEquals(value.encoded), reason: label);
        expect(reparsed.content, orderedEquals(value.content), reason: label);
      });
    });

    test('content is always a slice of the value encoding', () {
      _forEachCase((random, label) {
        final value = DerReader(_randomDer(random, 0)).read();
        final header = value.encoded.length - value.content.length;

        expect(header, greaterThanOrEqualTo(2), reason: label);
        expect(
          Uint8List.sublistView(value.encoded, header),
          orderedEquals(value.content),
          reason: label,
        );
      });
    });
  });

  test('rejects nesting past the budget without overflowing the stack', () {
    // 2000 nested SEQUENCEs, each wrapping the next. The lengths must go
    // through _encode: a hand-written length byte silently becomes long-form
    // once it reaches 0x80, and the reader would then reject the input for
    // being malformed rather than for being too deep.
    var encoded = _encode(0x30, const []);
    for (var index = 0; index < 2000; index++) {
      encoded = _encode(0x30, encoded);
    }

    expect(() => _walk(DerReader(encoded)), throwsFormatException);
  });
}

void _forEachCase(void Function(Random random, String label) body) {
  for (final seed in _seeds) {
    final random = Random(seed);
    for (var case_ = 0; case_ < _casesPerSeed; case_++) {
      body(random, 'seed $seed case $case_');
    }
  }
}

void _expectOnlyFormatException(
  void Function() body,
  String label,
  List<int> bytes,
) {
  try {
    body();
  } on FormatException {
    return;
  } catch (error) {
    fail('$label threw ${error.runtimeType} ($error) for ${_hex(bytes)}');
  }
}

/// Reads every triple, descending into each constructed value.
///
/// Walking the whole tree is what forces the reader to spend its nesting
/// budget, so a missing depth check surfaces as a stack overflow rather than
/// passing unnoticed.
void _walk(DerReader reader) {
  while (!reader.isAtEnd) {
    final value = reader.read();
    if (value.tag & 0x20 != 0) {
      _walk(value.reader());
    }
  }
}

Uint8List _randomBytes(Random random) {
  final length = random.nextInt(24);
  return Uint8List.fromList([
    for (var index = 0; index < length; index++) random.nextInt(256),
  ]);
}

/// Builds one well-formed DER triple, nesting up to three levels deep.
Uint8List _randomDer(Random random, int depth) {
  if (depth >= 3 || random.nextInt(3) == 0) {
    final length = random.nextInt(8);
    final content = [
      for (var index = 0; index < length; index++) random.nextInt(256),
    ];
    // Primitive tags only, avoiding the high-tag-number form the reader bans.
    const primitives = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0c, 0x13, 0x17];
    return _encode(primitives[random.nextInt(primitives.length)], content);
  }
  final children = <int>[];
  final count = random.nextInt(3) + 1;
  for (var index = 0; index < count; index++) {
    children.addAll(_randomDer(random, depth + 1));
  }
  return _encode(random.nextBool() ? 0x30 : 0x31, children);
}

/// Encodes [tag] and [content] with a minimal definite length.
Uint8List _encode(int tag, List<int> content) {
  final length = content.length;
  final header = length < 0x80
      ? [tag, length]
      : length < 0x100
      ? [tag, 0x81, length]
      : [tag, 0x82, length >> 8, length & 0xff];
  return Uint8List.fromList([...header, ...content]);
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

import 'dart:typed_data';

import 'package:c2pa_crypto/src/der_reader.dart';
import 'package:test/test.dart';

/// Wraps [bytes] in `levels` nested `SEQUENCE` headers.
Uint8List _nest(int levels) {
  var bytes = Uint8List.fromList([0x05, 0x00]);
  for (var index = 0; index < levels; index++) {
    final length = bytes.length;
    bytes = Uint8List.fromList([
      0x30,
      if (length < 0x80) length else ...[0x82, length >> 8, length & 0xff],
      ...bytes,
    ]);
  }
  return bytes;
}

/// Descends every nested `SEQUENCE`, returning how many levels were opened.
int _descend(Uint8List der, {int? maxDepth}) {
  var reader = maxDepth == null
      ? DerReader(der)
      : DerReader(der, maxDepth: maxDepth);
  var depth = 0;
  while (true) {
    final value = reader.read();
    if (value.tag != 0x30) {
      return depth;
    }
    reader = value.reader();
    depth++;
  }
}

void main() {
  group('DER nesting budget', () {
    test('accepts nesting up to the cap', () {
      expect(_descend(_nest(defaultMaxDerDepth)), defaultMaxDerDepth);
    });

    test('rejects nesting past the cap', () {
      expect(
        () => _descend(_nest(defaultMaxDerDepth + 1)),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('too deep'),
          ),
        ),
      );
    });

    test('rejects a structure built to exhaust the stack', () {
      expect(() => _descend(_nest(5000)), throwsFormatException);
    });

    test('honours a caller-supplied cap', () {
      expect(_descend(_nest(4), maxDepth: 4), 4);
      expect(() => _descend(_nest(5), maxDepth: 4), throwsFormatException);
    });
  });

  group('DER strictness', () {
    test('reads a value and exposes both spans', () {
      final value = DerReader([0x04, 0x02, 0xaa, 0xbb]).read(0x04);

      expect(value.tag, 0x04);
      expect(value.content, [0xaa, 0xbb]);
      expect(value.encoded, [0x04, 0x02, 0xaa, 0xbb]);
    });

    test('rejects an indefinite length', () {
      expect(
        () => DerReader([0x30, 0x80, 0x05, 0x00]).read(),
        throwsFormatException,
      );
    });

    test('rejects a non-minimal long-form length', () {
      expect(
        () => DerReader([0x04, 0x81, 0x01, 0xaa]).read(),
        throwsFormatException,
      );
    });

    test('rejects a leading zero in a length', () {
      expect(
        () => DerReader([0x04, 0x82, 0x00, 0x01, 0xaa]).read(),
        throwsFormatException,
      );
    });

    test('rejects high-tag-number form', () {
      expect(() => DerReader([0x1f, 0x01, 0x00]).read(), throwsFormatException);
    });

    test('rejects a length that overruns its container', () {
      expect(() => DerReader([0x04, 0x08, 0xaa]).read(), throwsFormatException);
    });

    test('rejects a truncated header', () {
      expect(() => DerReader([0x04]).read(), throwsFormatException);
    });

    test('rejects an unexpected tag', () {
      expect(() => DerReader([0x04, 0x00]).read(0x30), throwsFormatException);
    });

    test('requireEnd rejects trailing data', () {
      final reader = DerReader([0x04, 0x00, 0x05, 0x00])..read();

      expect(reader.requireEnd, throwsFormatException);
    });

    test('single rejects trailing data', () {
      expect(
        () => DerReader([0x04, 0x00, 0x05, 0x00]).single(0x04),
        throwsFormatException,
      );
    });

    test('peekTag reports the end instead of throwing', () {
      final reader = DerReader([0x04, 0x00]);

      expect(reader.peekTag(), 0x04);
      reader.read();
      expect(reader.peekTag(), isNull);
      expect(reader.isAtEnd, isTrue);
    });
  });
}

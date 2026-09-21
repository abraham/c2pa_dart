import 'dart:typed_data';

import 'package:c2pa_formats/src/byte_reader.dart';
import 'package:test/test.dart';

void main() {
  test('reads big-endian widths', () {
    final bytes = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);

    expect(readUint16Be(bytes, 0), 0xdead);
    expect(readUint16Be(bytes, 2), 0xbeef);
    expect(readUint32Be(bytes, 0), 0xdeadbeef);
    expect(readUint32Be(bytes, 2), 0xbeef0102);
  });

  test('reads little-endian widths', () {
    final bytes = Uint8List.fromList([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);

    expect(readUint16Le(bytes, 0), 0xadde);
    expect(readUint32Le(bytes, 0), 0xefbeadde);
  });

  test('reads a 32-bit value with the high bit set as unsigned', () {
    final bytes = Uint8List.fromList([0xff, 0xff, 0xff, 0xff]);

    expect(readUint32Be(bytes, 0), 0xffffffff);
    expect(readUint32Le(bytes, 0), 0xffffffff);
  });

  test('keeps the high word of a 64-bit value', () {
    // Combining the halves by shifting truncates to 32 bits on the web, which
    // would report this 2^32 + 5 size as 5 and let an oversized box through.
    final bytes = Uint8List.fromList([0, 0, 0, 1, 0, 0, 0, 5]);

    expect(tryReadUint64Be(bytes, 0), 0x100000005);
    expect(
      tryReadUint64Le(Uint8List.fromList([5, 0, 0, 0, 1, 0, 0, 0]), 0),
      0x100000005,
    );
  });

  test('accepts the largest exactly representable 64-bit value', () {
    final bytes = Uint8List.fromList([
      0,
      0x1f,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
    ]);

    expect(tryReadUint64Be(bytes, 0), maxExactByteValue);
  });

  test('rejects a 64-bit value above the exact range', () {
    final bytes = Uint8List.fromList([0, 0x20, 0, 0, 0, 0, 0, 0]);

    expect(tryReadUint64Be(bytes, 0), isNull);
    expect(
      tryReadUint64Le(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0x20, 0]), 0),
      isNull,
    );
  });

  test('reads at a non-zero offset and rejects a short buffer', () {
    final bytes = Uint8List.fromList([0xaa, 0, 0, 0, 1, 0, 0, 0, 5]);

    expect(tryReadUint64Be(bytes, 1), 0x100000005);
    // The VM raises RangeError and the web raises a plain ArgumentError, so
    // assert on their shared supertype.
    expect(
      () => readUint32Be(Uint8List.fromList([1, 2, 3]), 0),
      throwsA(isA<ArgumentError>()),
    );
    expect(
      () => tryReadUint64Be(Uint8List.fromList([1, 2, 3, 4]), 0),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('accepts a plain list as well as a typed view', () {
    expect(readUint32Be(const [0xde, 0xad, 0xbe, 0xef], 0), 0xdeadbeef);
  });
}

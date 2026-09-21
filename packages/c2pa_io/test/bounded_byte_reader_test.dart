import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  test('reads exact bytes and big-endian unsigned integers', () async {
    final source = MemoryByteSource([
      0xff,
      0x01,
      0x02,
      0x01,
      0x02,
      0x03,
      0x04,
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
    ]);
    final reader = BoundedByteReader(source, ByteRange(0, 15));

    expect(await reader.readUint8(), 0xff);
    expect(await reader.readUint16(), 0x0102);
    expect(await reader.readUint32(), 0x01020304);
    expect(await reader.readUint64(), 0x0001020304050607);
    expect(reader.position, 15);
    expect(reader.remaining, 0);
    expect(reader.isAtEnd, isTrue);
  });

  test('tracks positions relative to non-zero bounds and seeks', () async {
    final reader = BoundedByteReader(
      MemoryByteSource([0, 1, 2, 3, 4]),
      ByteRange(1, 4),
    );

    expect(reader.position, 0);
    expect(reader.absolutePosition, 1);
    expect(await reader.readExact(2), [1, 2]);
    reader.seek(1);
    expect(await reader.readUint8(), 2);
    reader.seek(3);
    expect(reader.isAtEnd, isTrue);
  });

  test('rejects reads and seeks outside reader bounds', () async {
    final reader = BoundedByteReader(
      MemoryByteSource([0, 1, 2, 3]),
      ByteRange(1, 3),
    );

    await expectLater(
      reader.readExact(3),
      throwsA(isA<ByteRangeOutOfBoundsException>()),
    );
    expect(reader.position, 0);
    expect(() => reader.seek(3), throwsA(isA<ByteRangeOutOfBoundsException>()));
    expect(() => reader.seek(-1), throwsA(isA<InvalidByteRangeException>()));
  });

  test('surfaces truncated source reads and does not advance', () async {
    final reader = BoundedByteReader(_TruncatingSource(), ByteRange(0, 4));

    await expectLater(
      reader.readExact(4),
      throwsA(
        isA<TruncatedReadException>()
            .having((error) => error.expectedLength, 'expectedLength', 4)
            .having((error) => error.actualLength, 'actualLength', 3),
      ),
    );
    expect(reader.position, 0);
  });

  test('returns an isolated copy even for an aliasing source', () async {
    final source = _AliasingSource();
    final reader = BoundedByteReader(source, ByteRange(0, 2));

    final bytes = await reader.readExact(2);
    bytes[0] = 9;

    expect(source.bytes, [1, 2]);
  });
}

final class _TruncatingSource implements RandomAccessByteSource {
  @override
  Future<int> get length async => 4;

  @override
  Future<Uint8List> read(ByteRange range) async => Uint8List(range.length - 1);
}

final class _AliasingSource implements RandomAccessByteSource {
  final Uint8List bytes = Uint8List.fromList([1, 2]);

  @override
  Future<int> get length async => bytes.length;

  @override
  Future<Uint8List> read(ByteRange range) async => bytes;
}

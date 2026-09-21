import 'dart:typed_data';

import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('MemoryByteSource', () {
    test('reports length and reads exact ranges', () async {
      final source = MemoryByteSource([1, 2, 3, 4]);

      expect(await source.length, 4);
      expect(await source.read(ByteRange(1, 3)), [2, 3]);
      expect(await source.read(ByteRange(4, 4)), isEmpty);
    });

    test('rejects reads outside the source', () async {
      final source = MemoryByteSource([1, 2]);

      await expectLater(
        source.read(ByteRange(1, 3)),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
    });

    test('isolates source input and returned bytes', () async {
      final input = [1, 2, 3];
      final source = MemoryByteSource(input);
      input[1] = 99;

      final first = await source.read(ByteRange(0, 3));
      first[0] = 88;
      final second = await source.read(ByteRange(0, 3));

      expect(second, [1, 2, 3]);
    });
  });

  group('MemoryByteSink', () {
    test('appends and patches without changing length', () async {
      final sink = MemoryByteSink();
      await sink.append([1, 2, 3, 4]);
      await sink.writeAt(1, [8, 9]);

      expect(await sink.length, 4);
      expect(sink.toBytes(), [1, 8, 9, 4]);
    });

    test('permits empty writes at the end', () async {
      final sink = MemoryByteSink();
      await sink.append([1, 2]);
      await sink.writeAt(2, []);

      expect(sink.toBytes(), [1, 2]);
    });

    test('rejects patches beyond existing bytes', () async {
      final sink = MemoryByteSink();
      await sink.append([1, 2]);

      await expectLater(
        sink.writeAt(2, [3]),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
      await expectLater(
        sink.writeAt(-1, [3]),
        throwsA(isA<InvalidByteRangeException>()),
      );
    });

    test('validates byte values without partially mutating', () async {
      final sink = MemoryByteSink();
      await sink.append([1, 2]);

      await expectLater(sink.append([3, 256]), throwsRangeError);
      expect(sink.toBytes(), [1, 2]);
    });

    test('isolates appended input and snapshots', () async {
      final sink = MemoryByteSink();
      final input = [1, 2];
      await sink.append(input);
      input[0] = 9;

      final snapshot = sink.toBytes();
      snapshot[1] = 8;

      expect(sink.toBytes(), [1, 2]);
    });

    test('rejects mutation after close and allows repeated close', () async {
      final sink = MemoryByteSink();
      await sink.append([1]);
      await sink.close();
      await sink.close();

      expect(sink.isClosed, isTrue);
      await expectLater(
        sink.append([2]),
        throwsA(isA<ByteSinkClosedException>()),
      );
      await expectLater(
        sink.writeAt(0, [2]),
        throwsA(isA<ByteSinkClosedException>()),
      );
      expect(sink.toBytes(), [1]);
    });
  });

  group('copyByteRange', () {
    test('copies a range in bounded chunks', () async {
      final source = MemoryByteSource([0, 1, 2, 3, 4, 5]);
      final sink = MemoryByteSink();

      await copyByteRange(source, sink, ByteRange(1, 6), chunkSize: 2);

      expect(sink.toBytes(), [1, 2, 3, 4, 5]);
    });

    test('copies an empty range without writing', () async {
      final sink = MemoryByteSink();

      await copyByteRange(MemoryByteSource([1]), sink, ByteRange(1, 1));

      expect(sink.toBytes(), isEmpty);
    });

    test('rejects invalid chunk sizes', () async {
      await expectLater(
        copyByteRange(
          MemoryByteSource([1]),
          MemoryByteSink(),
          ByteRange(0, 1),
          chunkSize: 0,
        ),
        throwsArgumentError,
      );
    });

    test('surfaces truncated chunks without appending them', () async {
      final sink = MemoryByteSink();

      await expectLater(
        copyByteRange(_TruncatingSource(), sink, ByteRange(0, 2)),
        throwsA(isA<TruncatedReadException>()),
      );
      expect(sink.toBytes(), isEmpty);
    });
  });
}

final class _TruncatingSource implements RandomAccessByteSource {
  @override
  Future<int> get length async => 2;

  @override
  Future<Uint8List> read(ByteRange range) async => Uint8List(range.length - 1);
}

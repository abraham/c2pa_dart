import 'dart:async';

import 'package:c2pa_io/c2pa_io.dart' as io;
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('supports deterministic sparse reads beyond 4 GiB', () async {
    const fourGiB = 4 * 1024 * 1024 * 1024;
    final segment = SparseByteSegment(
      offset: fourGiB + 8,
      bytes: [0xde, 0xad, 0xbe, 0xef],
    );
    final first = SparseRandomAccessAsset(
      logicalLength: fourGiB + 1024,
      seed: 123,
      segments: [segment],
    );
    final second = SparseRandomAccessAsset(
      logicalLength: fourGiB + 1024,
      seed: 123,
      segments: [
        SparseByteSegment(offset: fourGiB + 8, bytes: [0xde, 0xad, 0xbe, 0xef]),
      ],
    );
    final differentSeed = SparseRandomAccessAsset(
      logicalLength: fourGiB + 1024,
      seed: 124,
    );
    final range = io.ByteRange(fourGiB + 4, fourGiB + 16);

    final firstRead = await first.read(range);
    final secondRead = await second.read(range);

    expect(await first.length, fourGiB + 1024);
    expect(firstRead, secondRead);
    expect(
      await first.read(io.ByteRange(fourGiB + 20, fourGiB + 24)),
      isNot(await differentSeed.read(io.ByteRange(fourGiB + 20, fourGiB + 24))),
    );
    expect(firstRead.sublist(4, 8), [0xde, 0xad, 0xbe, 0xef]);
    firstRead[0] ^= 0xff;
    expect(await first.read(range), secondRead);
  });

  test('patterned chunks restart their pattern at chunk boundaries', () async {
    final source = PatternedChunkSource(
      logicalLength: 32,
      pattern: [1, 2, 3],
      chunkSize: 4,
    );

    expect(await source.read(io.ByteRange(2, 8)), [3, 1, 1, 2, 3, 1]);
  });

  test('sources enforce logical and per-read bounds', () async {
    final source = SparseRandomAccessAsset(logicalLength: 100, maxReadBytes: 4);

    await expectLater(
      source.read(io.ByteRange(99, 101)),
      throwsA(isA<io.ByteRangeOutOfBoundsException>()),
    );
    await expectLater(source.read(io.ByteRange(0, 5)), throwsRangeError);
    expect(
      () => SparseRandomAccessAsset(
        logicalLength: 4,
        segments: [
          SparseByteSegment(offset: 3, bytes: [1, 2]),
        ],
      ),
      throwsArgumentError,
    );
  });

  test('instrumented source records ranges, bytes, and concurrency', () async {
    final gate = Completer<void>();
    final source = InstrumentedByteSource(
      PatternedChunkSource(logicalLength: 32, pattern: [7], chunkSize: 4),
      beforeRead: (_) => gate.future,
    );

    final first = source.read(io.ByteRange(0, 4));
    final second = source.read(io.ByteRange(8, 14));
    await Future<void>.delayed(Duration.zero);
    expect(source.activeReads, 2);
    expect(source.peakConcurrency, 2);
    gate.complete();
    await Future.wait([first, second]);

    expect(source.readCount, 2);
    expect(source.totalRequestedBytes, 10);
    expect(source.peakRequestedChunkSize, 6);
    expect(source.reads.map((read) => read.range), [
      io.ByteRange(0, 4),
      io.ByteRange(8, 14),
    ]);
    expect(source.reads.map((read) => read.concurrency), [1, 2]);
    expect(source.reads.every((read) => read.succeeded == true), isTrue);

    source.reset();
    expect(source.reads, isEmpty);
  });
}

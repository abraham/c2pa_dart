@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('streaming full-source hashing', () {
    final vectors = {
      HashAlgorithm.sha256:
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      HashAlgorithm.sha384:
          'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5b'
          'ed8086072ba1e7cc2358baeca134c825a7',
      HashAlgorithm.sha512:
          'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d3'
          '9a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54'
          'ca49f',
    };

    for (final entry in vectors.entries) {
      test('${entry.key.name} known vector', () async {
        final digest = await AssetHashEngine(chunkSize: 1)
            .digestSource(MemoryByteSource(ascii.encode('abc')), entry.key);
        expect(_hex(digest), entry.value);
      });
    }
  });

  test('hashes ordered inclusion ranges as one stream', () async {
    final source = MemoryByteSource(ascii.encode('abcdefgh'));
    final digest = await AssetHashEngine(chunkSize: 2).digestRanges(
      source,
      HashAlgorithm.sha256,
      [ByteRange(0, 2), ByteRange(4, 6)],
    );
    expect(digest, await HashAlgorithm.sha256.digest(ascii.encode('abef')));
  });

  test(
    'normalizes overlapping, adjacent, empty, and unordered exclusions',
    () async {
      final source = MemoryByteSource(ascii.encode('abcdefghij'));
      final digest = await AssetHashEngine(chunkSize: 2)
          .digestExcluding(source, HashAlgorithm.sha256, [
            ByteRange(6, 8),
            ByteRange(2, 5),
            ByteRange(4, 7),
            ByteRange(1, 1),
            ByteRange(8, 8),
          ]);
      expect(digest, await HashAlgorithm.sha256.digest(ascii.encode('abij')));
    },
  );

  test('rejects out-of-order and overlapping inclusion ranges', () async {
    final engine = AssetHashEngine();
    final source = MemoryByteSource(List<int>.filled(10, 0));
    await expectLater(
      engine.digestRanges(source, HashAlgorithm.sha256, [
        ByteRange(5, 8),
        ByteRange(2, 4),
      ]),
      throwsArgumentError,
    );
    await expectLater(
      engine.digestRanges(source, HashAlgorithm.sha256, [
        ByteRange(1, 6),
        ByteRange(5, 9),
      ]),
      throwsArgumentError,
    );
  });

  test('supports injected event bytes between source ranges', () async {
    final source = MemoryByteSource(ascii.encode('abcdef'));
    final injectedOffset = _uint64(0x100000002);
    final digest = await AssetHashEngine(chunkSize: 1)
        .digestEvents(source, HashAlgorithm.sha256, [
          AssetHashRangeEvent(ByteRange(0, 2)),
          AssetHashInjectedBytesEvent(injectedOffset),
          AssetHashRangeEvent(ByteRange(4, 6)),
        ]);
    expect(
      digest,
      await HashAlgorithm.sha256.digest([
        ...ascii.encode('ab'),
        ...injectedOffset,
        ...ascii.encode('ef'),
      ]),
    );
  });

  test('uses checked large offsets without reading skipped bytes', () async {
    const length = 0x10000000010;
    final source = _PatternSource(length);
    final range = ByteRange(length - 5, length);
    final digest = await AssetHashEngine(chunkSize: 2)
        .digestRanges(source, HashAlgorithm.sha512, [range]);
    expect(
      digest,
      await HashAlgorithm.sha512.digest(
        List<int>.generate(5, (index) => (range.start + index) & 0xff),
      ),
    );
    expect(source.bytesRead, 5);
  });

  test('detects source-length mutation', () async {
    final source = _ChangingLengthSource(ascii.encode('abcdef'));
    await expectLater(
      AssetHashEngine(chunkSize: 2).digestSource(source, HashAlgorithm.sha256),
      throwsA(isA<AssetHashSourceLengthChangedException>()),
    );
  });

  test('detects short reads despite the source contract', () async {
    await expectLater(
      AssetHashEngine(chunkSize: 4).digestSource(
        _ShortReadSource(ascii.encode('abcdef')),
        HashAlgorithm.sha256,
      ),
      throwsA(
        isA<AssetHashShortReadException>()
            .having((error) => error.expectedLength, 'expectedLength', 4)
            .having((error) => error.actualLength, 'actualLength', 3),
      ),
    );
  });

  test('supports cooperative cancellation between chunks', () async {
    var checks = 0;
    final source = _PatternSource(100);
    final engine = AssetHashEngine(
      chunkSize: 10,
      isCancelled: () => ++checks >= 4,
    );
    await expectLater(
      engine.digestSource(source, HashAlgorithm.sha256),
      throwsA(isA<AssetHashCancelledException>()),
    );
    expect(source.bytesRead, 20);
  });

  test('reports monotonic progress with exact totals', () async {
    final updates = <AssetHashProgress>[];
    await AssetHashEngine(chunkSize: 3, onProgress: updates.add).digestEvents(
      MemoryByteSource(ascii.encode('abcdefgh')),
      HashAlgorithm.sha256,
      [
        AssetHashRangeEvent(ByteRange(0, 5)),
        AssetHashInjectedBytesEvent([1, 2]),
        AssetHashRangeEvent(ByteRange(6, 8)),
      ],
    );
    expect(
      updates.map((update) => update.bytesProcessed),
      orderedEquals([3, 5, 7, 9]),
    );
    expect(updates.every((update) => update.totalBytes == 9), isTrue);
    expect(updates.last.fraction, 1);
    expect(updates[2].sourceRange, isNull);
  });

  test('computes independent BoxHash-style range digests', () async {
    final source = MemoryByteSource(ascii.encode('abcdefgh'));
    final ranges = [ByteRange(0, 3), ByteRange(3, 3), ByteRange(5, 8)];
    final results = await AssetHashEngine(chunkSize: 2)
        .digestRangesIndependently(source, HashAlgorithm.sha384, ranges);
    expect(results.map((result) => result.range), ranges);
    expect(
      results[0].digest,
      await HashAlgorithm.sha384.digest(ascii.encode('abc')),
    );
    expect(results[1].digest, await HashAlgorithm.sha384.digest(const []));
    expect(
      results[2].digest,
      await HashAlgorithm.sha384.digest(ascii.encode('fgh')),
    );
  });

  test('compares digests in constant-work style', () {
    expect(constantTimeDigestEquals([1, 2, 3], [1, 2, 3]), isTrue);
    expect(constantTimeDigestEquals([1, 2, 3], [1, 2, 4]), isFalse);
    expect(constantTimeDigestEquals([1, 2, 3], [1, 2]), isFalse);
    expect(constantTimeDigestEquals(const [], const []), isTrue);
  });

  test('rejects invalid chunk sizes and exclusion bounds', () async {
    expect(() => AssetHashEngine(chunkSize: 0), throwsArgumentError);
    await expectLater(
      AssetHashEngine().digestExcluding(
        MemoryByteSource([1, 2, 3]),
        HashAlgorithm.sha256,
        [ByteRange(2, 4)],
      ),
      throwsA(isA<ByteRangeOutOfBoundsException>()),
    );
  });
}

final class _PatternSource implements RandomAccessByteSource {
  _PatternSource(this.logicalLength);

  final int logicalLength;
  int bytesRead = 0;

  @override
  Future<int> get length async => logicalLength;

  @override
  Future<Uint8List> read(ByteRange range) async {
    if (range.end > logicalLength) {
      throw ByteRangeOutOfBoundsException(range, ByteRange(0, logicalLength));
    }
    bytesRead += range.length;
    return Uint8List.fromList(
      List<int>.generate(range.length, (index) => (range.start + index) & 0xff),
    );
  }
}

final class _ChangingLengthSource implements RandomAccessByteSource {
  _ChangingLengthSource(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  var _lengthReads = 0;

  @override
  Future<int> get length async =>
      ++_lengthReads == 1 ? _bytes.length : _bytes.length + 1;

  @override
  Future<Uint8List> read(ByteRange range) async =>
      Uint8List.fromList(_bytes.sublist(range.start, range.end));
}

final class _ShortReadSource implements RandomAccessByteSource {
  _ShortReadSource(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;

  @override
  Future<int> get length async => _bytes.length;

  @override
  Future<Uint8List> read(ByteRange range) async =>
      Uint8List.fromList(_bytes.sublist(range.start, range.end - 1));
}

List<int> _uint64(int value) => [
  for (var shift = 56; shift >= 0; shift -= 8) (value >> shift) & 0xff,
];

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

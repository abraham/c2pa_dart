import 'dart:io';

import 'package:c2pa_io/c2pa_io_vm.dart';
import 'package:c2pa_io/src/file_byte_io_test_hooks.dart';
import 'package:test/test.dart';

void main() {
  late Directory scratch;

  setUp(() async {
    scratch = Directory(
      '.dart_tool/c2pa_io_test-$pid-'
      '${DateTime.now().microsecondsSinceEpoch}',
    );
    await scratch.create(recursive: true);
  });

  tearDown(() async {
    if (await scratch.exists()) await scratch.delete(recursive: true);
  });

  group('FileByteSource', () {
    test('snapshots length and performs exact concurrent reads', () async {
      final file = File('${scratch.path}/source.bin');
      await file.writeAsBytes([0, 1, 2, 3, 4, 5]);
      final source = await FileByteSource.open(file.path);
      addTearDown(source.close);

      expect(await source.length, 6);
      final reads = await Future.wait([
        source.read(ByteRange(1, 4)),
        source.read(ByteRange(4, 6)),
        source.read(ByteRange(0, 1)),
      ]);
      expect(reads, [
        [1, 2, 3],
        [4, 5],
        [0],
      ]);
    });

    test('rejects out-of-bounds reads explicitly', () async {
      final file = File('${scratch.path}/source.bin');
      await file.writeAsBytes([1, 2]);
      final source = await FileByteSource.open(file.path);
      addTearDown(source.close);

      await expectLater(
        source.read(ByteRange(1, 3)),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
    });

    test('detects truncation or growth after opening', () async {
      final file = File('${scratch.path}/source.bin');
      await file.writeAsBytes([1, 2, 3, 4]);
      final source = await FileByteSource.open(file.path);
      addTearDown(source.close);

      await file.writeAsBytes([1, 2], mode: FileMode.write);

      await expectLater(
        source.length,
        throwsA(
          isA<ByteSourceChangedException>()
              .having((error) => error.expectedLength, 'expectedLength', 4)
              .having((error) => error.actualLength, 'actualLength', 2),
        ),
      );
      await expectLater(
        source.read(ByteRange(0, 1)),
        throwsA(isA<ByteSourceChangedException>()),
      );
    });

    test('has idempotent close and rejects later operations', () async {
      final file = File('${scratch.path}/source.bin');
      await file.writeAsBytes([1]);
      final source = await FileByteSource.open(file.path);

      await source.close();
      await source.close();

      await expectLater(
        source.length,
        throwsA(isA<ByteSourceClosedException>()),
      );
      await expectLater(
        source.read(ByteRange(0, 1)),
        throwsA(isA<ByteSourceClosedException>()),
      );
    });

    test('wraps file open failures in a typed exception', () async {
      await expectLater(
        FileByteSource.open('${scratch.path}/missing.bin'),
        throwsA(isA<ByteSourceIoException>()),
      );
    });
  });

  group('FileByteSink', () {
    test('stages, patches, truncates, and atomically commits', () async {
      final target = File('${scratch.path}/target.bin');
      await target.writeAsBytes([99, 98]);
      final sink = await FileByteSink.open(target.path);

      await sink.append([1, 2, 3, 4]);
      await sink.writeAt(1, [8, 9]);
      await sink.truncate(3);

      expect(await target.readAsBytes(), [99, 98]);
      expect(await sink.length, 3);

      await sink.close();
      await sink.close();
      expect(await target.readAsBytes(), [1, 8, 9]);
      expect(await sink.length, 3);
      await expectLater(
        sink.append([4]),
        throwsA(isA<ByteSinkClosedException>()),
      );
      expect(scratch.listSync().whereType<File>().map((file) => file.path), [
        target.path,
      ]);
    });

    test('can grow by truncation and appends at the new end', () async {
      final target = File('${scratch.path}/target.bin');
      final sink = await FileByteSink.open(target.path);

      await sink.append([1]);
      await sink.truncate(3);
      await sink.append([4]);
      await sink.close();

      expect(await target.readAsBytes(), [1, 0, 0, 4]);
    });

    test('rejects invalid patches without changing staged length', () async {
      final sink = await FileByteSink.open('${scratch.path}/target.bin');
      addTearDown(sink.abort);
      await sink.append([1, 2]);

      await expectLater(
        sink.writeAt(2, [3]),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
      await expectLater(
        sink.writeAt(-1, [3]),
        throwsA(isA<InvalidByteRangeException>()),
      );
      expect(await sink.length, 2);
    });

    test('abort discards the stage and preserves the destination', () async {
      final target = File('${scratch.path}/target.bin');
      await target.writeAsBytes([7]);
      final sink = await FileByteSink.open(target.path);
      await sink.append([1, 2, 3]);

      await sink.abort();
      await sink.abort();

      expect(await target.readAsBytes(), [7]);
      expect(scratch.listSync().whereType<File>().map((file) => file.path), [
        target.path,
      ]);
      await expectLater(
        sink.append([4]),
        throwsA(isA<ByteSinkClosedException>()),
      );
    });

    test(
      'abort leaves a replacement installed after staging ownership',
      () async {
        final target = File('${scratch.path}/target.bin');
        late File staging;
        final sink = await FileByteSink.open(
          target.path,
          testHooks: FileByteSinkTestHooks(
            afterStagingOwnershipEstablished: (file) async {
              staging = file;
              await file.delete();
              await file.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.abort(), throwsA(isA<ByteSinkIoException>()));

        expect(await staging.readAsBytes(), [7, 8]);
        expect(await target.exists(), isFalse);
      },
    );

    test(
      'commit leaves a replacement installed before staging commit',
      () async {
        final target = File('${scratch.path}/target.bin');
        late File staging;
        final sink = await FileByteSink.open(
          target.path,
          testHooks: FileByteSinkTestHooks(
            beforeStagingCommit: (file) async {
              staging = file;
              await file.delete();
              await file.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await staging.readAsBytes(), [7, 8]);
        expect(await target.exists(), isFalse);
      },
    );

    test(
      'cleanup leaves a replacement installed at the staging path',
      () async {
        final target = File('${scratch.path}/target.bin');
        late File staging;
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            beforeStagingCleanup: (file) async {
              staging = file;
              await file.delete();
              await file.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await target.readAsBytes(), [1, 2, 3]);
        expect(await staging.readAsBytes(), [7, 8]);
      },
    );

    test('cleanup does not follow or delete a staging symlink', () async {
      final target = File('${scratch.path}/target.bin');
      final symlinkTarget = File('${scratch.path}/symlink-target.bin');
      await symlinkTarget.writeAsBytes([7, 8]);
      late File staging;
      final sink = await FileByteSink.open(
        target.path,
        testHooks: FileByteSinkTestHooks(
          beforeStagingCleanup: (file) async {
            staging = file;
            await file.delete();
            await Link(file.path).create(symlinkTarget.absolute.path);
          },
        ),
      );
      await sink.append([1, 2, 3]);

      await expectLater(sink.abort(), throwsA(isA<ByteSinkIoException>()));

      expect(await symlinkTarget.readAsBytes(), [7, 8]);
      expect(await Link(staging.path).target(), symlinkTarget.absolute.path);
      expect(await target.exists(), isFalse);
    });

    test(
      'refuses an existing destination and cleans its staging file',
      () async {
        final target = File('${scratch.path}/target.bin');
        await target.writeAsBytes([7]);
        final sink = await FileByteSink.open(target.path, overwrite: false);
        await sink.append([1]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));
        expect(await target.readAsBytes(), [7]);
        expect(scratch.listSync().whereType<File>().map((file) => file.path), [
          target.path,
        ]);
      },
    );

    test('no-clobber commit reserves and writes a new destination', () async {
      final target = File('${scratch.path}/target.bin');
      final sink = await FileByteSink.open(target.path, overwrite: false);
      await sink.append([1, 2, 3]);

      await sink.close();

      expect(await target.readAsBytes(), [1, 2, 3]);
      expect(scratch.listSync().whereType<File>().map((file) => file.path), [
        target.path,
      ]);
    });

    test(
      'no-clobber commit loses a deterministic creation race safely',
      () async {
        final target = File('${scratch.path}/target.bin');
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            beforeNoClobberReservation: (target) async {
              await target.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await target.readAsBytes(), [7, 8]);
        expect(scratch.listSync().whereType<File>().map((file) => file.path), [
          target.path,
        ]);
      },
    );

    test(
      'replacement file between reservation and open is untouched',
      () async {
        final target = File('${scratch.path}/target.bin');
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            afterNoClobberReservation: (target) async {
              await target.delete();
              await target.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await target.readAsBytes(), [7, 8]);
      },
    );

    test(
      'replacement symlink between reservation and open is not followed',
      () async {
        final target = File('${scratch.path}/target.bin');
        final symlinkTarget = File('${scratch.path}/symlink-target.bin');
        await symlinkTarget.writeAsBytes([7, 8]);
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            afterNoClobberReservation: (target) async {
              await target.delete();
              await Link(target.path).create(symlinkTarget.absolute.path);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await symlinkTarget.readAsBytes(), [7, 8]);
        expect(await Link(target.path).target(), symlinkTarget.absolute.path);
      },
    );

    test('replacement during write is untouched and not deleted', () async {
      final target = File('${scratch.path}/target.bin');
      final sink = await FileByteSink.open(
        target.path,
        overwrite: false,
        testHooks: FileByteSinkTestHooks(
          duringNoClobberWrite: (target) async {
            await target.delete();
            await target.writeAsBytes([7, 8]);
          },
        ),
      );
      await sink.append([1, 2, 3]);

      await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

      expect(await target.readAsBytes(), [7, 8]);
    });

    test(
      'replacement after destination ownership verification is untouched',
      () async {
        final target = File('${scratch.path}/target.bin');
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            afterNoClobberOwnershipVerified: (target) async {
              await target.delete();
              await target.writeAsBytes([7, 8]);
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await target.readAsBytes(), [7, 8]);
      },
    );

    test(
      'failed reserved commit leaves placeholder but removes staging',
      () async {
        final target = File('${scratch.path}/target.bin');
        final sink = await FileByteSink.open(
          target.path,
          overwrite: false,
          testHooks: FileByteSinkTestHooks(
            afterNoClobberOwnershipVerified: (_) {
              throw FileSystemException('Injected commit failure');
            },
          ),
        );
        await sink.append([1, 2, 3]);

        await expectLater(sink.close(), throwsA(isA<ByteSinkIoException>()));

        expect(await target.exists(), isTrue);
        expect(await target.length(), 32);
        expect(scratch.listSync().whereType<File>().map((file) => file.path), [
          target.path,
        ]);
      },
    );

    test('wraps staging failures in a typed exception', () async {
      await expectLater(
        FileByteSink.open('${scratch.path}/missing/target.bin'),
        throwsA(isA<ByteSinkIoException>()),
      );
    });
  });
}

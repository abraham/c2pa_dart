import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';
import 'byte_sink.dart';
import 'file_byte_io_test_hooks.dart';
import 'random_access_byte_source.dart';

/// A file-backed random-access byte source with stable-length checks.
final class FileByteSource implements RandomAccessByteSource {
  FileByteSource._(this._file, this._handle, this._snapshotLength);

  final File _file;
  final RandomAccessFile _handle;
  final int _snapshotLength;
  Future<void> _pending = Future.value();
  bool _closed = false;

  /// Opens [path] for random-access reads and snapshots its initial length.
  static Future<FileByteSource> open(String path) async {
    final file = File(path);
    RandomAccessFile? handle;
    try {
      handle = await file.open(mode: FileMode.read);
      final length = await handle.length();
      ByteRange(0, length);
      return FileByteSource._(file, handle, length);
    } on ByteIoException {
      await handle?.close();
      rethrow;
    } on FileSystemException catch (error) {
      await handle?.close();
      throw ByteSourceIoException(
        operation: 'open byte source',
        cause: error,
        location: path,
      );
    }
  }

  @override
  Future<int> get length => _synchronized(() async {
    await _verifyLength();
    return _snapshotLength;
  });

  @override
  Future<Uint8List> read(ByteRange range) => _synchronized(() async {
    final available = ByteRange(0, _snapshotLength);
    if (!available.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, available);
    }

    await _verifyLength();
    try {
      await _handle.setPosition(range.start);
      final bytes = await _handle.read(range.length);
      if (bytes.length != range.length) {
        throw TruncatedReadException(
          range: range,
          expectedLength: range.length,
          actualLength: bytes.length,
        );
      }
      await _verifyLength();
      return Uint8List.fromList(bytes);
    } on ByteIoException {
      rethrow;
    } on FileSystemException catch (error) {
      throw ByteSourceIoException(
        operation: 'read bytes',
        cause: error,
        location: _file.path,
      );
    }
  });

  /// Closes the underlying file handle.
  Future<void> close() => _synchronized(() async {
    if (_closed) return;
    _closed = true;
    try {
      await _handle.close();
    } on FileSystemException catch (error) {
      throw ByteSourceIoException(
        operation: 'close byte source',
        cause: error,
        location: _file.path,
      );
    }
  }, allowClosed: true);

  Future<void> _verifyLength() async {
    int actualLength;
    try {
      actualLength = await _handle.length();
    } on FileSystemException catch (error) {
      throw ByteSourceIoException(
        operation: 'check byte source length',
        cause: error,
        location: _file.path,
      );
    }
    if (actualLength != _snapshotLength) {
      throw ByteSourceChangedException(
        expectedLength: _snapshotLength,
        actualLength: actualLength,
      );
    }
  }

  Future<T> _synchronized<T>(
    Future<T> Function() action, {
    bool allowClosed = false,
  }) {
    final previous = _pending;
    final released = Completer<void>();
    _pending = released.future;
    return previous
        .then((_) {
          if (_closed && !allowClosed) {
            throw const ByteSourceClosedException();
          }
          return action();
        })
        .whenComplete(released.complete);
  }
}

/// A staged file sink that commits its staging file on [close].
///
/// With overwriting enabled, the staging file is atomically renamed over the
/// destination after its per-staging ownership marker, metadata, and contents
/// have been verified. Cleanup uses the same evidence and fails closed: if the
/// staging pathname cannot be shown to still name the owned file, it is left in
/// place and cleanup failure is reported rather than risking deletion of a
/// replacement.
///
/// With overwriting disabled, this API does **not** promise strict atomic
/// no-clobber semantics. Portable Dart APIs provide neither an atomic
/// no-replace rename nor an exclusive create that returns an open handle.
/// Instead, close exclusively creates the destination, reopens it without
/// truncation, and establishes probabilistic ownership with a cryptographically
/// random marker before writing through the retained handle.
///
/// A path replacement detected at any checkpoint fails closed and is neither
/// modified nor deleted. Failed commits deliberately leave the reservation
/// behind because portable Dart cannot safely unlink a path after checking it
/// without another replacement race. The destination can also be briefly
/// visible as an empty, marked, or partially written file.
///
/// There are unavoidable portable TOCTOU limitations between metadata/content
/// verification and opening, renaming, or deleting a pathname: `dart:io`
/// exposes neither stable file identity nor atomic create-and-open/no-replace
/// rename. In particular, a replacement that reproduces the verified metadata
/// and contents, or is installed after verification, cannot be distinguished.
/// Platforms needing strict filesystem-level guarantees must provide native
/// atomic primitives outside this implementation.
final class FileByteSink implements PatchableByteSink {
  FileByteSink._(
    this._target,
    this._stagingOwnership,
    this._handle,
    this._overwrite,
    this._testHooks,
  );

  final File _target;
  final _StagingOwnership _stagingOwnership;
  File get _staging => _stagingOwnership.file;
  final RandomAccessFile _handle;
  final bool _overwrite;
  final FileByteSinkTestHooks? _testHooks;
  Future<void> _pending = Future.value();
  int _length = 0;
  _FileSinkState _state = _FileSinkState.open;
  bool _handleClosed = false;
  _FileFingerprint? _stagingSnapshot;
  bool _cleanupHookInvoked = false;

  /// Opens a staged sink that commits to [path] when [close] succeeds.
  static Future<FileByteSink> open(
    String path, {
    bool overwrite = true,
    FileByteSinkTestHooks? testHooks,
  }) async {
    final target = File(path);
    _StagingOwnership? stagingOwnership;
    RandomAccessFile? handle;
    try {
      stagingOwnership = await _createStagingFile(target);
      handle = await stagingOwnership.file.open(mode: FileMode.write);
      stagingOwnership = await stagingOwnership.withCurrentFileFingerprint();
      await testHooks?.afterStagingOwnershipEstablished?.call(
        stagingOwnership.file,
      );
      return FileByteSink._(
        target,
        stagingOwnership,
        handle,
        overwrite,
        testHooks,
      );
    } on Object catch (error) {
      await handle?.close();
      Object? cleanupError;
      if (stagingOwnership != null) {
        try {
          await stagingOwnership.deleteIfOwned();
        } on Object catch (caught) {
          cleanupError = caught;
        }
      }
      throw ByteSinkIoException(
        operation: 'open staged byte sink',
        cause: cleanupError == null
            ? error
            : _CommitAndCleanupException(error, cleanupError),
        location: path,
      );
    }
  }

  @override
  Future<int> get length =>
      _synchronized(() async => _length, allowClosed: true);

  @override
  Future<void> append(List<int> bytes) => _synchronized(() async {
    _validateBytes(bytes);
    final nextLength = ByteRange.checkedAdd(_length, bytes.length);
    try {
      await _handle.setPosition(_length);
      await _handle.writeFrom(bytes);
      _length = nextLength;
    } on FileSystemException catch (error) {
      throw ByteSinkIoException(
        operation: 'append bytes',
        cause: error,
        location: _staging.path,
      );
    }
  });

  @override
  Future<void> writeAt(int offset, List<int> bytes) => _synchronized(() async {
    _validateBytes(bytes);
    final range = ByteRange.fromStartAndLength(offset, bytes.length);
    final available = ByteRange(0, _length);
    if (!available.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, available);
    }
    try {
      await _handle.setPosition(offset);
      await _handle.writeFrom(bytes);
    } on FileSystemException catch (error) {
      throw ByteSinkIoException(
        operation: 'patch bytes',
        cause: error,
        location: _staging.path,
      );
    }
  });

  /// Truncates the staged output to [length] bytes.
  Future<void> truncate(int length) => _synchronized(() async {
    ByteRange(0, length);
    try {
      await _handle.truncate(length);
      _length = length;
    } on FileSystemException catch (error) {
      throw ByteSinkIoException(
        operation: 'truncate staged bytes',
        cause: error,
        location: _staging.path,
      );
    }
  });

  @override
  Future<void> close() => _synchronized(() async {
    if (_state == _FileSinkState.committed) return;
    if (_state != _FileSinkState.open) {
      throw const ByteSinkClosedException();
    }

    try {
      await _handle.flush();
      _stagingSnapshot = await _captureStagingSnapshot();
      await _testHooks?.beforeStagingCommit?.call(_staging);
      if (_overwrite) {
        await _closeHandle();
        await _stagingOwnership.verifyOwned(_stagingSnapshot!);
        await _staging.rename(_target.path);
        await _stagingOwnership.deleteMarkerIfOwned();
      } else {
        await _commitWithoutOverwrite();
      }
      _state = _FileSinkState.committed;
    } on Object catch (error) {
      _state = _FileSinkState.failed;
      Object? cleanupError;
      try {
        await _cleanupAfterFailedCommit();
      } on Object catch (caught) {
        cleanupError = caught;
      }
      throw ByteSinkIoException(
        operation: 'commit staged bytes',
        cause: cleanupError == null
            ? error
            : _CommitAndCleanupException(error, cleanupError),
        location: _target.path,
      );
    }
  }, allowClosed: true);

  Future<void> _commitWithoutOverwrite() async {
    await _testHooks?.beforeNoClobberReservation?.call(_target);

    RandomAccessFile? destinationHandle;
    try {
      await _target.create(exclusive: true);
      final reservation = await _reservationFingerprint(_target);
      await _testHooks?.afterNoClobberReservation?.call(_target);

      await _verifyReservationPath(_target, reservation);
      destinationHandle = await _target.open(mode: FileMode.append);
      if (await destinationHandle.length() != 0) {
        throw FileSystemException(
          'No-clobber reservation changed before it was opened',
          _target.path,
        );
      }
      await _verifyReservationPath(_target, reservation);

      final marker = _newReservationMarker();
      await destinationHandle.writeFrom(marker);
      await destinationHandle.flush();
      await _verifyHandleMarker(destinationHandle, marker);
      await _verifyMarkedPath(_target, marker);

      await _testHooks?.afterNoClobberOwnershipVerified?.call(_target);

      await _copyStagingTo(destinationHandle, truncateFirst: true);
      await destinationHandle.flush();
      await _verifyCommittedPath(_target, destinationHandle);

      await _closeHandle();
      await _deleteStagingIfOwned();
    } finally {
      await destinationHandle?.close();
    }
  }

  Future<void> _copyStagingTo(
    RandomAccessFile destination, {
    required bool truncateFirst,
  }) async {
    if (truncateFirst) {
      await destination.truncate(0);
      await destination.setPosition(0);
    }
    await _handle.setPosition(0);
    var invokedWriteHook = false;
    while (true) {
      final bytes = await _handle.read(64 * 1024);
      if (bytes.isEmpty) break;
      await destination.writeFrom(bytes);
      if (!invokedWriteHook) {
        invokedWriteHook = true;
        await _testHooks?.duringNoClobberWrite?.call(_target);
      }
    }
  }

  static Future<_ReservationFingerprint> _reservationFingerprint(
    File target,
  ) async {
    final type = await FileSystemEntity.type(target.path, followLinks: false);
    final stat = await target.stat();
    if (type != FileSystemEntityType.file || stat.size != 0) {
      throw FileSystemException(
        'Exclusive no-clobber reservation is not an empty regular file',
        target.path,
      );
    }
    return _ReservationFingerprint(
      modified: stat.modified,
      changed: stat.changed,
      mode: stat.mode,
    );
  }

  static Future<void> _verifyReservationPath(
    File target,
    _ReservationFingerprint expected,
  ) async {
    if (await FileSystemEntity.type(target.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'No-clobber reservation was replaced by a non-file',
        target.path,
      );
    }
    final stat = await target.stat();
    if (stat.size != 0 ||
        stat.modified != expected.modified ||
        stat.changed != expected.changed ||
        stat.mode != expected.mode) {
      throw FileSystemException(
        'No-clobber reservation identity changed',
        target.path,
      );
    }
  }

  static Uint8List _newReservationMarker() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(32, (_) => random.nextInt(256)),
    );
  }

  static Future<void> _verifyHandleMarker(
    RandomAccessFile handle,
    Uint8List marker,
  ) async {
    if (await handle.length() != marker.length) {
      throw const FileSystemException(
        'No-clobber reservation handle changed while marking',
      );
    }
    await handle.setPosition(0);
    final actual = await handle.read(marker.length);
    if (!_bytesEqual(actual, marker)) {
      throw const FileSystemException(
        'No-clobber reservation marker verification failed',
      );
    }
  }

  static Future<void> _verifyMarkedPath(File target, Uint8List marker) async {
    if (await FileSystemEntity.type(target.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'No-clobber reservation was replaced while marking',
        target.path,
      );
    }
    final reader = await target.open(mode: FileMode.read);
    try {
      if (await reader.length() != marker.length ||
          !_bytesEqual(await reader.read(marker.length), marker)) {
        throw FileSystemException(
          'No-clobber reservation marker is not present at the destination',
          target.path,
        );
      }
    } finally {
      await reader.close();
    }
  }

  Future<void> _verifyCommittedPath(
    File target,
    RandomAccessFile destination,
  ) async {
    if (await FileSystemEntity.type(target.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'No-clobber destination was replaced during commit',
        target.path,
      );
    }
    final reader = await target.open(mode: FileMode.read);
    try {
      final expectedLength = await destination.length();
      if (await reader.length() != expectedLength) {
        throw FileSystemException(
          'No-clobber destination changed during commit',
          target.path,
        );
      }
      await destination.setPosition(0);
      while (true) {
        final expected = await destination.read(64 * 1024);
        if (expected.isEmpty) break;
        final actual = await reader.read(expected.length);
        if (!_bytesEqual(actual, expected)) {
          throw FileSystemException(
            'No-clobber destination changed during commit',
            target.path,
          );
        }
      }
    } finally {
      await reader.close();
    }
  }

  static bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    var difference = 0;
    for (var index = 0; index < left.length; index++) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }

  Future<void> _cleanupAfterFailedCommit() async {
    Object? ownershipError;
    if (_stagingSnapshot == null && !_handleClosed) {
      try {
        await _handle.flush();
        _stagingSnapshot = await _captureStagingSnapshot();
      } on Object catch (error) {
        ownershipError = error;
      }
    }
    try {
      await _closeHandle();
    } on FileSystemException {
      // Continue cleanup so a close failure does not leak the staging file.
    }
    if (ownershipError != null || _stagingSnapshot == null) {
      await _stagingOwnership.deleteMarkerIfOwned();
      throw FileSystemException(
        'Staging cleanup refused because ownership could not be established'
        '${ownershipError == null ? '' : ': $ownershipError'}',
        _staging.path,
      );
    }
    await _deleteStagingIfOwned();
  }

  Future<void> _closeHandle() async {
    if (_handleClosed) return;
    await _handle.close();
    _handleClosed = true;
  }

  Future<_FileFingerprint> _captureStagingSnapshot() async {
    await _stagingOwnership.verifyMarker();
    if (await FileSystemEntity.type(_staging.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'Staging pathname no longer names a regular file',
        _staging.path,
      );
    }

    final before = _FileFingerprint.fromStat(await _staging.stat());
    if (before.size != _length || await _handle.length() != _length) {
      throw FileSystemException(
        'Staging pathname length does not match the owned handle',
        _staging.path,
      );
    }

    final reader = await _staging.open(mode: FileMode.read);
    try {
      await _handle.setPosition(0);
      while (true) {
        final expected = await _handle.read(64 * 1024);
        if (expected.isEmpty) break;
        if (!_bytesEqual(await reader.read(expected.length), expected)) {
          throw FileSystemException(
            'Staging pathname contents do not match the owned handle',
            _staging.path,
          );
        }
      }
    } finally {
      await reader.close();
    }

    final after = _FileFingerprint.fromStat(await _staging.stat());
    if (after != before) {
      throw FileSystemException(
        'Staging pathname changed during ownership verification',
        _staging.path,
      );
    }
    return after;
  }

  Future<void> _deleteStagingIfOwned() async {
    if (!_cleanupHookInvoked) {
      _cleanupHookInvoked = true;
      await _testHooks?.beforeStagingCleanup?.call(_staging);
    }
    await _stagingOwnership.deleteIfOwned(snapshot: _stagingSnapshot);
  }

  /// Discards staged bytes. Calling this more than once is harmless.
  Future<void> abort() => _synchronized(() async {
    if (_state == _FileSinkState.aborted) return;
    if (_state == _FileSinkState.committed) {
      throw const ByteSinkClosedException();
    }
    try {
      Object? ownershipError;
      if (_stagingSnapshot == null && !_handleClosed) {
        try {
          await _handle.flush();
          _stagingSnapshot = await _captureStagingSnapshot();
        } on Object catch (error) {
          ownershipError = error;
        }
      }
      if (!_handleClosed) {
        await _handle.close();
        _handleClosed = true;
      }
      _state = _FileSinkState.aborted;
      if (ownershipError != null || _stagingSnapshot == null) {
        await _stagingOwnership.deleteMarkerIfOwned();
        throw FileSystemException(
          'Staging cleanup refused because ownership could not be established'
          '${ownershipError == null ? '' : ': $ownershipError'}',
          _staging.path,
        );
      }
      await _deleteStagingIfOwned();
    } on FileSystemException catch (error) {
      throw ByteSinkIoException(
        operation: 'discard staged bytes',
        cause: error,
        location: _staging.path,
      );
    }
  }, allowClosed: true);

  Future<T> _synchronized<T>(
    Future<T> Function() action, {
    bool allowClosed = false,
  }) {
    final previous = _pending;
    final released = Completer<void>();
    _pending = released.future;
    return previous
        .then((_) {
          if (_state != _FileSinkState.open && !allowClosed) {
            throw const ByteSinkClosedException();
          }
          return action();
        })
        .whenComplete(released.complete);
  }

  static Future<_StagingOwnership> _createStagingFile(File target) async {
    final random = Random.secure();
    for (var attempt = 0; attempt < 100; attempt++) {
      final suffix = random.nextInt(0x7fffffff).toRadixString(16);
      final candidate = File('${target.path}.c2pa-stage-$pid-$suffix');
      final marker = File('${candidate.path}.owner');
      try {
        await candidate.create(exclusive: true);
      } on PathExistsException {
        continue;
      }

      final token = _newReservationMarker();
      try {
        await marker.create(exclusive: true);
        await marker.writeAsBytes(token, mode: FileMode.write);
        final ownership = await _StagingOwnership.create(
          candidate,
          marker,
          token,
        );
        return ownership;
      } on Object catch (error) {
        // Without the independently created marker and verified metadata,
        // portable Dart cannot prove the pathname is still ours. Leave it.
        throw FileSystemException(
          'Unable to establish staging ownership atomically; '
          'the staging pathname was left in place: $error',
          candidate.path,
        );
      }
    }
    throw FileSystemException(
      'Unable to allocate a unique staging file',
      target.path,
    );
  }

  static void _validateBytes(List<int> bytes) {
    for (final byte in bytes) {
      if (byte < 0 || byte > 255) {
        throw RangeError.range(byte, 0, 255, 'byte');
      }
    }
  }
}

enum _FileSinkState { open, committed, aborted, failed }

final class _ReservationFingerprint {
  const _ReservationFingerprint({
    required this.modified,
    required this.changed,
    required this.mode,
  });

  final DateTime modified;
  final DateTime changed;
  final int mode;
}

final class _FileFingerprint {
  const _FileFingerprint({
    required this.size,
    required this.modified,
    required this.changed,
    required this.mode,
  });

  factory _FileFingerprint.fromStat(FileStat stat) => _FileFingerprint(
    size: stat.size,
    modified: stat.modified,
    changed: stat.changed,
    mode: stat.mode,
  );

  final int size;
  final DateTime modified;
  final DateTime changed;
  final int mode;

  @override
  bool operator ==(Object other) =>
      other is _FileFingerprint &&
      size == other.size &&
      modified == other.modified &&
      changed == other.changed &&
      mode == other.mode;

  @override
  int get hashCode => Object.hash(size, modified, changed, mode);
}

final class _StagingOwnership {
  const _StagingOwnership._(
    this.file,
    this.marker,
    this.token,
    this.initialFingerprint,
    this.markerFingerprint,
  );

  static Future<_StagingOwnership> create(
    File file,
    File marker,
    Uint8List token,
  ) async {
    if (await FileSystemEntity.type(file.path, followLinks: false) !=
            FileSystemEntityType.file ||
        await file.length() != 0) {
      throw FileSystemException(
        'New staging pathname is not an empty regular file',
        file.path,
      );
    }
    if (await FileSystemEntity.type(marker.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'Staging ownership marker is not a regular file',
        marker.path,
      );
    }
    final actual = await marker.readAsBytes();
    if (!FileByteSink._bytesEqual(actual, token)) {
      throw FileSystemException(
        'Staging ownership marker verification failed',
        marker.path,
      );
    }
    return _StagingOwnership._(
      file,
      marker,
      token,
      _FileFingerprint.fromStat(await file.stat()),
      _FileFingerprint.fromStat(await marker.stat()),
    );
  }

  final File file;
  final File marker;
  final Uint8List token;
  final _FileFingerprint initialFingerprint;
  final _FileFingerprint markerFingerprint;

  Future<_StagingOwnership> withCurrentFileFingerprint() async {
    await verifyMarker();
    if (await FileSystemEntity.type(file.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'Staging pathname was replaced before opening completed',
        file.path,
      );
    }
    return _StagingOwnership._(
      file,
      marker,
      token,
      _FileFingerprint.fromStat(await file.stat()),
      markerFingerprint,
    );
  }

  Future<void> verifyMarker() async {
    if (await FileSystemEntity.type(marker.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'Staging ownership marker was replaced by a non-file',
        marker.path,
      );
    }
    final before = _FileFingerprint.fromStat(await marker.stat());
    final contents = await marker.readAsBytes();
    final after = _FileFingerprint.fromStat(await marker.stat());
    if (before != markerFingerprint ||
        after != before ||
        !FileByteSink._bytesEqual(contents, token)) {
      throw FileSystemException(
        'Staging ownership marker changed',
        marker.path,
      );
    }
  }

  Future<void> verifyOwned(_FileFingerprint expected) async {
    await verifyMarker();
    if (await FileSystemEntity.type(file.path, followLinks: false) !=
        FileSystemEntityType.file) {
      throw FileSystemException(
        'Staging pathname was replaced by a non-file',
        file.path,
      );
    }
    if (_FileFingerprint.fromStat(await file.stat()) != expected) {
      throw FileSystemException('Staging pathname changed', file.path);
    }
  }

  Future<void> deleteIfOwned({_FileFingerprint? snapshot}) async {
    await verifyOwned(snapshot ?? initialFingerprint);
    await file.delete();
    await deleteMarkerIfOwned();
  }

  Future<void> deleteMarkerIfOwned() async {
    try {
      await verifyMarker();
      await marker.delete();
    } on PathNotFoundException {
      // Already absent.
    }
  }
}

final class _CommitAndCleanupException implements Exception {
  const _CommitAndCleanupException(this.commitError, this.cleanupError);

  final Object commitError;
  final Object cleanupError;

  @override
  String toString() =>
      'Commit failed: $commitError; staging cleanup also failed: $cleanupError';
}

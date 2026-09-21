import 'dart:typed_data';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';

abstract interface class WritableByteSink {
  Future<int> get length;

  Future<void> append(List<int> bytes);

  Future<void> close();
}

abstract interface class PatchableByteSink implements WritableByteSink {
  /// Replaces existing bytes beginning at [offset] without changing the length.
  Future<void> writeAt(int offset, List<int> bytes);
}

final class MemoryByteSink implements PatchableByteSink {
  final List<int> _bytes = [];
  bool _closed = false;

  bool get isClosed => _closed;

  @override
  Future<int> get length async => _bytes.length;

  @override
  Future<void> append(List<int> bytes) async {
    _ensureOpen();
    _validateBytes(bytes);
    ByteRange.checkedAdd(_bytes.length, bytes.length);
    _bytes.addAll(bytes);
  }

  @override
  Future<void> writeAt(int offset, List<int> bytes) async {
    _ensureOpen();
    _validateBytes(bytes);
    final range = ByteRange.fromStartAndLength(offset, bytes.length);
    final available = ByteRange(0, _bytes.length);
    if (!available.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, available);
    }
    _bytes.setRange(range.start, range.end, bytes);
  }

  /// Returns an isolated snapshot of the bytes written so far.
  Uint8List toBytes() => Uint8List.fromList(_bytes);

  @override
  Future<void> close() async {
    _closed = true;
  }

  void _ensureOpen() {
    if (_closed) throw const ByteSinkClosedException();
  }

  static void _validateBytes(List<int> bytes) {
    for (final byte in bytes) {
      if (byte < 0 || byte > 255) {
        throw RangeError.range(byte, 0, 255, 'byte');
      }
    }
  }
}

import 'dart:js_interop';
import 'dart:typed_data';

import 'package:web/web.dart';

import 'byte_io_exceptions.dart';
import 'byte_range.dart';
import 'random_access_byte_source.dart';

/// A browser [Blob]-backed random-access byte source.
final class BlobByteSource implements RandomAccessByteSource {
  /// Creates a source that reads the [Blob] in chunks up to [chunkSize].
  BlobByteSource(this._blob, {this.chunkSize = 4 * 1024 * 1024})
    : _bounds = ByteRange(0, _blob.size) {
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
  }

  final Blob _blob;
  final ByteRange _bounds;

  /// Maximum number of bytes requested from the [Blob] in a single slice.
  final int chunkSize;

  @override
  Future<int> get length async => _bounds.length;

  @override
  Future<Uint8List> read(ByteRange range) async {
    if (!_bounds.containsRange(range)) {
      throw ByteRangeOutOfBoundsException(range, _bounds);
    }

    final result = Uint8List(range.length);
    var sourceOffset = range.start;
    var destinationOffset = 0;
    while (sourceOffset < range.end) {
      final remaining = range.end - sourceOffset;
      final count = remaining < chunkSize ? remaining : chunkSize;
      final end = sourceOffset + count;
      Uint8List bytes;
      try {
        final buffer = await _blob
            .slice(sourceOffset, end)
            .arrayBuffer()
            .toDart;
        bytes = buffer.toDart.asUint8List();
      } catch (error) {
        throw ByteSourceIoException(operation: 'read Blob bytes', cause: error);
      }
      if (bytes.length != count) {
        throw TruncatedReadException(
          range: ByteRange(sourceOffset, end),
          expectedLength: count,
          actualLength: bytes.length,
        );
      }
      result.setRange(destinationOffset, destinationOffset + count, bytes);
      sourceOffset = end;
      destinationOffset += count;
    }
    return result;
  }
}

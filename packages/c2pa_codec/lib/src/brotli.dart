import 'dart:typed_data';

import 'brotli_vendor/decoder/decode.dart' as vendor;
import 'brotli_vendor/exception.dart' as vendor;
import 'errors.dart';

/// Decodes one Brotli stream with a mandatory output-size limit.
///
/// The decoder stops while producing the first byte beyond [maxOutputBytes];
/// it never accumulates the full oversized output.
Uint8List decodeBrotli(List<int> input, {required int maxOutputBytes}) {
  if (maxOutputBytes < 0) {
    throw const BrotliDecodingException(
      BrotliDecodingErrorCode.invalidLimit,
      'maxOutputBytes must not be negative',
    );
  }
  if (input.any((byte) => byte < 0 || byte > 0xff)) {
    throw const BrotliDecodingException(
      BrotliDecodingErrorCode.malformed,
      'Brotli input contains a value outside the byte range',
    );
  }
  final bytes = Uint8List.fromList(input);
  try {
    return vendor.decodeWithLimit(bytes, maxOutputBytes);
  } on vendor.BrotliOutputLimitException catch (error) {
    throw BrotliDecodingException(
      BrotliDecodingErrorCode.outputLimitExceeded,
      error.message,
    );
  } on vendor.BrotliException catch (error) {
    final truncated =
        error.message.contains('end of input') ||
        error.message == 'No more input' ||
        error.message == 'Read after end';
    throw BrotliDecodingException(
      truncated
          ? BrotliDecodingErrorCode.truncated
          : BrotliDecodingErrorCode.malformed,
      error.message,
    );
  } on RangeError catch (error) {
    throw BrotliDecodingException(
      BrotliDecodingErrorCode.malformed,
      'Malformed Brotli stream: $error',
    );
  }
}

/// This exception is thrown when an error occurs
/// during Brotli encoding or decoding.
class BrotliException implements Exception {
  /// The exception message.
  final String message;

  /// Instantiates a new [BrotliException] with [message].
  const BrotliException(this.message);

  @override
  String toString() {
    return message;
  }
}

/// Error raised when decoded Brotli output exceeds the configured limit.
class BrotliOutputLimitException extends BrotliException {
  /// Creates an output-limit exception.
  const BrotliOutputLimitException()
    : super('Decoded Brotli output exceeds the configured limit');
}

import 'byte_range.dart';

/// Base class for failures reported by byte source and sink abstractions.
sealed class ByteIoException implements Exception {
  /// Creates an exception with a human-readable [message].
  const ByteIoException(this.message);

  /// Human-readable detail describing the failed byte I/O operation.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// An invalid half-open byte range or coordinate.
final class InvalidByteRangeException extends ByteIoException {
  /// Creates an exception describing why a byte range is invalid.
  const InvalidByteRangeException(super.message);
}

/// A byte range calculation exceeded the supported coordinate limit.
final class ByteRangeOverflowException extends ByteIoException {
  /// Creates an exception describing the overflowing byte range operation.
  const ByteRangeOverflowException(super.message);
}

/// A requested byte range was outside the available container range.
final class ByteRangeOutOfBoundsException extends ByteIoException {
  /// Creates an exception for [range] when it is not contained in [container].
  ByteRangeOutOfBoundsException(this.range, this.container)
    : super('Range $range is outside $container.');

  /// Requested range that could not be satisfied.
  final ByteRange range;

  /// Available range that [range] was expected to fit within.
  final ByteRange container;
}

/// A read returned fewer bytes than the requested range length.
final class TruncatedReadException extends ByteIoException {
  /// Creates an exception for a short read of [range].
  TruncatedReadException({
    required this.range,
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'Expected $expectedLength bytes for $range, but received '
         '$actualLength.',
       );

  /// Range that was being read when the source ended or returned short data.
  final ByteRange range;

  /// Number of bytes required to satisfy [range].
  final int expectedLength;

  /// Number of bytes actually returned by the source.
  final int actualLength;
}

/// An operation attempted to write to or close an already closed byte sink.
final class ByteSinkClosedException extends ByteIoException {
  /// Creates an exception for using a closed byte sink.
  const ByteSinkClosedException() : super('The byte sink is closed.');
}

/// An operation attempted to read from an already closed byte source.
final class ByteSourceClosedException extends ByteIoException {
  /// Creates an exception for using a closed byte source.
  const ByteSourceClosedException() : super('The byte source is closed.');
}

/// A byte source's length changed after it was opened.
final class ByteSourceChangedException extends ByteIoException {
  /// Creates an exception for a byte source length mismatch.
  ByteSourceChangedException({
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'The byte source length changed from $expectedLength to '
         '$actualLength.',
       );

  /// Length captured when the byte source was opened.
  final int expectedLength;

  /// Length observed during a later source operation.
  final int actualLength;
}

/// An underlying byte source I/O operation failed.
final class ByteSourceIoException extends ByteIoException {
  /// Creates an exception for a failed source [operation].
  ByteSourceIoException({
    required this.operation,
    required this.cause,
    this.location,
  }) : super(
         'Failed to $operation${location == null ? '' : ' at $location'}: '
         '$cause',
       );

  /// Description of the source operation that failed, such as opening or read.
  final String operation;

  /// Original error reported by the underlying platform or source.
  final Object cause;

  /// Optional path or source-specific location where the failure occurred.
  final String? location;
}

/// An underlying byte sink I/O operation failed.
final class ByteSinkIoException extends ByteIoException {
  /// Creates an exception for a failed sink [operation].
  ByteSinkIoException({
    required this.operation,
    required this.cause,
    this.location,
  }) : super(
         'Failed to $operation${location == null ? '' : ' at $location'}: '
         '$cause',
       );

  /// Description of the sink operation that failed, such as append or commit.
  final String operation;

  /// Original error reported by the underlying platform or sink.
  final Object cause;

  /// Optional path or sink-specific location where the failure occurred.
  final String? location;
}

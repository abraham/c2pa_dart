import 'byte_range.dart';

sealed class ByteIoException implements Exception {
  const ByteIoException(this.message);

  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

final class InvalidByteRangeException extends ByteIoException {
  const InvalidByteRangeException(super.message);
}

final class ByteRangeOverflowException extends ByteIoException {
  const ByteRangeOverflowException(super.message);
}

final class ByteRangeOutOfBoundsException extends ByteIoException {
  ByteRangeOutOfBoundsException(this.range, this.container)
    : super('Range $range is outside $container.');

  final ByteRange range;
  final ByteRange container;
}

final class TruncatedReadException extends ByteIoException {
  TruncatedReadException({
    required this.range,
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'Expected $expectedLength bytes for $range, but received '
         '$actualLength.',
       );

  final ByteRange range;
  final int expectedLength;
  final int actualLength;
}

final class ByteSinkClosedException extends ByteIoException {
  const ByteSinkClosedException() : super('The byte sink is closed.');
}

final class ByteSourceClosedException extends ByteIoException {
  const ByteSourceClosedException() : super('The byte source is closed.');
}

final class ByteSourceChangedException extends ByteIoException {
  ByteSourceChangedException({
    required this.expectedLength,
    required this.actualLength,
  }) : super(
         'The byte source length changed from $expectedLength to '
         '$actualLength.',
       );

  final int expectedLength;
  final int actualLength;
}

final class ByteSourceIoException extends ByteIoException {
  ByteSourceIoException({
    required this.operation,
    required this.cause,
    this.location,
  }) : super(
         'Failed to $operation${location == null ? '' : ' at $location'}: '
         '$cause',
       );

  final String operation;
  final Object cause;
  final String? location;
}

final class ByteSinkIoException extends ByteIoException {
  ByteSinkIoException({
    required this.operation,
    required this.cause,
    this.location,
  }) : super(
         'Failed to $operation${location == null ? '' : ' at $location'}: '
         '$cause',
       );

  final String operation;
  final Object cause;
  final String? location;
}

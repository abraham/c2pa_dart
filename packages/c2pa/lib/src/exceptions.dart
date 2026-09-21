import 'validation.dart';
import 'validation_code.dart';

class C2paException implements Exception {
  const C2paException(this.message, {this.cause, this.stackTrace});

  final String message;
  final Object? cause;
  final StackTrace? stackTrace;

  @override
  String toString() => '$runtimeType: $message';
}

base class C2paFormatException extends C2paException {
  const C2paFormatException(super.message, {super.cause, super.stackTrace});
}

enum C2paParseStage { extraction, jumbf, manifestStore, claim }

final class C2paParseException extends C2paFormatException {
  const C2paParseException(
    super.message, {
    required this.stage,
    this.validationCode,
    super.cause,
    super.stackTrace,
  });

  final C2paParseStage stage;
  final ValidationCode? validationCode;
}

final class C2paValidationException extends C2paException {
  const C2paValidationException(
    super.message, {
    this.results,
    super.cause,
    super.stackTrace,
  });

  final ValidationResults? results;
}

base class C2paSigningException extends C2paException {
  const C2paSigningException(super.message, {super.cause, super.stackTrace});
}

final class C2paTimestampException extends C2paSigningException {
  const C2paTimestampException(super.message, {super.cause, super.stackTrace});
}

final class C2paTimestampLimitException extends C2paTimestampException {
  const C2paTimestampLimitException({required this.limit, required this.actual})
    : super('Timestamp token size $actual exceeds reservation $limit');

  final int limit;
  final int actual;
}

final class C2paVerificationException extends C2paException {
  const C2paVerificationException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

base class C2paResourceException extends C2paException {
  const C2paResourceException(super.message, {super.cause, super.stackTrace});
}

base class C2paNetworkException extends C2paException {
  const C2paNetworkException(super.message, {super.cause, super.stackTrace});
}

final class C2paUnsupportedException extends C2paException {
  const C2paUnsupportedException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

base class C2paArchiveException extends C2paException {
  const C2paArchiveException(super.message, {super.cause, super.stackTrace});
}

final class C2paMalformedArchiveException extends C2paArchiveException {
  const C2paMalformedArchiveException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

final class C2paUnsafeArchivePathException extends C2paArchiveException {
  const C2paUnsafeArchivePathException(this.path)
    : super('Unsafe path in C2PA working archive: $path');

  final String path;
}

final class C2paArchiveResourceException extends C2paArchiveException {
  const C2paArchiveResourceException(super.message, {this.path, super.cause});

  final String? path;
}

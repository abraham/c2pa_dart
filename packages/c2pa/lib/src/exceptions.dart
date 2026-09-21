import 'validation.dart';
import 'validation_code.dart';

/// Base exception for failures reported by the C2PA SDK.
///
/// Thrown when an operation cannot be completed because parsing, validation,
/// signing, resources, network access, or archive handling failed.
class C2paException implements Exception {
  /// Creates an SDK exception with a human-readable [message].
  const C2paException(this.message, {this.cause, this.stackTrace});

  /// Human-readable description of the failure condition.
  final String message;

  /// Lower-level error that caused this exception, or `null` if none exists.
  final Object? cause;

  /// Stack trace associated with [cause], or `null` when unavailable.
  final StackTrace? stackTrace;

  @override
  String toString() => '$runtimeType: $message';
}

/// Exception thrown when C2PA bytes or metadata are structurally invalid.
///
/// This is used for malformed boxes, claims, sink state, or inputs that cannot
/// be interpreted as the expected C2PA format.
base class C2paFormatException extends C2paException {
  /// Creates a format exception for malformed C2PA data.
  const C2paFormatException(super.message, {super.cause, super.stackTrace});
}

/// The reader stage that failed while parsing C2PA data.
enum C2paParseStage {
  /// Extraction of manifest bytes from the source asset failed.
  extraction,

  /// Parsing JUMBF boxes or payloads failed.
  jumbf,

  /// Decoding the manifest store or active manifest failed.
  manifestStore,

  /// Decoding a claim or claim-specific structure failed.
  claim,
}

/// Exception thrown when reading a source fails at a known parse stage.
///
/// The [stage] identifies the failing layer, and [validationCode] carries the
/// equivalent validation status when one is known.
final class C2paParseException extends C2paFormatException {
  /// Creates a parse exception for a specific [stage].
  const C2paParseException(
    super.message, {
    required this.stage,
    this.validationCode,
    super.cause,
    super.stackTrace,
  });

  /// The parser layer that detected the malformed data.
  final C2paParseStage stage;

  /// Validation code corresponding to the parse failure, or `null` if none.
  final ValidationCode? validationCode;
}

/// Exception thrown when C2PA validation rules are not satisfied.
///
/// This is used for invalid builder definitions, failed trust checks, illegal
/// redactions, and manifest validation failures that stop processing.
final class C2paValidationException extends C2paException {
  /// Creates a validation exception, optionally carrying [results].
  const C2paValidationException(
    super.message, {
    this.results,
    super.cause,
    super.stackTrace,
  });

  /// Structured validation results for the failure, or `null` if unavailable.
  final ValidationResults? results;
}

/// Exception thrown when building or signing a manifest fails.
///
/// This includes missing signers, unsupported algorithms, malformed signer
/// output, digest mismatches, and inputs that cannot be signed safely.
base class C2paSigningException extends C2paException {
  /// Creates a signing exception for a manifest creation failure.
  const C2paSigningException(super.message, {super.cause, super.stackTrace});
}

/// Exception thrown when timestamp token creation or validation fails.
///
/// This includes cancellation, unavailable TSA responses, malformed timestamp
/// tokens, untrusted timestamp certificates, and invalid TSA message imprints.
final class C2paTimestampException extends C2paSigningException {
  /// Creates a timestamp exception for timestamp-specific signing failure.
  const C2paTimestampException(super.message, {super.cause, super.stackTrace});
}

/// Exception thrown when a timestamp token exceeds its reserved byte range.
final class C2paTimestampLimitException extends C2paTimestampException {
  /// Creates a limit exception with the reserved [limit] and measured [actual].
  const C2paTimestampLimitException({required this.limit, required this.actual})
    : super('Timestamp token size $actual exceeds reservation $limit');

  /// Maximum reserved timestamp-token size in bytes.
  final int limit;

  /// Actual timestamp-token size in bytes.
  final int actual;
}

/// Exception thrown when signature verification cannot be completed.
///
/// This is reserved for verifier failures where validation cannot continue
/// because the configured verifier or verification input failed.
final class C2paVerificationException extends C2paException {
  /// Creates a verification exception for a signature-checking failure.
  const C2paVerificationException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

/// Exception thrown when manifest resources cannot be used.
///
/// This includes missing resources, duplicate resource URIs, malformed resource
/// identifiers, ambiguous lookups, and resource limit violations.
base class C2paResourceException extends C2paException {
  /// Creates a resource exception for manifest resource handling failure.
  const C2paResourceException(super.message, {super.cause, super.stackTrace});
}

/// Exception thrown when remote network resolution fails or is disallowed.
///
/// This includes policy violations, transport errors, redirects, timeouts,
/// oversized responses, and disabled network access.
base class C2paNetworkException extends C2paException {
  /// Creates a network exception for remote C2PA resolution failure.
  const C2paNetworkException(super.message, {super.cause, super.stackTrace});
}

/// Exception thrown when an asset format or operation is not supported.
///
/// Reader and builder operations throw this when no handler exists for the
/// requested format or when an operation cannot apply to that format.
final class C2paUnsupportedException extends C2paException {
  /// Creates an unsupported-operation exception.
  const C2paUnsupportedException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

/// Exception thrown when a C2PA working archive cannot be processed.
///
/// This is used for malformed archives, unsafe archive paths, and resource
/// failures while importing or exporting archive contents.
base class C2paArchiveException extends C2paException {
  /// Creates an archive exception for working-archive handling failure.
  const C2paArchiveException(super.message, {super.cause, super.stackTrace});
}

/// Exception thrown when a C2PA working archive is structurally invalid.
///
/// This includes missing JSON members, truncated ZIP entries, duplicate archive
/// entries, invalid CBOR payloads, and unexpected archive member types.
final class C2paMalformedArchiveException extends C2paArchiveException {
  /// Creates a malformed-archive exception.
  const C2paMalformedArchiveException(
    super.message, {
    super.cause,
    super.stackTrace,
  });
}

/// Exception thrown when an archive entry path is unsafe to materialize.
///
/// This is used for absolute paths, traversal outside the archive root,
/// empty segments, and backslash-separated paths.
final class C2paUnsafeArchivePathException extends C2paArchiveException {
  /// Creates an unsafe-path exception for [path].
  const C2paUnsafeArchivePathException(this.path)
    : super('Unsafe path in C2PA working archive: $path');

  /// Archive-relative path that failed safety validation.
  final String path;
}

/// Exception thrown when an archive resource cannot be read or written.
///
/// The optional [path] identifies the archive member or filesystem path whose
/// bytes failed resource validation or I/O.
final class C2paArchiveResourceException extends C2paArchiveException {
  /// Creates an archive-resource exception, optionally scoped to [path].
  const C2paArchiveResourceException(super.message, {this.path, super.cause});

  /// Path of the affected resource, or `null` when no single path applies.
  final String? path;
}

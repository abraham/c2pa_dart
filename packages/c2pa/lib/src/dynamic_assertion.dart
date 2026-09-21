import 'dart:typed_data';

import 'claim.dart';
import 'json_utils.dart';

/// Encodings a dynamic assertion callback may produce.
enum C2paDynamicAssertionEncoding {
  /// CBOR assertion payload encoded by the SDK.
  cbor,

  /// JSON assertion payload encoded by the SDK.
  json,

  /// Already-encoded binary assertion payload.
  binary,
}

/// Preliminary claim data passed to a dynamic assertion callback.
final class C2paDynamicClaimContext {
  /// Creates immutable dynamic-assertion claim context.
  C2paDynamicClaimContext({
    required this.manifestLabel,
    required this.instanceId,
    required this.format,
    required this.hashAlgorithm,
    required Iterable<ClaimHashedUri> assertions,
  }) : assertions = List<ClaimHashedUri>.unmodifiable(assertions);

  /// Label of the manifest being built.
  final String manifestLabel;

  /// Claim instance ID for the manifest being built.
  final String instanceId;

  /// Asset media type recorded in the claim.
  final String format;

  /// Digest algorithm used for claim assertion references.
  final String hashAlgorithm;

  /// Claim references for assertions already known to the builder.
  final List<ClaimHashedUri> assertions;
}

/// Request sent when resolving a dynamic assertion.
final class C2paDynamicAssertionRequest {
  /// Creates a dynamic assertion request.
  const C2paDynamicAssertionRequest({
    required this.label,
    required this.reservedSize,
    required this.claim,
  });

  /// Assertion label requested by the builder.
  final String label;

  /// Reserved payload size in bytes for placeholder workflows.
  final int reservedSize;

  /// Preliminary claim context available to the callback.
  final C2paDynamicClaimContext claim;
}

/// Output produced by a dynamic assertion callback.
final class C2paDynamicAssertionOutput {
  /// Creates CBOR output whose [data] is frozen for safe reuse.
  C2paDynamicAssertionOutput.cbor({required this.label, required Object? data})
    : encoding = C2paDynamicAssertionEncoding.cbor,
      contentType = null,
      data = freezeJson(data);

  /// Creates JSON output whose [data] is frozen for safe reuse.
  C2paDynamicAssertionOutput.json({required this.label, required Object? data})
    : encoding = C2paDynamicAssertionEncoding.json,
      contentType = null,
      data = freezeJson(data);

  /// Creates binary output with an explicit [contentType].
  C2paDynamicAssertionOutput.binary({
    required this.label,
    required this.contentType,
    required Uint8List data,
  }) : encoding = C2paDynamicAssertionEncoding.binary,
       data = Uint8List.fromList(data).asUnmodifiableView();

  /// Assertion label for the generated output.
  final String label;

  /// Encoding used to serialize [data].
  ///
  /// Set by the named constructor used to create this output.
  final C2paDynamicAssertionEncoding encoding;

  /// Media type for binary output, otherwise `null`.
  ///
  /// Binary output requires this to be non-null.
  final String? contentType;

  /// Generated assertion payload.
  final Object? data;
}

/// Callback that produces dynamic assertion content after claim planning.
typedef C2paDynamicAssertionCallback =
    Future<C2paDynamicAssertionOutput> Function(
      C2paDynamicAssertionRequest request,
    );

/// An assertion whose final content is produced after the preliminary claim
/// and all reserved assertion references are known.
final class C2paDynamicAssertion {
  /// Creates a dynamic assertion registration.
  const C2paDynamicAssertion({
    required this.label,
    required this.reservedSize,
    required this.encoding,
    required this.callback,
    this.contentType,
  });

  /// Assertion label to reserve and later generate.
  final String label;

  /// Reserved payload size in bytes for the generated assertion.
  final int reservedSize;

  /// Encoding expected from [callback].
  final C2paDynamicAssertionEncoding encoding;

  /// Required binary media type, or `null` for CBOR and JSON.
  final String? contentType;

  /// Callback invoked once claim references are known.
  final C2paDynamicAssertionCallback callback;
}

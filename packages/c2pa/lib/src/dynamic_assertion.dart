import 'dart:typed_data';

import 'claim.dart';
import 'json_utils.dart';

enum C2paDynamicAssertionEncoding { cbor, json, binary }

final class C2paDynamicClaimContext {
  C2paDynamicClaimContext({
    required this.manifestLabel,
    required this.instanceId,
    required this.format,
    required this.hashAlgorithm,
    required Iterable<ClaimHashedUri> assertions,
  }) : assertions = List<ClaimHashedUri>.unmodifiable(assertions);

  final String manifestLabel;
  final String instanceId;
  final String format;
  final String hashAlgorithm;
  final List<ClaimHashedUri> assertions;
}

final class C2paDynamicAssertionRequest {
  const C2paDynamicAssertionRequest({
    required this.label,
    required this.reservedSize,
    required this.claim,
  });

  final String label;
  final int reservedSize;
  final C2paDynamicClaimContext claim;
}

final class C2paDynamicAssertionOutput {
  C2paDynamicAssertionOutput.cbor({required this.label, required Object? data})
    : encoding = C2paDynamicAssertionEncoding.cbor,
      contentType = null,
      data = freezeJson(data);

  C2paDynamicAssertionOutput.json({required this.label, required Object? data})
    : encoding = C2paDynamicAssertionEncoding.json,
      contentType = null,
      data = freezeJson(data);

  C2paDynamicAssertionOutput.binary({
    required this.label,
    required this.contentType,
    required Uint8List data,
  }) : encoding = C2paDynamicAssertionEncoding.binary,
       data = Uint8List.fromList(data).asUnmodifiableView();

  final String label;
  final C2paDynamicAssertionEncoding encoding;
  final String? contentType;
  final Object? data;
}

typedef C2paDynamicAssertionCallback =
    Future<C2paDynamicAssertionOutput> Function(
      C2paDynamicAssertionRequest request,
    );

/// An assertion whose final content is produced after the preliminary claim
/// and all reserved assertion references are known.
final class C2paDynamicAssertion {
  const C2paDynamicAssertion({
    required this.label,
    required this.reservedSize,
    required this.encoding,
    required this.callback,
    this.contentType,
  });

  final String label;
  final int reservedSize;
  final C2paDynamicAssertionEncoding encoding;
  final String? contentType;
  final C2paDynamicAssertionCallback callback;
}

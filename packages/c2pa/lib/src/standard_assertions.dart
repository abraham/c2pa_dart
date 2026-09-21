import 'dart:convert';
import 'dart:typed_data';

import 'claim.dart';
import 'json_utils.dart';

part 'standard_assertions/asset_reference.dart';
part 'standard_assertions/embedded_data.dart';
part 'standard_assertions/internal.dart';
part 'standard_assertions/metadata.dart';
part 'standard_assertions/region.dart';
part 'standard_assertions/soft_binding.dart';
part 'standard_assertions/timestamp_legacy.dart';

/// Wire encoding used for a standard C2PA assertion payload.
enum C2paStandardAssertionEncoding {
  /// CBOR payload encoded as `application/cbor`.
  cbor,

  /// JSON payload encoded as `application/json`.
  json,

  /// Opaque byte payload with an explicit content type.
  binary,
}

/// A standard C2PA assertion value that can be embedded in a claim.
abstract interface class C2paStandardAssertion {
  /// Assertion label as it appears in the manifest.
  String get label;

  /// Wire encoding used for the value returned by `toAssertionData`.
  C2paStandardAssertionEncoding get encoding;

  /// MIME type for the assertion payload; null when none is declared.
  String? get contentType;

  /// Converts this assertion to the payload model for its encoding.
  Object? toAssertionData();
}

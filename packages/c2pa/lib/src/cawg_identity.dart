import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart';

import 'builder.dart';
import 'claim.dart';
import 'context.dart';
import 'dynamic_assertion.dart';
import 'json_utils.dart';
import 'remote_manifest.dart';
import 'signing.dart';

part 'cawg/assertion.dart';
part 'cawg/builder_extension.dart';
part 'cawg/ica_claims.dart';
part 'cawg/ica_credential.dart';
part 'cawg/ica_verifier.dart';
part 'cawg/internal.dart';
part 'cawg/signer_payload.dart';
part 'cawg/status.dart';
part 'cawg/validator.dart';
part 'cawg/x509.dart';

/// CAWG assertion labels and helpers for identity assertions.
abstract final class CawgIdentityLabels {
  /// Base label for a CAWG identity assertion.
  static const identity = 'cawg.identity';

  /// Signature type for X.509 COSE identity assertions.
  static const x509Cose = 'cawg.x509.cose';

  /// Signature type for identity-claims aggregation credentials.
  static const identityClaimsAggregation = 'cawg.identity_claims_aggregation';

  /// Builds the identity assertion label for a zero-based instance index.
  ///
  /// Throws ArgumentError when the index is negative.
  static String instance(int index) {
    if (index < 0) {
      throw ArgumentError.value(index, 'index', 'Must not be negative');
    }
    return index == 0 ? identity : '${identity}__$index';
  }

  /// Checks whether a label is `cawg.identity` or a numbered instance.
  static bool isIdentity(String label) =>
      label == identity ||
      RegExp(r'^cawg\.identity__[1-9][0-9]*$').hasMatch(label);
}

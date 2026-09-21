part of '../cawg_identity.dart';

/// Severity level attached to a CAWG validation status.
enum CawgStatusSeverity {
  /// Successful validation condition.
  success,

  /// Non-failing informational validation condition.
  informational,

  /// Failing validation condition.
  failure,
}

/// Status code constants emitted by CAWG identity validation.
abstract final class CawgStatusCodes {
  /// Status code for an identity assertion that is not valid CBOR.
  static const cborInvalid = 'cawg.identity.cbor.invalid';

  /// Status code for non-zero CAWG identity padding bytes.
  static const padInvalid = 'cawg.identity.pad.invalid';

  /// Status code for a referenced assertion hash mismatch.
  static const assertionMismatch = 'cawg.identity.assertion.mismatch';

  /// Status code for duplicate assertion references in signer payload.
  static const assertionDuplicate = 'cawg.identity.assertion.duplicate';

  /// Status code for identity assertions without a hard-binding reference.
  static const hardBindingMissing = 'cawg.identity.hard_binding_missing';

  /// Status code for cycles among referenced identity assertions.
  static const assertionCycle = 'cawg.identity.assertion.cycle';

  /// Status code for an unsupported CAWG signature type.
  static const signatureTypeUnknown = 'cawg.identity.sig_type.unknown';

  /// Status code for a failed CAWG X.509 COSE signature check.
  static const signatureInvalid = 'cawg.identity.signature.invalid';

  /// Status code for an untrusted CAWG signing certificate.
  static const certificateUntrusted = 'cawg.identity.credential.untrusted';

  /// Status code for malformed or unusable CAWG certificate data.
  static const certificateInvalid = 'cawg.identity.credential.invalid';

  /// Status code for a revoked CAWG signing certificate.
  static const certificateRevoked = 'cawg.identity.credential.revoked';

  /// Status code for a positive OCSP not-revoked result.
  static const certificateNotRevoked = 'cawg.identity.credential.not_revoked';

  /// Status code for missing or inconclusive OCSP revocation data.
  static const ocspUnknown = 'cawg.identity.credential.ocsp_unknown';

  /// Status code for malformed CAWG X.509 timestamp data.
  static const timestampMalformed = 'cawg.identity.timestamp.malformed';

  /// Status code for an untrusted CAWG X.509 timestamp token.
  static const timestampUntrusted = 'cawg.identity.timestamp.untrusted';

  /// Status code for a structurally well-formed identity assertion.
  static const wellFormed = 'cawg.identity.well-formed';

  /// Status code for a trusted CAWG identity assertion.
  static const trusted = 'cawg.identity.trusted';

  /// Compatibility status for a trusted signing credential.
  static const signingCredentialTrusted = 'signingCredential.trusted';

  /// Compatibility status for an untrusted signing credential.
  static const signingCredentialUntrusted = 'signingCredential.untrusted';

  /// Status code for invalid ICA COSE_Sign1 structure.
  static const icaInvalidCose = 'cawg.ica.invalid_cose_sign1';

  /// Status code for missing or unsupported ICA COSE algorithm.
  static const icaInvalidAlgorithm = 'cawg.ica.invalid_alg';

  /// Status code for ICA COSE content type other than `application/vc`.
  static const icaInvalidContentType = 'cawg.ica.invalid_content_type';

  /// Status code for malformed ICA verifiable credential content.
  static const icaInvalidCredential = 'cawg.ica.invalid_verifiable_credential';

  /// Status code for ICA credential `c2paAsset` payload mismatch.
  static const icaAssetMismatch = 'cawg.ica.signer_payload.mismatch';

  /// Status code for an unsupported ICA issuer DID method.
  static const icaIssuerUnsupported = 'cawg.ica.invalid_issuer';

  /// Status code for did:web resolution failure.
  static const icaDidResolutionFailed = 'cawg.ica.did_unavailable';

  /// Status code for a malformed or unauthorized DID document.
  static const icaInvalidDidDocument = 'cawg.ica.invalid_did_document';

  /// Status code for an ICA credential signature mismatch.
  static const icaSignatureMismatch = 'cawg.ica.signature_mismatch';

  /// Status code for a valid ICA timestamp token.
  static const icaTimestampValidated = 'cawg.ica.time_stamp.validated';

  /// Status code for an invalid ICA timestamp token.
  static const icaTimestampInvalid = 'cawg.ica.time_stamp.invalid';

  /// Status code for a missing ICA validity start timestamp.
  static const icaValidFromMissing = 'cawg.ica.valid_from.missing';

  /// Status code for an ICA credential not yet valid.
  static const icaValidFromInvalid = 'cawg.ica.valid_from.invalid';

  /// Status code for an expired ICA credential.
  static const icaValidUntilInvalid = 'cawg.ica.valid_until.invalid';

  /// Status code for a valid ICA credential profile and signature.
  static const icaCredentialValid = 'cawg.ica.credential_valid';
}

/// Single validation status emitted during CAWG identity checking.
final class CawgValidationStatus {
  /// Creates a validation status with optional URL and explanation.
  const CawgValidationStatus({
    required this.code,
    required this.severity,
    this.url,
    this.explanation,
  });

  /// Machine-readable validation code, usually from CawgStatusCodes.
  final String code;

  /// Severity that determines whether the status is a failure.
  final CawgStatusSeverity severity;

  /// Optional assertion URL or label related to this status.
  final String? url;

  /// Optional human-readable detail for diagnostics.
  final String? explanation;

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    'code': code,
    'severity': severity.name,
    'url': ?url,
    'explanation': ?explanation,
  };

  @override
  bool operator ==(Object other) =>
      other is CawgValidationStatus &&
      code == other.code &&
      severity == other.severity &&
      url == other.url &&
      explanation == other.explanation;

  @override
  int get hashCode => Object.hash(code, severity, url, explanation);
}

/// Result of validating one CAWG identity assertion.
final class CawgIdentityValidationResult {
  /// Creates a validation result with immutable status records.
  CawgIdentityValidationResult({
    required this.assertionLabel,
    required Iterable<CawgValidationStatus> statuses,
    this.signerPayload,
    Map<String, Object?>? credentialSummary,
  }) : statuses = List<CawgValidationStatus>.unmodifiable(statuses),
       credentialSummary = credentialSummary == null
           ? null
           : freezeJsonMap(credentialSummary);

  /// Manifest label of the identity assertion that was validated.
  final String assertionLabel;

  /// Validation statuses emitted in evaluation order.
  final List<CawgValidationStatus> statuses;

  /// Decoded signer payload, or null when it could not be decoded.
  final CawgSignerPayload? signerPayload;

  /// Optional JSON summary of the verified credential or certificate.
  final Map<String, Object?>? credentialSummary;

  /// Whether validation produced `cawg.identity.well-formed` and no failures.
  bool get isWellFormed =>
      statuses.any((status) => status.code == CawgStatusCodes.wellFormed) &&
      !statuses.any((status) => status.severity == CawgStatusSeverity.failure);

  /// Whether validation produced a trusted status and no failures.
  bool get isTrusted =>
      statuses.any(
        (status) =>
            status.code == CawgStatusCodes.trusted ||
            status.code == CawgStatusCodes.signingCredentialTrusted,
      ) &&
      !statuses.any((status) => status.severity == CawgStatusSeverity.failure);

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    'assertionLabel': assertionLabel,
    'statuses': statuses.map((status) => status.toJson()).toList(),
    'signerPayload': ?signerPayload?.toJson(),
    'credential': ?credentialSummary,
  };
}

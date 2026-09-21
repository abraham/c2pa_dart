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

/// Decoded CAWG `signer_payload` map used as signature input.
final class CawgSignerPayload {
  /// Creates a signer payload from referenced assertions and signature type.
  ///
  /// Throws FormatException when the signature type or any role is empty.
  factory CawgSignerPayload({
    required Iterable<ClaimHashedUri> referencedAssertions,
    required String signatureType,
    String? role,
    Iterable<String> roles = const [],
    Map<String, Object?> expected = const {},
    Map<String, Object?> unknownFields = const {},
  }) => CawgSignerPayload._(
    referencedAssertions: referencedAssertions,
    signatureType: signatureType,
    roles: [?role, ...roles],
    roleEncoding: _CawgRoleEncoding.list,
    expected: expected,
    unknownFields: unknownFields,
  );

  CawgSignerPayload._({
    required Iterable<ClaimHashedUri> referencedAssertions,
    required this.signatureType,
    required Iterable<String> roles,
    required this._roleEncoding,
    required Map<String, Object?> expected,
    required Map<String, Object?> unknownFields,
    Uint8List? rawBytes,
  }) : referencedAssertions = List<ClaimHashedUri>.unmodifiable(
         referencedAssertions,
       ),
       roles = List<String>.unmodifiable(roles),
       expected = freezeJsonMap(expected),
       unknownFields = freezeJsonMap(unknownFields),
       _rawBytes = rawBytes == null
           ? null
           : Uint8List.fromList(rawBytes).asUnmodifiableView() {
    if (signatureType.isEmpty) {
      throw const FormatException('CAWG signer_payload requires sig_type');
    }
    if (this.roles.any((role) => role.isEmpty)) {
      throw const FormatException(
        'CAWG signer_payload roles must not be empty',
      );
    }
  }

  /// Parses a CAWG `signer_payload` CBOR map.
  factory CawgSignerPayload.fromCbor(Object? value) {
    final map = _stringMap(value, 'CAWG signer_payload');
    final refs = map['referenced_assertions'];
    final sigType = map['sig_type'];
    final role = map['role'];
    if (refs is! List || sigType is! String) {
      throw const FormatException('Malformed CAWG signer_payload');
    }
    if (role != null &&
        role is! String &&
        (role is! List || !role.every((item) => item is String))) {
      throw const FormatException('CAWG role must be a string or string array');
    }
    final expected = <String, Object?>{};
    final unknown = <String, Object?>{};
    for (final entry in map.entries) {
      if (const {
        'referenced_assertions',
        'sig_type',
        'role',
      }.contains(entry.key)) {
        continue;
      }
      if (entry.key.startsWith('expected_')) {
        expected[entry.key] = entry.value;
      } else {
        unknown[entry.key] = entry.value;
      }
    }
    return CawgSignerPayload._(
      referencedAssertions: refs.map(ClaimHashedUri.fromCbor),
      signatureType: sigType,
      roles: role is String
          ? [role]
          : role is List
          ? role.cast<String>()
          : const [],
      roleEncoding: role == null
          ? _CawgRoleEncoding.absent
          : role is String
          ? _CawgRoleEncoding.legacyString
          : _CawgRoleEncoding.list,
      expected: expected,
      unknownFields: unknown,
    );
  }

  /// Assertions covered by the identity signature.
  final List<ClaimHashedUri> referencedAssertions;

  /// CAWG signature type such as `cawg.x509.cose`.
  final String signatureType;

  /// Optional non-empty roles associated with the signer.
  final List<String> roles;
  final _CawgRoleEncoding _roleEncoding;

  /// Legacy single role value, or null when zero or multiple roles exist.
  String? get role => roles.length == 1 ? roles.single : null;

  /// Fields whose keys start with `expected_` in the signer payload.
  final Map<String, Object?> expected;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  final Uint8List? _rawBytes;

  CawgSignerPayload _withRawBytes(Uint8List bytes) => CawgSignerPayload._(
    referencedAssertions: referencedAssertions,
    signatureType: signatureType,
    roles: roles,
    roleEncoding: _roleEncoding,
    expected: expected,
    unknownFields: unknownFields,
    rawBytes: bytes,
  );

  /// Encodes the signer payload as the CBOR map used for signing.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    ...expected,
    'referenced_assertions': referencedAssertions
        .map((reference) => reference.toCborMap())
        .toList(growable: false),
    'sig_type': signatureType,
    if (_roleEncoding != _CawgRoleEncoding.absent)
      'role': _roleEncoding == _CawgRoleEncoding.legacyString
          ? roles.single
          : roles,
  };

  /// Encodes the signer payload to CBOR, preserving original bytes when known.
  Uint8List encode() => _rawBytes == null
      ? encodeCbor(toCborMap())
      : Uint8List.fromList(_rawBytes);

  /// Encodes the signer payload as JSON with byte strings base64 encoded.
  Map<String, Object?> toJson() =>
      _bytesToBase64(toCborMap()) as Map<String, Object?>;

  @override
  bool operator ==(Object other) =>
      other is CawgSignerPayload &&
      deepEquals(referencedAssertions, other.referencedAssertions) &&
      signatureType == other.signatureType &&
      deepEquals(roles, other.roles) &&
      deepEquals(expected, other.expected) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    deepHash(referencedAssertions),
    signatureType,
    deepHash(roles),
    deepHash(expected),
    deepHash(unknownFields),
  );
}

enum _CawgRoleEncoding { absent, legacyString, list }

/// CAWG identity assertion containing signer payload, signature, and padding.
final class CawgIdentityAssertion {
  /// Creates a CAWG identity assertion from its CBOR fields.
  ///
  /// Throws FormatException when the signature byte string is empty.
  CawgIdentityAssertion({
    required this.signerPayload,
    required Uint8List signature,
    Uint8List? pad1,
    Uint8List? pad2,
    Map<String, Object?> unknownFields = const {},
    Uint8List? rawBytes,
  }) : signature = Uint8List.fromList(signature).asUnmodifiableView(),
       pad1 = Uint8List.fromList(pad1 ?? const []).asUnmodifiableView(),
       pad2 = pad2 == null
           ? null
           : Uint8List.fromList(pad2).asUnmodifiableView(),
       unknownFields = freezeJsonMap(unknownFields),
       _rawBytes = rawBytes == null
           ? null
           : Uint8List.fromList(rawBytes).asUnmodifiableView() {
    if (signature.isEmpty) {
      throw const FormatException('CAWG identity signature must not be empty');
    }
  }

  /// Parses a CAWG identity assertion from a decoded CBOR map.
  factory CawgIdentityAssertion.fromCbor(Object? value) {
    final map = _stringMap(value, 'CAWG identity assertion');
    final signerPayload = map['signer_payload'];
    final signature = cborBytes(map['signature']);
    final pad1 = cborBytes(map['pad1']);
    final rawPad2 = map['pad2'];
    final pad2 = cborBytes(rawPad2);
    if (signerPayload == null ||
        signature == null ||
        pad1 == null ||
        (rawPad2 != null && pad2 == null)) {
      throw const FormatException('Malformed CAWG identity assertion');
    }
    return CawgIdentityAssertion(
      signerPayload: CawgSignerPayload.fromCbor(signerPayload),
      signature: signature,
      pad1: pad1,
      pad2: pad2,
      unknownFields: unknownFieldsOf(map, const {
        'signer_payload',
        'signature',
        'pad1',
        'pad2',
      }),
    );
  }

  /// Decodes a CAWG identity assertion from raw CBOR bytes.
  factory CawgIdentityAssertion.decode(Uint8List bytes) {
    final decoded = CawgIdentityAssertion.fromCbor(
      decodeCbor(
        bytes,
        requireCanonicalMapOrder: false,
        allowIndefiniteLength: true,
      ),
    );
    final signerPayloadBytes = _cborMapValueBytes(bytes, 'signer_payload');
    return CawgIdentityAssertion(
      signerPayload: decoded.signerPayload._withRawBytes(signerPayloadBytes),
      signature: decoded.signature,
      pad1: decoded.pad1,
      pad2: decoded.pad2,
      unknownFields: decoded.unknownFields,
      rawBytes: bytes,
    );
  }

  /// Payload signed by the CAWG identity signature.
  final CawgSignerPayload signerPayload;

  /// Signature bytes from the CAWG identity assertion.
  final Uint8List signature;

  /// First padding byte string, required to contain only zeros.
  final Uint8List pad1;

  /// Optional second padding byte string, also required to contain zeros.
  final Uint8List? pad2;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  final Uint8List? _rawBytes;

  /// Encodes the identity assertion as the CBOR map stored in the manifest.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'signer_payload': signerPayload.toCborMap(),
    'signature': Uint8List.fromList(signature),
    'pad1': Uint8List.fromList(pad1),
    'pad2': ?(pad2 == null ? null : Uint8List.fromList(pad2!)),
  };

  /// Encodes the identity assertion to CBOR, preserving original bytes.
  Uint8List encode() => _rawBytes == null
      ? encodeCbor(toCborMap())
      : Uint8List.fromList(_rawBytes);

  /// Whether all present padding bytes are zero.
  bool get hasValidPadding =>
      pad1.every((value) => value == 0) &&
      (pad2?.every((value) => value == 0) ?? true);

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityAssertion &&
      signerPayload == other.signerPayload &&
      deepEquals(signature, other.signature) &&
      deepEquals(pad1, other.pad1) &&
      deepEquals(pad2, other.pad2) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    signerPayload,
    deepHash(signature),
    deepHash(pad1),
    deepHash(pad2),
    deepHash(unknownFields),
  );
}

/// Validator for CAWG identity assertions referenced by a claim.
final class CawgIdentityValidator {
  /// Creates a stateless CAWG identity validator.
  const CawgIdentityValidator();

  /// Validates identity references, hard binding, and signature trust.
  ///
  /// Performs certificate, OCSP, timestamp, or ICA checks according to the
  /// signature type and validation context.
  Future<CawgIdentityValidationResult> validate({
    required String assertionLabel,
    required CawgIdentityAssertion assertion,
    required Iterable<ClaimHashedUri> claimAssertions,
    required C2paContext context,
    Map<String, CawgIdentityAssertion> identityAssertions = const {},
  }) async {
    final statuses = <CawgValidationStatus>[];
    bool failed(String code, String explanation) {
      statuses.add(
        CawgValidationStatus(
          code: code,
          severity: CawgStatusSeverity.failure,
          url: assertionLabel,
          explanation: explanation,
        ),
      );
      return context.cawgValidationPolicy ==
          CawgValidationPolicy.stopOnFirstFailure;
    }

    if (!assertion.hasValidPadding &&
        failed(
          CawgStatusCodes.padInvalid,
          'pad1 and pad2 must contain zeros',
        )) {
      return _result(assertionLabel, assertion, statuses);
    }

    final available = {
      for (final reference in claimAssertions)
        _relativeAssertionUrl(reference.url): reference,
    };
    final identityGraph = <String, CawgIdentityAssertion>{
      for (final entry in identityAssertions.entries)
        _identityLabel(entry.key): entry.value,
      _identityLabel(assertionLabel): assertion,
    };
    if (_hasIdentityReferenceCycle(
          _identityLabel(assertionLabel),
          identityGraph,
        ) &&
        failed(
          CawgStatusCodes.assertionCycle,
          'Identity assertion references form a cycle',
        )) {
      return _result(assertionLabel, assertion, statuses);
    }
    var hasHardBinding = false;
    final seen = <String>{};
    for (final reference in assertion.signerPayload.referencedAssertions) {
      final relative = _relativeAssertionUrl(reference.url);
      if (!seen.add(relative)) {
        if (failed(
          CawgStatusCodes.assertionDuplicate,
          'The identity assertion contains a duplicate reference',
        )) {
          return _result(assertionLabel, assertion, statuses);
        }
      }
      hasHardBinding |= _isHardBinding(relative);
      final actual = available[relative];
      if (actual == null ||
          !deepEquals(actual.hash, reference.hash) ||
          (reference.algorithm != null &&
              actual.algorithm != reference.algorithm)) {
        if (failed(
          CawgStatusCodes.assertionMismatch,
          'A referenced assertion does not match the claim',
        )) {
          return _result(assertionLabel, assertion, statuses);
        }
      }
    }
    if (!hasHardBinding &&
        failed(
          CawgStatusCodes.hardBindingMissing,
          'At least one hard-binding assertion must be referenced',
        )) {
      return _result(assertionLabel, assertion, statuses);
    }

    Map<String, Object?>? credential;
    final hadStructuralFailure = statuses.any(
      (status) => status.severity == CawgStatusSeverity.failure,
    );
    switch (assertion.signerPayload.signatureType) {
      case CawgIdentityLabels.x509Cose:
        final verification = await CawgX509CoseVerifier().verify(
          assertion,
          context,
        );
        statuses.addAll(verification.statuses);
        if (context.cawgIcaCompatibility == CawgIcaCompatibility.c2paRs09022 &&
            !hadStructuralFailure) {
          statuses.removeWhere(
            (status) => status.code == CawgStatusCodes.signingCredentialTrusted,
          );
        }
        credential = verification.credentialSummary;
      case CawgIdentityLabels.identityClaimsAggregation:
        final verification = await CawgIcaVerifier(
          compatibility: context.cawgIcaCompatibility,
        ).verify(assertion, context);
        statuses.addAll(verification.statuses);
        credential = verification.credentialSummary;
      default:
        // c2pa-rs v0.90.22 skips identity assertions whose signature type it
        // does not recognize rather than invalidating the manifest, so this is
        // reported without failing the verdict.
        statuses.add(
          CawgValidationStatus(
            code: CawgStatusCodes.signatureTypeUnknown,
            severity: CawgStatusSeverity.informational,
            url: assertionLabel,
            explanation:
                'Unknown CAWG signature type '
                '${assertion.signerPayload.signatureType}',
          ),
        );
    }
    if (context.cawgIcaCompatibility != CawgIcaCompatibility.c2paRs09022 &&
        !statuses.any(
          (status) => status.severity == CawgStatusSeverity.failure,
        )) {
      statuses.add(
        const CawgValidationStatus(
          code: CawgStatusCodes.wellFormed,
          severity: CawgStatusSeverity.success,
        ),
      );
      if (statuses.any((status) => status.code == CawgStatusCodes.trusted)) {
        // The signature verifier has already emitted the trusted status.
      }
    }
    return CawgIdentityValidationResult(
      assertionLabel: assertionLabel,
      statuses: statuses,
      signerPayload: assertion.signerPayload,
      credentialSummary: credential,
    );
  }

  CawgIdentityValidationResult _result(
    String label,
    CawgIdentityAssertion assertion,
    List<CawgValidationStatus> statuses,
  ) => CawgIdentityValidationResult(
    assertionLabel: label,
    statuses: statuses,
    signerPayload: assertion.signerPayload,
  );
}

/// Internal-style result returned by CAWG signature verifiers.
final class CawgX509Verification {
  /// Creates a verifier result with statuses and optional credential summary.
  CawgX509Verification(this.statuses, this.credentialSummary);

  /// Validation statuses emitted in evaluation order.
  final List<CawgValidationStatus> statuses;

  /// Optional JSON summary of the verified credential or certificate.
  final Map<String, Object?>? credentialSummary;
}

/// Verifier for `cawg.x509.cose` identity signatures.
final class CawgX509CoseVerifier {
  /// Creates a stateless X.509 COSE verifier.
  const CawgX509CoseVerifier();

  /// Verifies a CAWG X.509 COSE signature and related trust evidence.
  Future<CawgX509Verification> verify(
    CawgIdentityAssertion assertion,
    C2paContext context,
  ) async {
    final statuses = <CawgValidationStatus>[];
    try {
      final envelope = _CawgCoseEnvelope.parse(assertion.signature);
      if (envelope.textHeaders.containsKey('sigTst')) {
        return CawgX509Verification([
          const CawgValidationStatus(
            code: CawgStatusCodes.timestampMalformed,
            severity: CawgStatusSeverity.failure,
            explanation: 'CAWG 1.1 permits sigTst2 only',
          ),
        ], null);
      }
      final message = CoseSign1.parse(envelope.sanitizedBytes);
      if (message.payload != null) {
        throw const FormatException('CAWG X.509 COSE payload must be detached');
      }
      final chain = _x5chain(message);
      final leaf = X509Certificate.parse(chain.first);
      final algorithm = SigningAlgorithm.fromCoseId(
        message.protectedHeaders[CoseHeaderLabel.algorithm]! as int,
      );
      final backend = await _verificationBackend(
        algorithm,
        leaf,
        context.verifier,
      );
      final valid = await _verifyCoseWithProtectedBytes(
        backend,
        algorithm,
        envelope.protectedBytes,
        assertion.signerPayload.encode(),
        message.signature,
      );
      if (!valid) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.signatureInvalid,
            severity: CawgStatusSeverity.failure,
          ),
        );
      }

      final trust = context.cawgTrust;
      var trusted = false;
      if (valid && trust.verifyTrust) {
        final path = await validateCertificatePath(
          chain.first,
          algorithm: algorithm,
          policy: TrustPolicy(
            trustAnchors: trust.trustAnchors,
            intermediates: [...trust.intermediates, ...chain.skip(1)],
            allowedEndEntitySha256Hashes: trust.allowedEndEntitySha256Hashes,
            allowedEkuOids: trust.allowedEkuOids,
            evaluationTime: trust.evaluationTime,
            maxDepth: trust.maxPathDepth,
          ),
        );
        trusted = path.isTrusted;
        if (!trusted) {
          statuses.add(
            CawgValidationStatus(
              code:
                  context.cawgIcaCompatibility ==
                      CawgIcaCompatibility.c2paRs09022
                  ? CawgStatusCodes.signingCredentialUntrusted
                  : CawgStatusCodes.certificateUntrusted,
              severity: CawgStatusSeverity.failure,
            ),
          );
        }
      } else if (valid) {
        statuses.add(
          CawgValidationStatus(
            code:
                context.cawgIcaCompatibility == CawgIcaCompatibility.c2paRs09022
                ? CawgStatusCodes.signingCredentialUntrusted
                : CawgStatusCodes.certificateUntrusted,
            severity: CawgStatusSeverity.informational,
            explanation: 'CAWG trust verification is disabled',
          ),
        );
      }

      final rVals = envelope.textHeaders['rVals'];
      final stapledOcsp = _firstByteString(rVals, 'ocspVals');
      if (rVals != null && stapledOcsp == null) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.ocspUnknown,
            severity: CawgStatusSeverity.failure,
          ),
        );
      } else if (stapledOcsp != null) {
        if (chain.length < 2) {
          statuses.add(
            const CawgValidationStatus(
              code: CawgStatusCodes.ocspUnknown,
              severity: CawgStatusSeverity.failure,
            ),
          );
        } else {
          final issuer = X509Certificate.parse(chain[1]);
          final result = await verifyOcspResponse(
            stapledOcsp,
            certificate: leaf,
            issuer: issuer,
            trustPolicy: TrustPolicy(
              trustAnchors: trust.trustAnchors,
              intermediates: [...trust.intermediates, ...chain.skip(1)],
              allowedEndEntitySha256Hashes: trust.allowedEndEntitySha256Hashes,
              evaluationTime: trust.evaluationTime,
              maxDepth: trust.maxPathDepth,
            ),
            evaluationTime: trust.evaluationTime,
            maxAgeWithoutNextUpdate:
                context.settings.ocspMaxAgeWithoutNextUpdate,
            clockSkew: context.settings.ocspClockSkew,
          );
          statuses.add(
            CawgValidationStatus(
              code: result.status == OcspResultStatus.good
                  ? CawgStatusCodes.certificateNotRevoked
                  : result.status == OcspResultStatus.revoked
                  ? CawgStatusCodes.certificateRevoked
                  : CawgStatusCodes.ocspUnknown,
              severity: result.status == OcspResultStatus.good
                  ? CawgStatusSeverity.success
                  : CawgStatusSeverity.failure,
            ),
          );
        }
      }

      final sigTst2 = envelope.textHeaders['sigTst2'];
      if (sigTst2 != null) {
        final token = _timestampToken(sigTst2);
        if (token == null) {
          statuses.add(
            const CawgValidationStatus(
              code: CawgStatusCodes.timestampMalformed,
              severity: CawgStatusSeverity.failure,
            ),
          );
          if (context.cawgIcaCompatibility ==
              CawgIcaCompatibility.c2paRs09022) {
            return CawgX509Verification(statuses, null);
          }
        } else {
          final signedBytes = encodeCbor(<Object?>[
            'CounterSignature',
            envelope.protectedBytes,
            Uint8List(0),
            encodeCbor(message.signature),
          ]);
          final timestampTrust = context.timestampTrust;
          final result = await verifyTimestampToken(
            token,
            signedBytes: signedBytes,
            trustPolicy: TrustPolicy(
              trustAnchors: timestampTrust.trustAnchors,
              intermediates: timestampTrust.intermediates,
              allowedEndEntitySha256Hashes:
                  timestampTrust.allowedEndEntitySha256Hashes,
              evaluationTime: timestampTrust.evaluationTime,
              maxDepth: timestampTrust.maxPathDepth,
            ),
          );
          if (!result.isValid) {
            statuses.add(
              CawgValidationStatus(
                code: result.status == TimestampStatus.untrusted
                    ? CawgStatusCodes.timestampUntrusted
                    : CawgStatusCodes.timestampMalformed,
                severity: CawgStatusSeverity.failure,
              ),
            );
          }
        }
      }
      if (valid && trusted) {
        statuses.add(
          CawgValidationStatus(
            code:
                context.cawgIcaCompatibility == CawgIcaCompatibility.c2paRs09022
                ? CawgStatusCodes.signingCredentialTrusted
                : CawgStatusCodes.trusted,
            severity: CawgStatusSeverity.success,
          ),
        );
      }
      return CawgX509Verification(statuses, {
        'type': CawgIdentityLabels.x509Cose,
        'subject': _distinguishedNameText(leaf.subject),
        'issuer': _distinguishedNameText(leaf.issuer),
        'algorithm': algorithm.name,
        'trusted': trusted,
      });
    } on Object catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.certificateInvalid,
          severity: CawgStatusSeverity.failure,
          explanation: error.toString(),
        ),
      ], null);
    }
  }
}

/// Signing material used to generate X.509 COSE identity assertions.
final class CawgX509CredentialHolder {
  /// Creates an X.509 credential holder for dynamic identity signing.
  ///
  /// Throws ArgumentError when the chain is empty or reservation size is not
  /// positive.
  CawgX509CredentialHolder({
    required this.signer,
    required Iterable<Uint8List> certificateChain,
    required this.reservedAssertionSize,
    this.role,
    this.expected = const {},
    this.timestamp,
  }) : certificateChain = List<Uint8List>.unmodifiable(
         certificateChain.map(
           (certificate) =>
               Uint8List.fromList(certificate).asUnmodifiableView(),
         ),
       ) {
    if (this.certificateChain.isEmpty) {
      throw ArgumentError.value(
        certificateChain,
        'certificateChain',
        'At least one certificate is required',
      );
    }
    if (reservedAssertionSize < 1) {
      throw ArgumentError.value(
        reservedAssertionSize,
        'reservedAssertionSize',
        'Must be positive',
      );
    }
  }

  /// Signer callback used to produce COSE signatures.
  final C2paSigner signer;

  /// Certificate chain placed in the COSE `x5chain` header.
  final List<Uint8List> certificateChain;

  /// Exact byte size reserved for the generated identity assertion.
  final int reservedAssertionSize;

  /// Optional signer role included in the generated signer payload.
  final String? role;

  /// Fields whose keys start with `expected_` in the signer payload.
  final Map<String, Object?> expected;

  /// Optional callback that supplies a timestamp token for `sigTst2`.
  final CawgTimestampCallback? timestamp;

  /// Builds a dynamic assertion that signs the claim at generation time.
  C2paDynamicAssertion toDynamicAssertion({int instance = 0}) {
    final label = CawgIdentityLabels.instance(instance);
    return C2paDynamicAssertion(
      label: label,
      reservedSize: reservedAssertionSize,
      encoding: C2paDynamicAssertionEncoding.cbor,
      callback: (request) async {
        final payload = CawgSignerPayload(
          referencedAssertions: request.claim.assertions.where(
            (reference) => !_isIdentityReference(reference.url),
          ),
          signatureType: CawgIdentityLabels.x509Cose,
          role: role,
          expected: expected,
        );
        final algorithm = _algorithmByName(signer.algorithm);
        var cose =
            await CoseSigner(
              backends: {algorithm: _CallbackSigningBackend(signer)},
            ).sign(
              algorithm: algorithm,
              payload: payload.encode(),
              protectedHeaders: CoseHeaders({
                CoseHeaderLabel.x509Chain: certificateChain.length == 1
                    ? certificateChain.single
                    : certificateChain,
              }),
              detached: true,
            );
        if (timestamp != null) {
          final message = CoseSign1.parse(cose);
          final signedBytes = encodeCbor(<Object?>[
            'CounterSignature',
            message.protectedBytes,
            Uint8List(0),
            encodeCbor(message.signature),
          ]);
          cose = _withSigTst2(cose, await timestamp!(signedBytes));
        }
        final identity = _fitIdentityAssertion(
          payload: payload,
          signature: cose,
          size: request.reservedSize,
        );
        return C2paDynamicAssertionOutput.cbor(
          label: label,
          data: identity.toCborMap(),
        );
      },
    );
  }
}

/// Callback that timestamps CAWG COSE counter-signature bytes.
typedef CawgTimestampCallback = Future<Uint8List> Function(
  Uint8List counterSignatureBytes,
);

/// Convenience methods for adding CAWG identity assertions to a builder.
extension CawgBuilderExtension on C2paBuilder {
  /// Adds an X.509 COSE CAWG identity dynamic assertion.
  C2paBuilder withCawgX509Identity(
    CawgX509CredentialHolder holder, {
    int instance = 0,
  }) => withDynamicAssertion(holder.toDynamicAssertion(instance: instance));

  /// Adds an identity-claims aggregation dynamic assertion.
  C2paBuilder withCawgIdentityClaims(
    CawgIcaCredentialHolder holder, {
    int instance = 0,
  }) => withDynamicAssertion(holder.toDynamicAssertion(instance: instance));
}

Uint8List _withSigTst2(Uint8List cose, Uint8List timestampToken) {
  final tagged = cose.isNotEmpty && cose.first == 0xd2;
  final decoded = decodeCbor(tagged ? Uint8List.sublistView(cose, 1) : cose);
  if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
    throw const FormatException('Malformed generated COSE_Sign1');
  }
  final unprotected = Map<Object?, Object?>.from(decoded[1] as Map);
  unprotected['sigTst2'] = {
    'tstTokens': [
      {'val': Uint8List.fromList(timestampToken)},
    ],
  };
  final encoded = encodeCbor([decoded[0], unprotected, decoded[2], decoded[3]]);
  return tagged ? Uint8List.fromList([0xd2, ...encoded]) : encoded;
}

/// Factory that creates an ICA credential from the signer payload.
typedef CawgIcaCredentialFactory = CawgIdentityClaimsCredential Function(
  CawgSignerPayload signerPayload,
);

/// Signing material used to generate ICA identity assertions.
final class CawgIcaCredentialHolder {
  /// Creates an ICA credential holder for dynamic identity signing.
  ///
  /// Throws ArgumentError unless the signer uses Ed25519 or the reservation
  /// size is positive.
  CawgIcaCredentialHolder({
    required this.signer,
    required this.credentialFactory,
    required this.reservedAssertionSize,
    this.keyId,
    this.role,
    this.expected = const {},
  }) {
    if (_algorithmByName(signer.algorithm) != SigningAlgorithm.ed25519) {
      throw ArgumentError.value(
        signer.algorithm,
        'signer',
        'ICA requires Ed25519',
      );
    }
    if (reservedAssertionSize < 1) {
      throw ArgumentError.value(
        reservedAssertionSize,
        'reservedAssertionSize',
        'Must be positive',
      );
    }
  }

  /// Signer callback used to produce COSE signatures.
  final C2paSigner signer;

  /// Factory that must produce a credential matching the signer payload.
  final CawgIcaCredentialFactory credentialFactory;

  /// Exact byte size reserved for the generated identity assertion.
  final int reservedAssertionSize;

  /// Optional COSE key identifier encoded as UTF-8 in the protected header.
  final String? keyId;

  /// Optional signer role included in the generated signer payload.
  final String? role;

  /// Fields whose keys start with `expected_` in the signer payload.
  final Map<String, Object?> expected;

  /// Builds a dynamic assertion that signs the claim at generation time.
  C2paDynamicAssertion toDynamicAssertion({int instance = 0}) {
    final label = CawgIdentityLabels.instance(instance);
    return C2paDynamicAssertion(
      label: label,
      reservedSize: reservedAssertionSize,
      encoding: C2paDynamicAssertionEncoding.cbor,
      callback: (request) async {
        final signerPayload = CawgSignerPayload(
          referencedAssertions: request.claim.assertions.where(
            (reference) => !_isIdentityReference(reference.url),
          ),
          signatureType: CawgIdentityLabels.identityClaimsAggregation,
          role: role,
          expected: expected,
        );
        final credential = credentialFactory(signerPayload);
        if (!deepEquals(credential.c2paAsset, signerPayload.toJson())) {
          throw const FormatException(
            'ICA credential c2paAsset must match signer_payload',
          );
        }
        final protected = <CoseHeaderLabel, Object?>{
          CoseHeaderLabel.contentType: 'application/vc',
          if (keyId != null)
            CoseHeaderLabel.keyId: Uint8List.fromList(utf8.encode(keyId!)),
        };
        final credentialBytes = Uint8List.fromList(
          utf8.encode(jsonEncode(credential.toJson())),
        );
        final signature =
            await CoseSigner(
              backends: {
                SigningAlgorithm.ed25519: _CallbackSigningBackend(signer),
              },
            ).sign(
              algorithm: SigningAlgorithm.ed25519,
              payload: credentialBytes,
              protectedHeaders: CoseHeaders(protected),
            );
        return C2paDynamicAssertionOutput.cbor(
          label: label,
          data: _fitIdentityAssertion(
            payload: signerPayload,
            signature: signature,
            size: request.reservedSize,
          ).toCborMap(),
        );
      },
    );
  }
}

/// Issuer value from a CAWG identity-claims credential.
final class CawgIssuer {
  /// Creates an issuer with optional JSON object fields.
  CawgIssuer({required this.id, Map<String, Object?> fields = const {}})
    : fields = freezeJsonMap(fields);

  /// Parses a credential issuer from a string or JSON object.
  factory CawgIssuer.fromJson(Object? value) {
    if (value is String) return CawgIssuer(id: value);
    final map = _stringMap(value, 'VC issuer');
    final id = map['id'];
    if (id is! String) {
      throw const FormatException('VC issuer object requires id');
    }
    return CawgIssuer(id: id, fields: unknownFieldsOf(map, const {'id'}));
  }

  /// Issuer identifier string, commonly a DID.
  final String id;

  /// Additional issuer object fields preserved for JSON output.
  final Map<String, Object?> fields;

  /// Encodes the issuer as either a string or JSON object.
  Object toJson() => fields.isEmpty ? id : {...fields, 'id': id};

  @override
  bool operator ==(Object other) =>
      other is CawgIssuer && id == other.id && deepEquals(fields, other.fields);

  @override
  int get hashCode => Object.hash(id, deepHash(fields));
}

/// Verified identity provider entry in an ICA credential.
final class CawgIdentityProvider {
  /// Creates a verified identity provider.
  ///
  /// Throws FormatException when the URI or provider name is empty.
  CawgIdentityProvider({
    required this.id,
    required this.name,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (id.toString().isEmpty || name.isEmpty) {
      throw const FormatException('Malformed verified identity provider');
    }
  }

  /// Parses a verified identity provider from JSON.
  factory CawgIdentityProvider.fromJson(Object? value) {
    final map = _stringMap(value, 'verified identity provider');
    final id = map['id'];
    final name = map['name'];
    final uri = id is String ? Uri.tryParse(id) : null;
    if (uri == null || name is! String) {
      throw const FormatException('Malformed verified identity provider');
    }
    return CawgIdentityProvider(
      id: uri,
      name: name,
      unknownFields: unknownFieldsOf(map, const {'id', 'name'}),
    );
  }

  /// Provider identifier URI.
  final Uri id;

  /// Human-readable provider name; must be non-empty.
  final String name;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'id': id.toString(),
    'name': name,
  };

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityProvider &&
      id == other.id &&
      name == other.name &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(id, name, deepHash(unknownFields));
}

/// Verified identity claim embedded in an ICA credential.
final class CawgVerifiedIdentity {
  /// Creates a verified identity claim.
  ///
  /// Throws FormatException when required or supplied identity strings are
  /// empty.
  CawgVerifiedIdentity({
    required this.type,
    required DateTime verifiedAt,
    required this.provider,
    this.name,
    this.username,
    this.address,
    this.uri,
    Map<String, Object?> unknownFields = const {},
  }) : verifiedAt = verifiedAt.toUtc(),
       unknownFields = freezeJsonMap(unknownFields) {
    if (type.isEmpty ||
        (name != null && name!.isEmpty) ||
        (username != null && username!.isEmpty) ||
        (address != null && address!.isEmpty)) {
      throw const FormatException('Malformed verified identity');
    }
  }

  /// Parses a verified identity claim from JSON.
  factory CawgVerifiedIdentity.fromJson(Object? value) {
    final map = _stringMap(value, 'verified identity');
    final type = map['type'];
    final verifiedAt = map['verifiedAt'];
    if (type is! String || verifiedAt is! String) {
      throw const FormatException('Malformed verified identity');
    }
    final parsedTime = DateTime.tryParse(verifiedAt);
    final uri = map['uri'];
    if (parsedTime == null || (uri != null && uri is! String)) {
      throw const FormatException('Malformed verified identity');
    }
    return CawgVerifiedIdentity(
      type: type,
      verifiedAt: parsedTime,
      provider: CawgIdentityProvider.fromJson(map['provider']),
      name: map['name'] as String?,
      username: map['username'] as String?,
      address: map['address'] as String?,
      uri: uri == null ? null : Uri.parse(uri as String),
      unknownFields: unknownFieldsOf(map, const {
        'type',
        'name',
        'username',
        'address',
        'uri',
        'verifiedAt',
        'provider',
      }),
    );
  }

  /// Identity category such as a person, organization, or account.
  final String type;

  /// Optional display name for the verified identity.
  final String? name;

  /// Optional username or handle for the verified identity.
  final String? username;

  /// Optional address string for the verified identity.
  final String? address;

  /// Optional URI associated with the verified identity.
  final Uri? uri;

  /// UTC timestamp when the provider verified the identity.
  final DateTime verifiedAt;

  /// Provider that verified this identity.
  final CawgIdentityProvider provider;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'type': type,
    'name': ?name,
    'username': ?username,
    'address': ?address,
    'uri': ?uri?.toString(),
    'verifiedAt': verifiedAt.toIso8601String(),
    'provider': provider.toJson(),
  };

  @override
  bool operator ==(Object other) =>
      other is CawgVerifiedIdentity &&
      type == other.type &&
      name == other.name &&
      username == other.username &&
      address == other.address &&
      uri == other.uri &&
      verifiedAt == other.verifiedAt &&
      provider == other.provider &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hash(
    type,
    name,
    username,
    address,
    uri,
    verifiedAt,
    provider,
    deepHash(unknownFields),
  );
}

/// Identity Claims Aggregation verifiable credential.
final class CawgIdentityClaimsCredential {
  /// Creates an ICA credential from VC fields and credentialSubject data.
  ///
  /// Throws FormatException when no verified identities are supplied.
  CawgIdentityClaimsCredential({
    required Iterable<String> context,
    required Iterable<String> types,
    required this.issuer,
    required Iterable<CawgVerifiedIdentity> verifiedIdentities,
    required Map<String, Object?> c2paAsset,
    this.id,
    this.validFrom,
    this.validUntil,
    this.issuanceDate,
    this.expirationDate,
    Map<String, Object?> unknownFields = const {},
    Map<String, Object?> subjectUnknownFields = const {},
    Uint8List? rawJsonBytes,
  }) : context = List<String>.unmodifiable(context),
       types = List<String>.unmodifiable(types),
       verifiedIdentities = List<CawgVerifiedIdentity>.unmodifiable(
         verifiedIdentities,
       ),
       c2paAsset = freezeJsonMap(c2paAsset),
       unknownFields = freezeJsonMap(unknownFields),
       subjectUnknownFields = freezeJsonMap(subjectUnknownFields),
       _rawJsonBytes = rawJsonBytes == null
           ? null
           : Uint8List.fromList(rawJsonBytes).asUnmodifiableView() {
    if (this.verifiedIdentities.isEmpty) {
      throw const FormatException('verifiedIdentities must not be empty');
    }
  }

  /// Parses an ICA credential from a decoded JSON value.
  factory CawgIdentityClaimsCredential.fromJson(Object? value) {
    final map = _stringMap(value, 'ICA credential');
    final context = _strings(map['@context'], '@context');
    final types = _strings(map['type'], 'type');
    final subject = _stringMap(map['credentialSubject'], 'credentialSubject');
    final identities = subject['verifiedIdentities'];
    final asset = subject['c2paAsset'];
    if (identities is! List || asset is! Map) {
      throw const FormatException('Malformed ICA credentialSubject');
    }

    return CawgIdentityClaimsCredential(
      context: context,
      types: types,
      issuer: CawgIssuer.fromJson(map['issuer']),
      verifiedIdentities: identities.map(CawgVerifiedIdentity.fromJson),
      c2paAsset: _stringMap(asset, 'c2paAsset'),
      id: map['id'] as String?,
      validFrom: _optionalDate(map['validFrom'], 'validFrom'),
      validUntil: _optionalDate(map['validUntil'], 'validUntil'),
      issuanceDate: _optionalDate(map['issuanceDate'], 'issuanceDate'),
      expirationDate: _optionalDate(map['expirationDate'], 'expirationDate'),
      unknownFields: unknownFieldsOf(map, const {
        '@context',
        'type',
        'issuer',
        'id',
        'validFrom',
        'validUntil',
        'issuanceDate',
        'expirationDate',
        'credentialSubject',
      }),
      subjectUnknownFields: unknownFieldsOf(subject, const {
        'verifiedIdentities',
        'c2paAsset',
      }),
    );
  }

  /// Decodes an ICA credential from UTF-8 JSON bytes.
  factory CawgIdentityClaimsCredential.decode(Uint8List bytes) {
    final value = jsonDecode(utf8.decode(bytes));
    final parsed = CawgIdentityClaimsCredential.fromJson(value);
    return CawgIdentityClaimsCredential(
      context: parsed.context,
      types: parsed.types,
      issuer: parsed.issuer,
      verifiedIdentities: parsed.verifiedIdentities,
      c2paAsset: parsed.c2paAsset,
      id: parsed.id,
      validFrom: parsed.validFrom,
      validUntil: parsed.validUntil,
      issuanceDate: parsed.issuanceDate,
      expirationDate: parsed.expirationDate,
      unknownFields: parsed.unknownFields,
      subjectUnknownFields: parsed.subjectUnknownFields,
      rawJsonBytes: bytes,
    );
  }

  /// Verifiable Credential context values from `@context`.
  final List<String> context;

  /// Credential type values from `type`.
  final List<String> types;

  /// Credential issuer.
  final CawgIssuer issuer;

  /// Non-empty verified identities in `credentialSubject`.
  final List<CawgVerifiedIdentity> verifiedIdentities;

  /// Signer-payload JSON stored in `credentialSubject.c2paAsset`.
  final Map<String, Object?> c2paAsset;

  /// Optional credential identifier.
  final String? id;

  /// Optional UTC instant when the credential becomes valid.
  final DateTime? validFrom;

  /// Optional UTC instant when the credential stops being valid.
  final DateTime? validUntil;

  /// Optional VC 1.1 issuance timestamp.
  final DateTime? issuanceDate;

  /// Optional VC 1.1 expiration timestamp.
  final DateTime? expirationDate;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Additional `credentialSubject` fields preserved for JSON output.
  final Map<String, Object?> subjectUnknownFields;
  final Uint8List? _rawJsonBytes;

  /// Original credential JSON bytes, or null when constructed from fields.
  Uint8List? get rawJsonBytes => _rawJsonBytes == null
      ? null
      : Uint8List.fromList(_rawJsonBytes).asUnmodifiableView();

  /// Whether the credential declares the VC 1.1 context.
  bool get isVc11 => context.contains('https://www.w3.org/2018/credentials/v1');

  /// Whether the credential declares the VC 2.0 context.
  bool get isVc20 => context.contains('https://www.w3.org/ns/credentials/v2');

  /// Encodes this value as a JSON-compatible map.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    '@context': context,
    'type': types,
    'issuer': issuer.toJson(),
    'id': ?id,
    'validFrom': ?validFrom?.toIso8601String(),
    'validUntil': ?validUntil?.toIso8601String(),
    'issuanceDate': ?issuanceDate?.toIso8601String(),
    'expirationDate': ?expirationDate?.toIso8601String(),
    'credentialSubject': {
      ...subjectUnknownFields,
      'verifiedIdentities': verifiedIdentities
          .map((identity) => identity.toJson())
          .toList(growable: false),
      'c2paAsset': c2paAsset,
    },
  };

  /// Encodes the credential to UTF-8 JSON, preserving original bytes.
  Uint8List encodeJson() => _rawJsonBytes == null
      ? Uint8List.fromList(utf8.encode(jsonEncode(toJson())))
      : Uint8List.fromList(_rawJsonBytes);

  @override
  bool operator ==(Object other) =>
      other is CawgIdentityClaimsCredential &&
      deepEquals(context, other.context) &&
      deepEquals(types, other.types) &&
      issuer == other.issuer &&
      deepEquals(verifiedIdentities, other.verifiedIdentities) &&
      deepEquals(c2paAsset, other.c2paAsset) &&
      id == other.id &&
      validFrom == other.validFrom &&
      validUntil == other.validUntil &&
      issuanceDate == other.issuanceDate &&
      expirationDate == other.expirationDate &&
      deepEquals(unknownFields, other.unknownFields) &&
      deepEquals(subjectUnknownFields, other.subjectUnknownFields);

  @override
  int get hashCode => Object.hash(
    deepHash(context),
    deepHash(types),
    issuer,
    deepHash(verifiedIdentities),
    deepHash(c2paAsset),
    id,
    validFrom,
    validUntil,
    issuanceDate,
    expirationDate,
    deepHash(unknownFields),
    deepHash(subjectUnknownFields),
  );
}

/// Verifier for CAWG identity-claims aggregation credentials.
final class CawgIcaVerifier {
  /// Creates an ICA verifier using the selected compatibility profile.
  const CawgIcaVerifier({this.compatibility = CawgIcaCompatibility.stable11});

  /// Compatibility profile that controls ICA validation edge cases.
  final CawgIcaCompatibility compatibility;

  /// Verifies a CAWG X.509 COSE signature and related trust evidence.
  Future<CawgX509Verification> verify(
    CawgIdentityAssertion assertion,
    C2paContext context,
  ) async {
    final statuses = <CawgValidationStatus>[];
    late _CawgCoseEnvelope envelope;
    try {
      envelope = _CawgCoseEnvelope.parse(assertion.signature);
    } on _CawgInvalidProtectedHeaders catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidAlgorithm,
          severity: CawgStatusSeverity.failure,
          explanation: error.message,
        ),
      ], null);
    } on Object catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidCose,
          severity: CawgStatusSeverity.failure,
          explanation: error.toString(),
        ),
      ], null);
    }
    late CoseSign1 message;
    try {
      message = CoseSign1.parse(
        envelope.sanitizedBytes,
        allowTagged: true,
        allowUntagged: false,
      );
    } on CoseException catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: _isAlgorithmCoseError(error.code)
              ? CawgStatusCodes.icaInvalidAlgorithm
              : CawgStatusCodes.icaInvalidCose,
          severity: CawgStatusSeverity.failure,
          explanation: error.toString(),
        ),
      ], null);
    }
    try {
      if (envelope.textHeaders.containsKey('sigTst')) {
        return CawgX509Verification([
          const CawgValidationStatus(
            code: CawgStatusCodes.icaTimestampInvalid,
            severity: CawgStatusSeverity.failure,
            explanation: 'CAWG 1.1 permits sigTst2 only',
          ),
        ], null);
      }
      final contentType = message.protectedHeaders[CoseHeaderLabel.contentType];
      if (contentType != 'application/vc') {
        const status = CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidContentType,
          severity: CawgStatusSeverity.failure,
        );
        if (compatibility == CawgIcaCompatibility.stable11) {
          return CawgX509Verification([status], null);
        }
        statuses.add(status);
      }
      late SigningAlgorithm algorithm;
      try {
        final algorithmId = message.protectedHeaders[CoseHeaderLabel.algorithm];
        if (algorithmId is! int) {
          throw const FormatException('ICA COSE algorithm is missing');
        }
        algorithm = SigningAlgorithm.fromCoseId(algorithmId);
      } on Object catch (error) {
        return CawgX509Verification([
          CawgValidationStatus(
            code: CawgStatusCodes.icaInvalidAlgorithm,
            severity: CawgStatusSeverity.failure,
            explanation: error.toString(),
          ),
        ], null);
      }
      if (algorithm != SigningAlgorithm.ed25519) {
        return CawgX509Verification([
          const CawgValidationStatus(
            code: CawgStatusCodes.icaInvalidAlgorithm,
            severity: CawgStatusSeverity.failure,
          ),
        ], null);
      }
      final payload = message.payload;
      if (payload == null) {
        return CawgX509Verification([
          const CawgValidationStatus(
            code: CawgStatusCodes.icaInvalidCredential,
            severity: CawgStatusSeverity.failure,
            explanation: 'ICA COSE payload must be embedded',
          ),
        ], null);
      }
      final credential = CawgIdentityClaimsCredential.decode(payload);
      _validateCredentialProfile(credential);
      final publicKey = await _resolveIssuer(
        credential.issuer.id,
        message,
        context,
      );
      final valid = await _verifyCoseWithProtectedBytes(
        Ed25519VerificationBackend(publicKey),
        algorithm,
        envelope.protectedBytes,
        payload,
        message.signature,
      );
      if (!valid) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaSignatureMismatch,
            severity: CawgStatusSeverity.failure,
          ),
        );
        if (compatibility == CawgIcaCompatibility.c2paRs09022) {
          return CawgX509Verification(statuses, null);
        }
      }
      DateTime? timestampTime;
      final sigTst2 = envelope.textHeaders['sigTst2'];
      if (sigTst2 != null) {
        final token = _timestampToken(sigTst2);
        if (token == null) {
          statuses.add(
            const CawgValidationStatus(
              code: CawgStatusCodes.icaTimestampInvalid,
              severity: CawgStatusSeverity.failure,
            ),
          );
          if (compatibility == CawgIcaCompatibility.c2paRs09022) {
            return CawgX509Verification(statuses, null);
          }
        } else {
          final trust = context.timestampTrust;
          var result = await verifyTimestampToken(
            token,
            signedBytes: encodeCbor(<Object?>[
              'CounterSignature',
              envelope.protectedBytes,
              Uint8List(0),
              encodeCbor(message.signature),
            ]),
            trustPolicy: TrustPolicy(
              trustAnchors: trust.trustAnchors,
              intermediates: trust.intermediates,
              allowedEndEntitySha256Hashes: trust.allowedEndEntitySha256Hashes,
              evaluationTime: trust.evaluationTime,
              maxDepth: trust.maxPathDepth,
            ),
          );
          if (compatibility == CawgIcaCompatibility.c2paRs09022 &&
              result.issues.any(
                (issue) =>
                    issue.code == TimestampIssueCode.malformedToken &&
                    issue.message.contains(
                      'certificate set is not in canonical DER order',
                    ),
              )) {
            final normalized = _sortCmsCertificateSet(token);
            if (normalized != null) {
              result = await verifyTimestampToken(
                normalized,
                signedBytes: encodeCbor(<Object?>[
                  'CounterSignature',
                  envelope.protectedBytes,
                  Uint8List(0),
                  encodeCbor(message.signature),
                ]),
                trustPolicy: TrustPolicy(
                  trustAnchors: trust.trustAnchors,
                  intermediates: trust.intermediates,
                  allowedEndEntitySha256Hashes:
                      trust.allowedEndEntitySha256Hashes,
                  evaluationTime: trust.evaluationTime,
                  maxDepth: trust.maxPathDepth,
                ),
              );
            }
          }
          final timestampValid =
              result.isValid ||
              (compatibility == CawgIcaCompatibility.c2paRs09022 &&
                  result.token != null &&
                  result.issues.every(
                    (issue) =>
                        issue.code ==
                        TimestampIssueCode.untrustedCertificatePath,
                  ));
          statuses.add(
            CawgValidationStatus(
              code: timestampValid
                  ? CawgStatusCodes.icaTimestampValidated
                  : CawgStatusCodes.icaTimestampInvalid,
              severity: timestampValid
                  ? CawgStatusSeverity.success
                  : CawgStatusSeverity.failure,
            ),
          );
          if (timestampValid) {
            timestampTime = result.token!.timestampInfo.genTime.toUtc();
          } else if (compatibility == CawgIcaCompatibility.c2paRs09022) {
            return CawgX509Verification(statuses, null);
          }
        }
      }

      final now =
          timestampTime ??
          context.cawgTrust.evaluationTime?.toUtc() ??
          DateTime.now().toUtc();
      final validFrom = compatibility == CawgIcaCompatibility.stable11
          ? credential.validFrom ?? credential.issuanceDate
          : credential.validFrom;
      if (validFrom == null) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaValidFromMissing,
            severity: CawgStatusSeverity.failure,
          ),
        );
      } else if (validFrom.isAfter(now)) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaValidFromInvalid,
            severity: CawgStatusSeverity.failure,
          ),
        );
      }
      final validUntil = compatibility == CawgIcaCompatibility.stable11
          ? credential.validUntil ?? credential.expirationDate
          : credential.validUntil;
      if (validUntil != null && validUntil.isBefore(now)) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaValidUntilInvalid,
            severity: CawgStatusSeverity.failure,
          ),
        );
      }
      if (!_icaAssetMatches(
        credential.c2paAsset,
        assertion.signerPayload,
        compatibility: compatibility,
      )) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaAssetMismatch,
            severity: CawgStatusSeverity.failure,
          ),
        );
      }
      if (valid &&
          !statuses.any(
            (status) => status.severity == CawgStatusSeverity.failure,
          )) {
        statuses.add(
          const CawgValidationStatus(
            code: CawgStatusCodes.icaCredentialValid,
            severity: CawgStatusSeverity.success,
          ),
        );
        if (compatibility == CawgIcaCompatibility.stable11) {
          statuses.add(
            const CawgValidationStatus(
              code: CawgStatusCodes.trusted,
              severity: CawgStatusSeverity.success,
            ),
          );
        }
      }
      return CawgX509Verification(statuses, {
        'type': CawgIdentityLabels.identityClaimsAggregation,
        'issuer': credential.issuer.id.toString(),
        'verifiedIdentities': credential.verifiedIdentities
            .map(_verifiedIdentitySummary)
            .toList(growable: false),
      });
    } on CoseException catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidCose,
          severity: CawgStatusSeverity.failure,
          explanation: error.toString(),
        ),
      ], null);
    } on _CawgUnsupportedIssuer catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaIssuerUnsupported,
          severity: CawgStatusSeverity.failure,
          explanation: error.message,
        ),
      ], null);
    } on _CawgDidResolutionFailure catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaDidResolutionFailed,
          severity: CawgStatusSeverity.failure,
          explanation: error.message,
        ),
      ], null);
    } on _CawgInvalidDidDocument catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidDidDocument,
          severity: CawgStatusSeverity.failure,
          explanation: error.message,
        ),
      ], null);
    } on Object catch (error) {
      return CawgX509Verification([
        CawgValidationStatus(
          code: CawgStatusCodes.icaInvalidCredential,
          severity: CawgStatusSeverity.failure,
          explanation: error.toString(),
        ),
      ], null);
    }
  }

  void _validateCredentialProfile(CawgIdentityClaimsCredential credential) {
    final validContext =
        credential.context.contains(
          'https://cawg.io/identity/1.1/ica/context/',
        ) &&
        (credential.isVc11 || credential.isVc20);
    if (!validContext ||
        !credential.types.contains('VerifiableCredential') ||
        !credential.types.contains('IdentityClaimsAggregationCredential')) {
      throw const FormatException('ICA credential profile is invalid');
    }
    if (compatibility == CawgIcaCompatibility.c2paRs09022 &&
        !credential.isVc20) {
      throw const FormatException(
        'c2pa-rs 0.90.22 compatibility requires VC 2.0',
      );
    }
  }

  Future<SimplePublicKey> _resolveIssuer(
    String issuer,
    CoseSign1 message,
    C2paContext context,
  ) async {
    if (issuer.startsWith('did:jwk:')) {
      try {
        return _didJwkKey(issuer);
      } on Object catch (error) {
        throw _CawgInvalidDidDocument(error.toString());
      }
    }
    if (issuer.startsWith('did:web:')) {
      return _didWebKey(issuer, message, context);
    }
    throw const _CawgUnsupportedIssuer('Unsupported ICA issuer DID method');
  }

  Future<SimplePublicKey> _didWebKey(
    String did,
    CoseSign1 message,
    C2paContext context,
  ) async {
    final resolver = context.didWebResolver;
    if (resolver == null) {
      throw const _CawgDidResolutionFailure(
        'did:web resolution is unavailable',
      );
    }
    final uri = _didWebUri(did);
    late Uint8List bytes;
    try {
      bytes = await resolveRemoteManifest(
        uri: uri,
        resolver: resolver,
        policy: context.didWebPolicy,
        timeout: context.settings.networkTimeout,
        isCancelled: context.isCancelled,
        acceptedContentTypes: const {
          'application/did+json',
          'application/json',
        },
      );
    } on Object catch (error) {
      throw _CawgDidResolutionFailure(error.toString());
    }
    try {
      final document = _stringMap(
        jsonDecode(utf8.decode(bytes)),
        'DID document',
      );
      if (document['id'] != did) {
        throw const FormatException('DID document id does not match issuer');
      }
      final methods = document['verificationMethod'];
      if (methods != null && methods is! List) {
        throw const FormatException(
          'DID document verificationMethod must be an array',
        );
      }
      final kid = message.protectedHeaders[CoseHeaderLabel.keyId];
      final keyId = kid is Uint8List ? utf8.decode(kid) : null;
      final methodMaps = (methods as List? ?? const <Object?>[])
          .map((value) => _stringMap(value, 'verificationMethod'))
          .toList(growable: false);
      final assertionMethods = document['assertionMethod'];
      if (assertionMethods is! List || assertionMethods.isEmpty) {
        throw const FormatException('DID document has no assertionMethod');
      }
      final authorized = <Map<String, Object?>>[];
      for (final value in assertionMethods) {
        if (value is String) {
          final referenced = methodMaps.where(
            (method) => method['id'] == value,
          );
          if (referenced.isEmpty) {
            throw const FormatException(
              'assertionMethod references an unknown verification method',
            );
          }
          authorized.add(referenced.single);
        } else {
          authorized.add(_stringMap(value, 'assertionMethod'));
        }
      }
      final method = authorized.firstWhere(
        (value) => keyId == null || value['id'] == keyId,
        orElse: () =>
            throw const FormatException('DID assertion method was not found'),
      );
      final jwk = method['publicKeyJwk'];
      if (jwk is! Map) {
        throw const FormatException('DID method requires publicKeyJwk');
      }
      return _publicJwkKey(_stringMap(jwk, 'publicKeyJwk'));
    } on Object catch (error) {
      throw _CawgInvalidDidDocument(error.toString());
    }
  }
}

CawgIdentityAssertion _fitIdentityAssertion({
  required CawgSignerPayload payload,
  required Uint8List signature,
  required int size,
}) {
  final empty = CawgIdentityAssertion(
    signerPayload: payload,
    signature: signature,
  );
  final minimum = empty.encode().length;
  if (minimum > size) {
    throw StateError(
      'CAWG identity assertion requires $minimum bytes, reservation is $size',
    );
  }
  final estimate = size - minimum;
  for (var adjustment = 0; adjustment <= 16; adjustment++) {
    final padding = estimate - adjustment;
    if (padding < 0) continue;
    final assertion = CawgIdentityAssertion(
      signerPayload: payload,
      signature: signature,
      pad1: Uint8List(padding),
    );
    if (assertion.encode().length == size) return assertion;
  }
  for (var pad1Length = 0; pad1Length <= 32; pad1Length++) {
    final base = CawgIdentityAssertion(
      signerPayload: payload,
      signature: signature,
      pad1: Uint8List(pad1Length),
      pad2: Uint8List(0),
    ).encode().length;
    final pad2Estimate = size - base;
    for (var offset = -8; offset <= 8; offset++) {
      final pad2Length = pad2Estimate + offset;
      if (pad2Length < 0) continue;
      final assertion = CawgIdentityAssertion(
        signerPayload: payload,
        signature: signature,
        pad1: Uint8List(pad1Length),
        pad2: Uint8List(pad2Length),
      );
      if (assertion.encode().length == size) return assertion;
    }
  }
  throw StateError('Unable to fit CAWG identity assertion reservation');
}

final class _CallbackSigningBackend implements CoseSigningBackend {
  const _CallbackSigningBackend(this.signer);

  /// Signer callback used to produce COSE signatures.
  final C2paSigner signer;

  @override
  Future<List<int>> sign(SigningAlgorithm algorithm, List<int> data) =>
      signer.sign(Uint8List.fromList(data));
}

final class _CallbackVerificationBackend implements CoseVerificationBackend {
  const _CallbackVerificationBackend(this.verifier, this.publicKey);
  final C2paVerifier verifier;
  final Uint8List publicKey;

  @override
  Future<bool> verify(
    SigningAlgorithm algorithm,
    List<int> data,
    List<int> signature,
  ) => verifier.verify(
    algorithm: algorithm.name,
    data: Uint8List.fromList(data),
    signature: Uint8List.fromList(signature),
    publicKey: publicKey,
  );
}

Future<CoseVerificationBackend> _verificationBackend(
  SigningAlgorithm algorithm,
  X509Certificate certificate,
  C2paVerifier? callback,
) async {
  if (callback != null) {
    return _CallbackVerificationBackend(
      callback,
      certificate.subjectPublicKeyInfoDer,
    );
  }
  switch (algorithm) {
    case SigningAlgorithm.es256:
    case SigningAlgorithm.es384:
    case SigningAlgorithm.es512:
      return WebCryptoEcdsaVerificationBackend(
        algorithm,
        await importEcdsaPublicKeySpki(
          algorithm,
          certificate.subjectPublicKeyInfoDer,
        ),
      );
    case SigningAlgorithm.ps256:
    case SigningAlgorithm.ps384:
    case SigningAlgorithm.ps512:
      return WebCryptoRsaPssVerificationBackend(
        algorithm,
        await importRsaPssPublicKeySpki(
          algorithm,
          certificate.subjectPublicKeyInfoDer,
        ),
      );
    case SigningAlgorithm.ed25519:
      return Ed25519VerificationBackend(
        SimplePublicKey(
          certificate.subjectPublicKey,
          type: KeyPairType.ed25519,
        ),
      );
  }
}

List<Uint8List> _x5chain(CoseSign1 message) {
  final value =
      message.protectedHeaders[CoseHeaderLabel.x509Chain] ??
      message.unprotectedHeaders[CoseHeaderLabel.x509Chain];
  if (value is Uint8List) return [value];
  if (value is List && value.isNotEmpty && value.every((v) => v is Uint8List)) {
    return value.cast<Uint8List>();
  }
  throw const FormatException('CAWG X.509 signature requires x5chain');
}

final class _CawgCoseEnvelope {
  _CawgCoseEnvelope(this.sanitizedBytes, this.textHeaders, this.protectedBytes);
  final Uint8List sanitizedBytes;
  final Map<String, Object?> textHeaders;
  final Uint8List protectedBytes;

  factory _CawgCoseEnvelope.parse(Uint8List bytes) {
    final tagged = bytes.isNotEmpty && bytes.first == 0xd2;
    final decoded = decodeCbor(
      tagged ? Uint8List.sublistView(bytes, 1) : bytes,
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );
    if (decoded is! List || decoded.length != 4 || decoded[1] is! Map) {
      throw const FormatException('Malformed COSE_Sign1');
    }
    final protectedBytes = decoded[0];
    if (protectedBytes is! Uint8List) {
      throw const FormatException('Malformed COSE protected headers');
    }
    late Object? protectedHeaders;
    try {
      protectedHeaders = protectedBytes.isEmpty
          ? <Object?, Object?>{}
          : decodeCbor(
              protectedBytes,
              requireCanonicalMapOrder: false,
              allowIndefiniteLength: true,
            );
    } on Object catch (error) {
      throw _CawgInvalidProtectedHeaders(error.toString());
    }
    if (protectedHeaders is! Map) {
      throw const _CawgInvalidProtectedHeaders(
        'Malformed COSE protected headers',
      );
    }
    final numeric = <Object?, Object?>{};
    final text = <String, Object?>{};
    for (final entry in (decoded[1] as Map).entries) {
      if (entry.key is String) {
        text[entry.key as String] = entry.value;
      } else {
        numeric[entry.key] = entry.value;
      }
    }
    final sanitized = encodeCbor([
      encodeCbor(protectedHeaders),
      numeric,
      decoded[2],
      decoded[3],
    ]);
    return _CawgCoseEnvelope(
      tagged ? Uint8List.fromList([0xd2, ...sanitized]) : sanitized,
      Map.unmodifiable(text),
      protectedBytes,
    );
  }
}

Future<bool> _verifyCoseWithProtectedBytes(
  CoseVerificationBackend backend,
  SigningAlgorithm algorithm,
  Uint8List protectedBytes,
  Uint8List payload,
  Uint8List signature,
) => backend.verify(
  algorithm,
  encodeCbor(['Signature1', protectedBytes, Uint8List(0), payload]),
  signature,
);

bool _isAlgorithmCoseError(CoseErrorCode code) =>
    code == CoseErrorCode.missingProtectedAlgorithm ||
    code == CoseErrorCode.invalidHeaderLabel ||
    code == CoseErrorCode.invalidHeaderValue ||
    code == CoseErrorCode.duplicateHeader;

Uint8List? _timestampToken(Object? value) {
  if (value is Uint8List) return value;
  if (value is Map) {
    final tokens = value['tstTokens'];
    if (tokens is List && tokens.isNotEmpty) {
      final first = tokens.first;
      if (first is Uint8List) return first;
      if (first is Map && first['val'] is Uint8List) {
        return first['val'] as Uint8List;
      }
    }
    if (value['val'] is Uint8List) return value['val'] as Uint8List;
  }
  return null;
}

Uint8List? _firstByteString(Object? value, String key) {
  if (value is! Map) return null;
  final values = value[key];
  if (values is Uint8List) return values;
  if (values is List && values.isNotEmpty && values.first is Uint8List) {
    return values.first as Uint8List;
  }
  return null;
}

SimplePublicKey _didJwkKey(String did) {
  final encoded = did.substring('did:jwk:'.length);
  final decoded = utf8.decode(base64Url.decode(base64Url.normalize(encoded)));
  return _publicJwkKey(_stringMap(jsonDecode(decoded), 'did:jwk'));
}

SimplePublicKey _publicJwkKey(Map<String, Object?> jwk) {
  if (jwk['kty'] != 'OKP' ||
      jwk['crv'] != 'Ed25519' ||
      jwk['x'] is! String ||
      jwk.containsKey('d')) {
    throw const FormatException('Expected a public Ed25519 OKP JWK');
  }
  final bytes = base64Url.decode(base64Url.normalize(jwk['x']! as String));
  if (bytes.length != 32) {
    throw const FormatException('Ed25519 JWK x must contain 32 bytes');
  }
  return SimplePublicKey(bytes, type: KeyPairType.ed25519);
}

/// Renders a distinguished name for display, preferring the organization then
/// the common name, matching how signer names are surfaced elsewhere.
String _distinguishedNameText(X509DistinguishedName name) {
  String? attribute(String oid) {
    for (final entry in name.attributes.reversed) {
      if (entry.oid == oid) return entry.value;
    }
    return null;
  }

  return attribute('2.5.4.10') ??
      attribute('2.5.4.3') ??
      name.attributes.lastOrNull?.value ??
      '';
}

Uri _didWebUri(String did) {
  final segments = did.substring('did:web:'.length).split(':');
  if (segments.isEmpty || segments.first.isEmpty) {
    throw const FormatException('Malformed did:web identifier');
  }
  final authority = Uri.decodeComponent(segments.first);
  final authorityUri = Uri.tryParse('https://$authority');
  if (authorityUri == null || authorityUri.host.isEmpty) {
    throw const FormatException('Malformed did:web authority');
  }
  final decodedSegments = segments.skip(1).map(Uri.decodeComponent).toList();
  if (decodedSegments.any(
    (segment) =>
        segment.isEmpty ||
        segment == '.' ||
        segment == '..' ||
        segment.contains('/') ||
        segment.contains(r'\'),
  )) {
    throw const FormatException('Malformed did:web path');
  }
  final path = segments.length == 1
      ? '/.well-known/did.json'
      : '/${decodedSegments.join('/')}/did.json';
  return Uri(
    scheme: 'https',
    host: authorityUri.host,
    port: authorityUri.hasPort ? authorityUri.port : null,
    path: path,
  );
}

Map<String, Object?> _verifiedIdentitySummary(CawgVerifiedIdentity identity) =>
    {
      'type': identity.type,
      'name': ?identity.name,
      'username': ?identity.username,
      'address': ?identity.address,
      'uri': ?identity.uri?.toString(),
      'verifiedAt': identity.verifiedAt.toIso8601String(),
      'provider': {
        'id': identity.provider.id.toString(),
        'name': identity.provider.name,
      },
    };

bool _icaAssetMatches(
  Map<String, Object?> credentialAsset,
  CawgSignerPayload signerPayload, {
  required CawgIcaCompatibility compatibility,
}) {
  final actual = _mutableJsonMap(credentialAsset);
  final expected = _mutableJsonMap(signerPayload.toJson());
  final actualReferences = actual['referenced_assertions'];
  final expectedReferences = expected['referenced_assertions'];
  if (actualReferences is List && expectedReferences is List) {
    for (
      var index = 0;
      index < actualReferences.length && index < expectedReferences.length;
      index++
    ) {
      final actualReference = actualReferences[index];
      final expectedReference = expectedReferences[index];
      if (actualReference is! Map || expectedReference is! Map) {
        continue;
      }
      final actualMap = actualReference.cast<String, Object?>();
      final expectedMap = expectedReference.cast<String, Object?>();
      final hash = actualMap['hash'];
      if (hash is List && hash.every((value) => value is int)) {
        try {
          actualMap['hash'] = utf8.decode(hash.cast<int>());
        } on FormatException {
          return false;
        }
      }
      final actualAlgorithm = actualMap['alg'];
      if (compatibility == CawgIcaCompatibility.c2paRs09022 &&
          !expectedMap.containsKey('alg') &&
          actualAlgorithm is String) {
        expectedMap['alg'] = actualMap['alg'];
      }
    }
  }
  return deepEquals(actual, expected);
}

Map<String, Object?> _mutableJsonMap(Map<String, Object?> value) =>
    value.map((key, child) => MapEntry(key, _mutableJsonValue(child)));

Object? _mutableJsonValue(Object? value) {
  if (value is Map) {
    return value.map(
      (key, child) => MapEntry(key.toString(), _mutableJsonValue(child)),
    );
  }
  if (value is List) {
    return value.map(_mutableJsonValue).toList();
  }
  return value;
}

Uint8List? _sortCmsCertificateSet(Uint8List bytes) {
  try {
    final contentInfo = _DerSlice.read(bytes, 0);
    if (contentInfo.tag != 0x30 || contentInfo.end != bytes.length) return null;
    final contentChildren = contentInfo.children();
    if (contentChildren.length < 2 || contentChildren[1].tag != 0xa0) {
      return null;
    }
    final wrapperChildren = contentChildren[1].children();
    if (wrapperChildren.length != 1 || wrapperChildren.single.tag != 0x30) {
      return null;
    }
    final signedData = wrapperChildren.single;
    final signedChildren = signedData.children();
    final certificateIndex = signedChildren.indexWhere(
      (child) => child.tag == 0xa0,
      3,
    );
    if (certificateIndex < 0) return null;
    final certificates = signedChildren[certificateIndex].children()
      ..sort((left, right) => _compareByteLists(left.encoded, right.encoded));
    final normalizedCertificateSet = _encodeDer(
      0xa0,
      certificates.expand((child) => child.encoded).toList(growable: false),
    );
    final normalizedSignedData = _encodeDer(0x30, [
      for (var index = 0; index < signedChildren.length; index++)
        ...(index == certificateIndex
            ? normalizedCertificateSet
            : signedChildren[index].encoded),
    ]);
    final normalizedWrapper = _encodeDer(0xa0, normalizedSignedData);
    return Uint8List.fromList(
      _encodeDer(0x30, [
        ...contentChildren.first.encoded,
        ...normalizedWrapper,
        for (final child in contentChildren.skip(2)) ...child.encoded,
      ]),
    );
  } on FormatException {
    return null;
  }
}

int _compareByteLists(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final comparison = left[index].compareTo(right[index]);
    if (comparison != 0) return comparison;
  }
  return left.length.compareTo(right.length);
}

List<int> _encodeDer(int tag, List<int> content) => [
  tag,
  ..._encodeDerLength(content.length),
  ...content,
];

List<int> _encodeDerLength(int length) {
  if (length < 0x80) return [length];
  final bytes = <int>[];
  for (var value = length; value > 0; value >>= 8) {
    bytes.insert(0, value & 0xff);
  }
  return [0x80 | bytes.length, ...bytes];
}

final class _DerSlice {
  const _DerSlice(
    this.source,
    this.start,
    this.tag,
    this.contentStart,
    this.end,
  );

  factory _DerSlice.read(Uint8List source, int offset) {
    if (offset < 0 || offset + 2 > source.length) {
      throw const FormatException('Truncated DER value');
    }
    final tag = source[offset];
    var cursor = offset + 1;
    final firstLength = source[cursor++];
    late int length;
    if (firstLength < 0x80) {
      length = firstLength;
    } else {
      final count = firstLength & 0x7f;
      if (count == 0 || count > 4 || cursor + count > source.length) {
        throw const FormatException('Malformed DER length');
      }
      length = 0;
      for (var index = 0; index < count; index++) {
        length = (length << 8) | source[cursor++];
      }
    }
    final end = cursor + length;
    if (end > source.length) {
      throw const FormatException('Truncated DER value');
    }
    return _DerSlice(source, offset, tag, cursor, end);
  }

  final Uint8List source;
  final int start;
  final int tag;
  final int contentStart;
  final int end;

  Uint8List get encoded => Uint8List.sublistView(source, start, end);

  List<_DerSlice> children() {
    final result = <_DerSlice>[];
    var cursor = contentStart;
    while (cursor < end) {
      final child = _DerSlice.read(source, cursor);
      result.add(child);
      cursor = child.end;
    }
    if (cursor != end) throw const FormatException('Malformed DER container');
    return result;
  }
}

final class _CawgUnsupportedIssuer implements Exception {
  const _CawgUnsupportedIssuer(this.message);
  final String message;
}

final class _CawgInvalidProtectedHeaders implements Exception {
  const _CawgInvalidProtectedHeaders(this.message);
  final String message;
}

final class _CawgDidResolutionFailure implements Exception {
  const _CawgDidResolutionFailure(this.message);
  final String message;
}

final class _CawgInvalidDidDocument implements Exception {
  const _CawgInvalidDidDocument(this.message);
  final String message;
}

SigningAlgorithm _algorithmByName(String name) {
  final normalized = name.toLowerCase().replaceAll('-', '');
  return SigningAlgorithm.values.firstWhere(
    (value) => value.name == normalized,
    orElse: () =>
        throw ArgumentError.value(name, 'algorithm', 'Unsupported algorithm'),
  );
}

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map) throw FormatException('$name must be a map');
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw FormatException('$name keys must be strings');
    }
    result[entry.key as String] = entry.value;
  }
  return result;
}

/// Collects entries whose keys are not part of the known field set.
Map<String, Object?> unknownFieldsOf(
  Map<String, Object?> map,
  Set<String> known,
) => {
  for (final entry in map.entries)
    if (!known.contains(entry.key)) entry.key: entry.value,
};

List<String> _strings(Object? value, String name) {
  if (value is String) return [value];
  if (value is List && value.every((item) => item is String)) {
    return value.cast<String>();
  }
  throw FormatException('$name must be a string or string array');
}

DateTime? _optionalDate(Object? value, String name) {
  if (value == null) return null;
  if (value is! String || DateTime.tryParse(value) == null) {
    throw FormatException('$name must be an RFC 3339 timestamp');
  }
  return DateTime.parse(value).toUtc();
}

Object? _bytesToBase64(Object? value) {
  if (value is Uint8List) return base64.encode(value);
  if (value is List) return value.map(_bytesToBase64).toList(growable: false);
  if (value is Map) {
    return {
      for (final entry in value.entries)
        entry.key.toString(): _bytesToBase64(entry.value),
    };
  }
  return value;
}

String _relativeAssertionUrl(String url) {
  final marker = '/c2pa.assertions/';
  final index = url.indexOf(marker);
  if (index >= 0) return url.substring(index + 1);
  return url.startsWith('self#jumbf=/') ? url.substring(12) : url;
}

String _identityLabel(String value) =>
    Uri.decodeComponent(_relativeAssertionUrl(value).split('/').last);

bool _hasIdentityReferenceCycle(
  String start,
  Map<String, CawgIdentityAssertion> assertions,
) {
  final visiting = <String>{};
  final visited = <String>{};

  bool visit(String label) {
    if (!visiting.add(label)) return true;
    if (visited.contains(label)) {
      visiting.remove(label);
      return false;
    }
    final assertion = assertions[label];
    if (assertion != null) {
      for (final reference in assertion.signerPayload.referencedAssertions) {
        final target = _identityLabel(reference.url);
        if (_isIdentityReference(target) &&
            assertions.containsKey(target) &&
            visit(target)) {
          return true;
        }
      }
    }
    visiting.remove(label);
    visited.add(label);
    return false;
  }

  return visit(start);
}

bool _isIdentityReference(String url) {
  final label = url.split('/').last;
  return CawgIdentityLabels.isIdentity(Uri.decodeComponent(label));
}

bool _isHardBinding(String url) {
  final label = Uri.decodeComponent(url.split('/').last);
  return label == 'c2pa.hash.data' ||
      label == 'c2pa.hash.boxes' ||
      label == 'c2pa.hash.bmff.v3' ||
      label == 'c2pa.hash.collection.data';
}

Uint8List _cborMapValueBytes(Uint8List bytes, String wantedKey) {
  final cursor = _CborSliceCursor(bytes);
  final header = cursor.readHeader();
  if (header.major != 5) {
    throw const FormatException('CAWG identity assertion must be a CBOR map');
  }
  var remaining = header.indefinite ? null : header.value;
  while (remaining == null || remaining > 0) {
    if (remaining == null && cursor.isBreak) {
      cursor.offset++;
      break;
    }
    final keyStart = cursor.offset;
    final keyEnd = cursor.skipItem();
    final key = decodeCbor(
      Uint8List.sublistView(bytes, keyStart, keyEnd),
      requireCanonicalMapOrder: false,
      allowIndefiniteLength: true,
    );
    final valueStart = cursor.offset;
    final valueEnd = cursor.skipItem();
    if (key == wantedKey) {
      return Uint8List.fromList(bytes.sublist(valueStart, valueEnd));
    }
    if (remaining != null) remaining--;
  }
  throw FormatException('CAWG identity assertion is missing $wantedKey');
}

final class _CborSliceCursor {
  _CborSliceCursor(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  bool get isBreak => offset < bytes.length && bytes[offset] == 0xff;

  ({int major, int value, bool indefinite}) readHeader() {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated CBOR');
    }
    final initial = bytes[offset++];
    final major = initial >> 5;
    final additional = initial & 0x1f;
    if (additional == 31) {
      return (major: major, value: 0, indefinite: true);
    }
    if (additional < 24) {
      return (major: major, value: additional, indefinite: false);
    }
    final width = switch (additional) {
      24 => 1,
      25 => 2,
      26 => 4,
      27 => 8,
      _ => throw const FormatException('Invalid CBOR additional information'),
    };
    if (offset + width > bytes.length) {
      throw const FormatException('Truncated CBOR argument');
    }
    var value = 0;
    for (var index = 0; index < width; index++) {
      value = (value << 8) | bytes[offset++];
    }
    return (major: major, value: value, indefinite: false);
  }

  int skipItem([int depth = 0]) {
    if (depth > 128) throw const FormatException('Excessive CBOR nesting');
    final header = readHeader();
    switch (header.major) {
      case 0:
      case 1:
        break;
      case 2:
      case 3:
        if (header.indefinite) {
          while (!isBreak) {
            final chunk = readHeader();
            if (chunk.major != header.major || chunk.indefinite) {
              throw const FormatException('Invalid indefinite CBOR string');
            }
            _skipBytes(chunk.value);
          }
          offset++;
        } else {
          _skipBytes(header.value);
        }
      case 4:
        if (header.indefinite) {
          while (!isBreak) {
            skipItem(depth + 1);
          }
          offset++;
        } else {
          for (var index = 0; index < header.value; index++) {
            skipItem(depth + 1);
          }
        }
      case 5:
        if (header.indefinite) {
          while (!isBreak) {
            skipItem(depth + 1);
            skipItem(depth + 1);
          }
          offset++;
        } else {
          for (var index = 0; index < header.value; index++) {
            skipItem(depth + 1);
            skipItem(depth + 1);
          }
        }
      case 6:
        if (header.indefinite) {
          throw const FormatException('Indefinite CBOR tag');
        }
        skipItem(depth + 1);
      case 7:
        if (header.indefinite) {
          throw const FormatException('Unexpected CBOR break');
        }
    }
    return offset;
  }

  void _skipBytes(int length) {
    if (length < 0 || offset + length > bytes.length) {
      throw const FormatException('Truncated CBOR value');
    }
    offset += length;
  }
}

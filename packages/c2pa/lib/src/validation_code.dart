enum ValidationSeverity { success, informational, failure }

enum ValidationClassification { runtime, specification }

/// A known C2PA SDK validation status code.
///
/// Runtime classification matches `validation_codes::log_kind` in c2pa-rs
/// v0.90.22. Unknown codes are classified as failures.
final class ValidationCode {
  const ValidationCode._(
    this.value,
    this.runtimeSeverity, [
    ValidationSeverity? specificationSeverity,
  ]) : specificationSeverity = specificationSeverity ?? runtimeSeverity;

  final String value;
  final ValidationSeverity runtimeSeverity;
  final ValidationSeverity specificationSeverity;

  ValidationSeverity severity({
    ValidationClassification classification = ValidationClassification.runtime,
  }) => switch (classification) {
    ValidationClassification.runtime => runtimeSeverity,
    ValidationClassification.specification => specificationSeverity,
  };

  static ValidationCode? lookup(String value) => registry[value];

  /// Severities for CAWG identity status codes.
  ///
  /// These are deliberately kept out of [registry], which mirrors the 89 status
  /// strings of the c2pa-rs v0.90.22 SDK exactly. CAWG identity codes are a
  /// separate namespace upstream and must not dilute that fidelity check.
  static final Map<String, ValidationSeverity>
  cawgRegistry = Map<String, ValidationSeverity>.unmodifiable({
    'cawg.identity.well-formed': ValidationSeverity.success,
    'cawg.identity.trusted': ValidationSeverity.success,
    'cawg.identity.credential.not_revoked': ValidationSeverity.success,
    'cawg.ica.time_stamp.validated': ValidationSeverity.success,
    'cawg.identity.credential.untrusted': ValidationSeverity.informational,
    'cawg.identity.credential.ocsp_unknown': ValidationSeverity.informational,
    'cawg.identity.timestamp.untrusted': ValidationSeverity.informational,
    // Upstream skips assertions with an unrecognized signature type
    // instead of invalidating the manifest.
    'cawg.identity.sig_type.unknown': ValidationSeverity.informational,
    'cawg.identity.cbor.invalid': ValidationSeverity.failure,
    'cawg.identity.pad.invalid': ValidationSeverity.failure,
    'cawg.identity.assertion.mismatch': ValidationSeverity.failure,
    'cawg.identity.assertion.duplicate': ValidationSeverity.failure,
    'cawg.identity.hard_binding_missing': ValidationSeverity.failure,
    'cawg.identity.assertion.cycle': ValidationSeverity.failure,

    'cawg.identity.signature.invalid': ValidationSeverity.failure,
    'cawg.identity.credential.invalid': ValidationSeverity.failure,
    'cawg.identity.credential.revoked': ValidationSeverity.failure,
    'cawg.identity.timestamp.malformed': ValidationSeverity.failure,
    'cawg.ica.invalid_cose_sign1': ValidationSeverity.failure,
    'cawg.ica.invalid_alg': ValidationSeverity.failure,
    'cawg.ica.invalid_content_type': ValidationSeverity.failure,
    'cawg.ica.invalid_verifiable_credential': ValidationSeverity.failure,
    'cawg.ica.signer_payload.mismatch': ValidationSeverity.failure,
    'cawg.ica.invalid_issuer': ValidationSeverity.failure,
    'cawg.ica.did_unavailable': ValidationSeverity.failure,
    'cawg.ica.invalid_did_document': ValidationSeverity.failure,
    'cawg.ica.signature_mismatch': ValidationSeverity.failure,
    'cawg.ica.time_stamp.invalid': ValidationSeverity.failure,
  });

  static ValidationSeverity classify(
    String value, {
    ValidationClassification classification = ValidationClassification.runtime,
  }) =>
      lookup(value)?.severity(classification: classification) ??
      cawgRegistry[value] ??
      ValidationSeverity.failure;

  static const claimSignatureValidated = ValidationCode._(
    'claimSignature.validated',
    ValidationSeverity.success,
  );
  static const claimSignatureInsideValidity = ValidationCode._(
    'claimSignature.insideValidity',
    ValidationSeverity.success,
  );
  static const signingCredentialTrusted = ValidationCode._(
    'signingCredential.trusted',
    ValidationSeverity.success,
  );
  static const signingCredentialNotRevoked = ValidationCode._(
    'signingCredential.ocsp.notRevoked',
    ValidationSeverity.success,
  );
  static const timestampValidated = ValidationCode._(
    'timeStamp.validated',
    ValidationSeverity.success,
  );
  static const timestampTrusted = ValidationCode._(
    'timeStamp.trusted',
    ValidationSeverity.success,
  );
  static const assertionHashedUriMatch = ValidationCode._(
    'assertion.hashedURI.match',
    ValidationSeverity.success,
  );
  static const assertionDataHashMatch = ValidationCode._(
    'assertion.dataHash.match',
    ValidationSeverity.success,
  );
  static const assertionDataHashAdditionalExclusions = ValidationCode._(
    'assertion.dataHash.additionalExclusionsPresent',
    ValidationSeverity.informational,
    ValidationSeverity.success,
  );
  static const assertionBmffHashMatch = ValidationCode._(
    'assertion.bmffHash.match',
    ValidationSeverity.success,
  );
  static const assertionBoxesHashMatch = ValidationCode._(
    'assertion.boxesHash.match',
    ValidationSeverity.success,
  );
  static const assertionCollectionHashMatch = ValidationCode._(
    'assertion.collectionHash.match',
    ValidationSeverity.success,
  );
  static const assertionAccessible = ValidationCode._(
    'assertion.accessible',
    ValidationSeverity.success,
  );
  static const ingredientManifestValidated = ValidationCode._(
    'ingredient.manifest.validated',
    ValidationSeverity.success,
  );
  static const ingredientProvenanceUnknown = ValidationCode._(
    'ingredient.unknownProvenance',
    ValidationSeverity.informational,
    ValidationSeverity.success,
  );
  static const ingredientClaimSignatureValidated = ValidationCode._(
    'ingredient.claimSignature.validated',
    ValidationSeverity.success,
  );

  static const signingCredentialOcspSkipped = ValidationCode._(
    'signingCredential.ocsp.skipped',
    ValidationSeverity.informational,
  );
  static const signingCredentialOcspInaccessible = ValidationCode._(
    'signingCredential.ocsp.inaccessible',
    ValidationSeverity.informational,
  );
  static const timestampMismatch = ValidationCode._(
    'timeStamp.mismatch',
    ValidationSeverity.informational,
  );
  static const timestampMalformed = ValidationCode._(
    'timeStamp.malformed',
    ValidationSeverity.informational,
  );
  static const timestampOutsideValidity = ValidationCode._(
    'timeStamp.outsideValidity',
    ValidationSeverity.informational,
  );
  static const timestampUntrusted = ValidationCode._(
    'timeStamp.untrusted',
    ValidationSeverity.informational,
  );
  static const manifestUnknownProvenance = ValidationCode._(
    'manifest.unknownProvenance',
    ValidationSeverity.informational,
  );
  static const manifestUnreferenced = ValidationCode._(
    'manifest.unreferenced',
    ValidationSeverity.failure,
    ValidationSeverity.informational,
  );
  static const algorithmDeprecated = ValidationCode._(
    'algorithm.deprecated',
    ValidationSeverity.informational,
  );
  static const timeOfSigningInsideValidity = ValidationCode._(
    'timeOfSigning.insideValidity',
    ValidationSeverity.informational,
  );

  static const claimMalformed = ValidationCode._(
    'claim.malformed',
    ValidationSeverity.failure,
  );
  static const claimMissing = ValidationCode._(
    'claim.missing',
    ValidationSeverity.failure,
  );
  static const claimMultiple = ValidationCode._(
    'claim.multiple',
    ValidationSeverity.failure,
  );
  static const hardBindingsMissing = ValidationCode._(
    'claim.hardBindings.missing',
    ValidationSeverity.failure,
  );
  static const hardBindingsMultiple = ValidationCode._(
    'assertion.multipleHardBindings',
    ValidationSeverity.failure,
  );
  static const claimRequiredMissing = ValidationCode._(
    'claim.required.missing',
    ValidationSeverity.failure,
  );
  static const claimCborInvalid = ValidationCode._(
    'claim.cbor.invalid',
    ValidationSeverity.failure,
  );
  static const ingredientHashedUriMismatch = ValidationCode._(
    'ingredient.hashedURI.mismatch',
    ValidationSeverity.failure,
  );
  static const claimSignatureMissing = ValidationCode._(
    'claimSignature.missing',
    ValidationSeverity.failure,
  );
  static const claimSignatureMismatch = ValidationCode._(
    'claimSignature.mismatch',
    ValidationSeverity.failure,
  );
  static const manifestInaccessible = ValidationCode._(
    'manifest.inaccessible',
    ValidationSeverity.failure,
  );
  static const manifestMultipleParents = ValidationCode._(
    'manifest.multipleParents',
    ValidationSeverity.failure,
  );
  static const manifestUpdateInvalid = ValidationCode._(
    'manifest.update.invalid',
    ValidationSeverity.failure,
  );
  static const manifestUpdateWrongParents = ValidationCode._(
    'manifest.update.wrongParents',
    ValidationSeverity.failure,
  );
  static const signingCredentialUntrusted = ValidationCode._(
    'signingCredential.untrusted',
    ValidationSeverity.failure,
  );
  static const signingCredentialInvalid = ValidationCode._(
    'signingCredential.invalid',
    ValidationSeverity.failure,
  );
  static const signingCredentialRevoked = ValidationCode._(
    'signingCredential.ocsp.revoked',
    ValidationSeverity.failure,
  );
  static const signingCredentialExpired = ValidationCode._(
    'signingCredential.expired',
    ValidationSeverity.failure,
  );
  static const assertionHashedUriMismatch = ValidationCode._(
    'assertion.hashedURI.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionMissing = ValidationCode._(
    'assertion.missing',
    ValidationSeverity.failure,
  );
  static const assertionUndeclared = ValidationCode._(
    'assertion.undeclared',
    ValidationSeverity.failure,
  );
  static const assertionInaccessible = ValidationCode._(
    'assertion.inaccessible',
    ValidationSeverity.failure,
  );
  static const assertionNotRedacted = ValidationCode._(
    'assertion.notRedacted',
    ValidationSeverity.failure,
  );
  static const assertionSelfRedacted = ValidationCode._(
    'assertion.selfRedacted',
    ValidationSeverity.failure,
  );
  static const assertionRequiredMissing = ValidationCode._(
    'assertion.required.missing',
    ValidationSeverity.failure,
  );
  static const assertionJsonInvalid = ValidationCode._(
    'assertion.json.invalid',
    ValidationSeverity.failure,
  );
  static const assertionCborInvalid = ValidationCode._(
    'assertion.cbor.invalid',
    ValidationSeverity.failure,
  );
  static const assertionActionIngredientMismatch = ValidationCode._(
    'assertion.action.ingredientMismatch',
    ValidationSeverity.failure,
  );
  static const assertionActionRedacted = ValidationCode._(
    'assertion.action.redacted',
    ValidationSeverity.failure,
  );
  static const assertionDataHashMismatch = ValidationCode._(
    'assertion.dataHash.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionBmffHashMismatch = ValidationCode._(
    'assertion.bmffHash.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionBoxesHashMismatch = ValidationCode._(
    'assertion.boxesHash.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionBoxesHashUnknownBox = ValidationCode._(
    'assertion.boxesHash.unknownBox',
    ValidationSeverity.failure,
  );
  static const assertionCloudDataHardBinding = ValidationCode._(
    'assertion.cloud-data.hardBinding',
    ValidationSeverity.failure,
  );
  static const assertionCloudDataActions = ValidationCode._(
    'assertion.cloud-data.actions',
    ValidationSeverity.failure,
  );
  static const algorithmUnsupported = ValidationCode._(
    'algorithm.unsupported',
    ValidationSeverity.failure,
  );
  static const generalError = ValidationCode._(
    'general.error',
    ValidationSeverity.failure,
  );
  static const claimSignatureOutsideValidity = ValidationCode._(
    'claimSignature.outsideValidity',
    ValidationSeverity.failure,
  );
  static const manifestTimestampInvalid = ValidationCode._(
    'manifest.timestamp.invalid',
    ValidationSeverity.failure,
  );
  static const manifestTimestampWrongParents = ValidationCode._(
    'manifest.timestamp.wrongParents',
    ValidationSeverity.failure,
  );
  static const manifestCompressedInvalid = ValidationCode._(
    'manifest.compressed.invalid',
    ValidationSeverity.failure,
  );
  static const signingCredentialOcspUnknown = ValidationCode._(
    'signingCredential.ocsp.unknown',
    ValidationSeverity.failure,
  );
  static const assertionOutsideManifest = ValidationCode._(
    'assertion.outsideManifest',
    ValidationSeverity.failure,
  );
  static const assertionActionMalformed = ValidationCode._(
    'assertion.action.malformed',
    ValidationSeverity.failure,
  );
  static const assertionActionRedactionMismatch = ValidationCode._(
    'assertion.action.redactionMismatch',
    ValidationSeverity.failure,
  );
  static const assertionDataHashMalformed = ValidationCode._(
    'assertion.dataHash.malformed',
    ValidationSeverity.failure,
  );
  static const assertionDataHashRedacted = ValidationCode._(
    'assertion.dataHash.redacted',
    ValidationSeverity.failure,
  );
  static const assertionBmffHashMalformed = ValidationCode._(
    'assertion.bmffHash.malformed',
    ValidationSeverity.failure,
  );
  static const assertionBoxesHashMalformed = ValidationCode._(
    'assertion.boxesHash.malformed',
    ValidationSeverity.failure,
  );
  static const assertionCloudDataMalformed = ValidationCode._(
    'assertion.cloud-data.malformed',
    ValidationSeverity.failure,
  );
  static const assertionCollectionHashMismatch = ValidationCode._(
    'assertion.collectionHash.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionCollectionHashIncorrectFileCount = ValidationCode._(
    'assertion.collectionHash.incorrectFileCount',
    ValidationSeverity.failure,
  );
  static const assertionCollectionHashInvalidUri = ValidationCode._(
    'assertion.collectionHash.invalidURI',
    ValidationSeverity.failure,
  );
  static const assertionCollectionHashMalformed = ValidationCode._(
    'assertion.collectionHash.malformed',
    ValidationSeverity.failure,
  );
  static const assertionIngredientMalformed = ValidationCode._(
    'assertion.ingredient.malformed',
    ValidationSeverity.failure,
  );
  static const assertionMetadataDisallowed = ValidationCode._(
    'assertion.metadata.disallowed',
    ValidationSeverity.failure,
  );
  static const ingredientManifestMissing = ValidationCode._(
    'ingredient.manifest.missing',
    ValidationSeverity.success,
    ValidationSeverity.failure,
  );
  static const ingredientManifestMismatch = ValidationCode._(
    'ingredient.manifest.mismatch',
    ValidationSeverity.failure,
  );
  static const ingredientClaimSignatureMissing = ValidationCode._(
    'ingredient.claimSignature.missing',
    ValidationSeverity.failure,
  );
  static const ingredientClaimSignatureMismatch = ValidationCode._(
    'ingredient.claimSignature.mismatch',
    ValidationSeverity.failure,
  );
  static const hashedUriMissing = ValidationCode._(
    'hashedURI.missing',
    ValidationSeverity.failure,
  );
  static const hashedUriMismatch = ValidationCode._(
    'hashedURI.mismatch',
    ValidationSeverity.failure,
  );
  static const assertionTimestampMalformed = ValidationCode._(
    'assertion.timestamp.malformed',
    ValidationSeverity.failure,
  );

  static const actionAssertionIngredientMismatch =
      assertionActionIngredientMismatch;
  static const actionAssertionRedacted = assertionActionRedacted;

  static const List<ValidationCode> all = [
    claimSignatureValidated,
    claimSignatureInsideValidity,
    signingCredentialTrusted,
    signingCredentialNotRevoked,
    timestampValidated,
    timestampTrusted,
    assertionHashedUriMatch,
    assertionDataHashMatch,
    assertionDataHashAdditionalExclusions,
    assertionBmffHashMatch,
    assertionBoxesHashMatch,
    assertionCollectionHashMatch,
    assertionAccessible,
    ingredientManifestValidated,
    ingredientProvenanceUnknown,
    ingredientClaimSignatureValidated,
    signingCredentialOcspSkipped,
    signingCredentialOcspInaccessible,
    timestampMismatch,
    timestampMalformed,
    timestampOutsideValidity,
    timestampUntrusted,
    manifestUnknownProvenance,
    manifestUnreferenced,
    algorithmDeprecated,
    timeOfSigningInsideValidity,
    claimMalformed,
    claimMissing,
    claimMultiple,
    hardBindingsMissing,
    hardBindingsMultiple,
    claimRequiredMissing,
    claimCborInvalid,
    ingredientHashedUriMismatch,
    claimSignatureMissing,
    claimSignatureMismatch,
    manifestInaccessible,
    manifestMultipleParents,
    manifestUpdateInvalid,
    manifestUpdateWrongParents,
    signingCredentialUntrusted,
    signingCredentialInvalid,
    signingCredentialRevoked,
    signingCredentialExpired,
    assertionHashedUriMismatch,
    assertionMissing,
    assertionUndeclared,
    assertionInaccessible,
    assertionNotRedacted,
    assertionSelfRedacted,
    assertionRequiredMissing,
    assertionJsonInvalid,
    assertionCborInvalid,
    assertionActionIngredientMismatch,
    assertionActionRedacted,
    assertionDataHashMismatch,
    assertionBmffHashMismatch,
    assertionBoxesHashMismatch,
    assertionBoxesHashUnknownBox,
    assertionCloudDataHardBinding,
    assertionCloudDataActions,
    algorithmUnsupported,
    generalError,
    claimSignatureOutsideValidity,
    manifestTimestampInvalid,
    manifestTimestampWrongParents,
    manifestCompressedInvalid,
    signingCredentialOcspUnknown,
    assertionOutsideManifest,
    assertionActionMalformed,
    assertionActionRedactionMismatch,
    assertionDataHashMalformed,
    assertionDataHashRedacted,
    assertionBmffHashMalformed,
    assertionBoxesHashMalformed,
    assertionCloudDataMalformed,
    assertionCollectionHashMismatch,
    assertionCollectionHashIncorrectFileCount,
    assertionCollectionHashInvalidUri,
    assertionCollectionHashMalformed,
    assertionIngredientMalformed,
    assertionMetadataDisallowed,
    ingredientManifestMissing,
    ingredientManifestMismatch,
    ingredientClaimSignatureMissing,
    ingredientClaimSignatureMismatch,
    hashedUriMissing,
    hashedUriMismatch,
    assertionTimestampMalformed,
  ];

  static const List<ValidationCode> values = all;

  static final Map<String, ValidationCode> registry =
      Map<String, ValidationCode>.unmodifiable({
        for (final code in all) code.value: code,
      });

  @override
  bool operator ==(Object other) =>
      other is ValidationCode && value == other.value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}

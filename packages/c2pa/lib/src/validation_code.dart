/// How a C2PA validation status affects trust in a manifest.
enum ValidationSeverity {
  /// A status that confirms the checked condition passed.
  success,

  /// A status that reports a non-fatal condition or warning.
  informational,

  /// A status that reports a validation failure.
  failure,
}

/// The severity table used to interpret a validation status code.
enum ValidationClassification {
  /// The c2pa-rs runtime classification used for SDK behavior.
  runtime,

  /// The C2PA specification classification for conformance reporting.
  specification,
}

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

  /// The exact C2PA status string, such as `claimSignature.validated`.
  final String value;

  /// The SDK runtime severity used by default classification.
  final ValidationSeverity runtimeSeverity;

  /// The specification severity when it differs from runtime handling.
  final ValidationSeverity specificationSeverity;

  /// Selects this code's severity for a validation classification.
  ValidationSeverity severity({
    ValidationClassification classification = ValidationClassification.runtime,
  }) => switch (classification) {
    ValidationClassification.runtime => runtimeSeverity,
    ValidationClassification.specification => specificationSeverity,
  };

  /// Looks up the known status code for [value].
  ///
  /// Returns `null` for CAWG identity codes and unrecognized strings.
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

  /// Classifies [value] using known C2PA and CAWG status registries.
  ///
  /// Unknown values are treated as the failure severity.
  static ValidationSeverity classify(
    String value, {
    ValidationClassification classification = ValidationClassification.runtime,
  }) =>
      lookup(value)?.severity(classification: classification) ??
      cawgRegistry[value] ??
      ValidationSeverity.failure;

  /// A valid claim signature, reported as `claimSignature.validated`.
  static const claimSignatureValidated = ValidationCode._(
    'claimSignature.validated',
    ValidationSeverity.success,
  );

  /// A claim signature made within the signer's validity period.
  static const claimSignatureInsideValidity = ValidationCode._(
    'claimSignature.insideValidity',
    ValidationSeverity.success,
  );

  /// A signing credential chain trusted by the configured policy.
  static const signingCredentialTrusted = ValidationCode._(
    'signingCredential.trusted',
    ValidationSeverity.success,
  );

  /// A signing credential not revoked by OCSP.
  static const signingCredentialNotRevoked = ValidationCode._(
    'signingCredential.ocsp.notRevoked',
    ValidationSeverity.success,
  );

  /// A timestamp token that validates against the signed claim.
  static const timestampValidated = ValidationCode._(
    'timeStamp.validated',
    ValidationSeverity.success,
  );

  /// A timestamp token issued by a trusted time-stamp authority.
  static const timestampTrusted = ValidationCode._(
    'timeStamp.trusted',
    ValidationSeverity.success,
  );

  /// An assertion hash that matches its claim hashed URI.
  static const assertionHashedUriMatch = ValidationCode._(
    'assertion.hashedURI.match',
    ValidationSeverity.success,
  );

  /// A data-hash hard binding that matches the asset bytes.
  static const assertionDataHashMatch = ValidationCode._(
    'assertion.dataHash.match',
    ValidationSeverity.success,
  );

  /// A data-hash assertion with extra exclusions accepted by the spec.
  static const assertionDataHashAdditionalExclusions = ValidationCode._(
    'assertion.dataHash.additionalExclusionsPresent',
    ValidationSeverity.informational,
    ValidationSeverity.success,
  );

  /// A BMFF hash hard binding that matches the asset boxes.
  static const assertionBmffHashMatch = ValidationCode._(
    'assertion.bmffHash.match',
    ValidationSeverity.success,
  );

  /// A boxes-hash hard binding that matches the asset boxes.
  static const assertionBoxesHashMatch = ValidationCode._(
    'assertion.boxesHash.match',
    ValidationSeverity.success,
  );

  /// A collection-hash hard binding that matches all entries.
  static const assertionCollectionHashMatch = ValidationCode._(
    'assertion.collectionHash.match',
    ValidationSeverity.success,
  );

  /// An assertion referenced by the claim was found and readable.
  static const assertionAccessible = ValidationCode._(
    'assertion.accessible',
    ValidationSeverity.success,
  );

  /// An ingredient's referenced manifest validated successfully.
  static const ingredientManifestValidated = ValidationCode._(
    'ingredient.manifest.validated',
    ValidationSeverity.success,
  );

  /// An ingredient lacks known provenance but is allowed by policy.
  static const ingredientProvenanceUnknown = ValidationCode._(
    'ingredient.unknownProvenance',
    ValidationSeverity.informational,
    ValidationSeverity.success,
  );

  /// An ingredient claim signature validated successfully.
  static const ingredientClaimSignatureValidated = ValidationCode._(
    'ingredient.claimSignature.validated',
    ValidationSeverity.success,
  );

  /// OCSP revocation checking for the signing credential was skipped.
  static const signingCredentialOcspSkipped = ValidationCode._(
    'signingCredential.ocsp.skipped',
    ValidationSeverity.informational,
  );

  /// OCSP status for the signing credential could not be reached.
  static const signingCredentialOcspInaccessible = ValidationCode._(
    'signingCredential.ocsp.inaccessible',
    ValidationSeverity.informational,
  );

  /// A timestamp token does not match the expected signed data.
  static const timestampMismatch = ValidationCode._(
    'timeStamp.mismatch',
    ValidationSeverity.informational,
  );

  /// A timestamp token is present but cannot be parsed.
  static const timestampMalformed = ValidationCode._(
    'timeStamp.malformed',
    ValidationSeverity.informational,
  );

  /// A timestamp falls outside the signing credential validity period.
  static const timestampOutsideValidity = ValidationCode._(
    'timeStamp.outsideValidity',
    ValidationSeverity.informational,
  );

  /// A timestamp token chains to an untrusted authority.
  static const timestampUntrusted = ValidationCode._(
    'timeStamp.untrusted',
    ValidationSeverity.informational,
  );

  /// A manifest has provenance that cannot be linked to a trusted source.
  static const manifestUnknownProvenance = ValidationCode._(
    'manifest.unknownProvenance',
    ValidationSeverity.informational,
  );

  /// A manifest store contains a manifest not referenced by the active chain.
  static const manifestUnreferenced = ValidationCode._(
    'manifest.unreferenced',
    ValidationSeverity.failure,
    ValidationSeverity.informational,
  );

  /// A deprecated algorithm was used but remains processable.
  static const algorithmDeprecated = ValidationCode._(
    'algorithm.deprecated',
    ValidationSeverity.informational,
  );

  /// The signing time is inside the signing credential validity period.
  static const timeOfSigningInsideValidity = ValidationCode._(
    'timeOfSigning.insideValidity',
    ValidationSeverity.informational,
  );

  /// A claim box exists but its claim content is malformed.
  static const claimMalformed = ValidationCode._(
    'claim.malformed',
    ValidationSeverity.failure,
  );

  /// A manifest does not contain the required claim box.
  static const claimMissing = ValidationCode._(
    'claim.missing',
    ValidationSeverity.failure,
  );

  /// A manifest contains more than one claim box.
  static const claimMultiple = ValidationCode._(
    'claim.multiple',
    ValidationSeverity.failure,
  );

  /// A claim is missing a required hard-binding assertion.
  static const hardBindingsMissing = ValidationCode._(
    'claim.hardBindings.missing',
    ValidationSeverity.failure,
  );

  /// A claim contains multiple hard-binding assertions.
  static const hardBindingsMultiple = ValidationCode._(
    'assertion.multipleHardBindings',
    ValidationSeverity.failure,
  );

  /// A claim is missing a required field or assertion reference.
  static const claimRequiredMissing = ValidationCode._(
    'claim.required.missing',
    ValidationSeverity.failure,
  );

  /// A claim CBOR payload is invalid or non-decodable.
  static const claimCborInvalid = ValidationCode._(
    'claim.cbor.invalid',
    ValidationSeverity.failure,
  );

  /// An ingredient hashed URI does not match the referenced bytes.
  static const ingredientHashedUriMismatch = ValidationCode._(
    'ingredient.hashedURI.mismatch',
    ValidationSeverity.failure,
  );

  /// A manifest is missing the required claim signature box.
  static const claimSignatureMissing = ValidationCode._(
    'claimSignature.missing',
    ValidationSeverity.failure,
  );

  /// A claim signature does not verify over the claim bytes.
  static const claimSignatureMismatch = ValidationCode._(
    'claimSignature.mismatch',
    ValidationSeverity.failure,
  );

  /// A referenced manifest cannot be read from the manifest store.
  static const manifestInaccessible = ValidationCode._(
    'manifest.inaccessible',
    ValidationSeverity.failure,
  );

  /// A manifest declares more than one parent ingredient.
  static const manifestMultipleParents = ValidationCode._(
    'manifest.multipleParents',
    ValidationSeverity.failure,
  );

  /// An update manifest violates the C2PA update-manifest rules.
  static const manifestUpdateInvalid = ValidationCode._(
    'manifest.update.invalid',
    ValidationSeverity.failure,
  );

  /// An update manifest does not reference exactly one parent manifest.
  static const manifestUpdateWrongParents = ValidationCode._(
    'manifest.update.wrongParents',
    ValidationSeverity.failure,
  );

  /// A signing credential chain is not trusted by policy.
  static const signingCredentialUntrusted = ValidationCode._(
    'signingCredential.untrusted',
    ValidationSeverity.failure,
  );

  /// A signing credential chain or certificate is invalid.
  static const signingCredentialInvalid = ValidationCode._(
    'signingCredential.invalid',
    ValidationSeverity.failure,
  );

  /// OCSP reports that the signing credential was revoked.
  static const signingCredentialRevoked = ValidationCode._(
    'signingCredential.ocsp.revoked',
    ValidationSeverity.failure,
  );

  /// The signing credential expired before the signing time.
  static const signingCredentialExpired = ValidationCode._(
    'signingCredential.expired',
    ValidationSeverity.failure,
  );

  /// An assertion hash does not match its claim hashed URI.
  static const assertionHashedUriMismatch = ValidationCode._(
    'assertion.hashedURI.mismatch',
    ValidationSeverity.failure,
  );

  /// A claim references an assertion that is missing from the store.
  static const assertionMissing = ValidationCode._(
    'assertion.missing',
    ValidationSeverity.failure,
  );

  /// An assertion exists that is not declared by the claim.
  static const assertionUndeclared = ValidationCode._(
    'assertion.undeclared',
    ValidationSeverity.failure,
  );

  /// A referenced assertion cannot be read from its JUMBF box.
  static const assertionInaccessible = ValidationCode._(
    'assertion.inaccessible',
    ValidationSeverity.failure,
  );

  /// A redaction URI targets an assertion that was not redacted.
  static const assertionNotRedacted = ValidationCode._(
    'assertion.notRedacted',
    ValidationSeverity.failure,
  );

  /// A claim attempts to redact one of its own assertions.
  static const assertionSelfRedacted = ValidationCode._(
    'assertion.selfRedacted',
    ValidationSeverity.failure,
  );

  /// A required assertion is absent from the manifest.
  static const assertionRequiredMissing = ValidationCode._(
    'assertion.required.missing',
    ValidationSeverity.failure,
  );

  /// An assertion declared as JSON is invalid or non-decodable.
  static const assertionJsonInvalid = ValidationCode._(
    'assertion.json.invalid',
    ValidationSeverity.failure,
  );

  /// An assertion declared as CBOR is invalid or non-decodable.
  static const assertionCborInvalid = ValidationCode._(
    'assertion.cbor.invalid',
    ValidationSeverity.failure,
  );

  /// A c2pa.actions entry references the wrong ingredient.
  static const assertionActionIngredientMismatch = ValidationCode._(
    'assertion.action.ingredientMismatch',
    ValidationSeverity.failure,
  );

  /// A c2pa.actions assertion was improperly redacted.
  static const assertionActionRedacted = ValidationCode._(
    'assertion.action.redacted',
    ValidationSeverity.failure,
  );

  /// A data-hash hard binding does not match the asset bytes.
  static const assertionDataHashMismatch = ValidationCode._(
    'assertion.dataHash.mismatch',
    ValidationSeverity.failure,
  );

  /// A BMFF hash hard binding does not match the asset bytes.
  static const assertionBmffHashMismatch = ValidationCode._(
    'assertion.bmffHash.mismatch',
    ValidationSeverity.failure,
  );

  /// A boxes-hash hard binding does not match the asset boxes.
  static const assertionBoxesHashMismatch = ValidationCode._(
    'assertion.boxesHash.mismatch',
    ValidationSeverity.failure,
  );

  /// A boxes-hash assertion references an unknown asset box.
  static const assertionBoxesHashUnknownBox = ValidationCode._(
    'assertion.boxesHash.unknownBox',
    ValidationSeverity.failure,
  );

  /// A cloud-data assertion conflicts with hard-binding requirements.
  static const assertionCloudDataHardBinding = ValidationCode._(
    'assertion.cloud-data.hardBinding',
    ValidationSeverity.failure,
  );

  /// A cloud-data assertion conflicts with actions requirements.
  static const assertionCloudDataActions = ValidationCode._(
    'assertion.cloud-data.actions',
    ValidationSeverity.failure,
  );

  /// A manifest uses an algorithm this SDK cannot process.
  static const algorithmUnsupported = ValidationCode._(
    'algorithm.unsupported',
    ValidationSeverity.failure,
  );

  /// A validation failure without a more specific status code.
  static const generalError = ValidationCode._(
    'general.error',
    ValidationSeverity.failure,
  );

  /// A claim signature was made outside credential validity.
  static const claimSignatureOutsideValidity = ValidationCode._(
    'claimSignature.outsideValidity',
    ValidationSeverity.failure,
  );

  /// A timestamp manifest violates C2PA timestamp-manifest rules.
  static const manifestTimestampInvalid = ValidationCode._(
    'manifest.timestamp.invalid',
    ValidationSeverity.failure,
  );

  /// A timestamp manifest references the wrong parent manifests.
  static const manifestTimestampWrongParents = ValidationCode._(
    'manifest.timestamp.wrongParents',
    ValidationSeverity.failure,
  );

  /// A compressed manifest cannot be decoded or violates the spec.
  static const manifestCompressedInvalid = ValidationCode._(
    'manifest.compressed.invalid',
    ValidationSeverity.failure,
  );

  /// OCSP returned an unknown status for the signing credential.
  static const signingCredentialOcspUnknown = ValidationCode._(
    'signingCredential.ocsp.unknown',
    ValidationSeverity.failure,
  );

  /// An assertion is stored outside the manifest that declares it.
  static const assertionOutsideManifest = ValidationCode._(
    'assertion.outsideManifest',
    ValidationSeverity.failure,
  );

  /// A c2pa.actions assertion is malformed.
  static const assertionActionMalformed = ValidationCode._(
    'assertion.action.malformed',
    ValidationSeverity.failure,
  );

  /// Redaction entries and c2pa.redacted actions do not match.
  static const assertionActionRedactionMismatch = ValidationCode._(
    'assertion.action.redactionMismatch',
    ValidationSeverity.failure,
  );

  /// A data-hash assertion is malformed.
  static const assertionDataHashMalformed = ValidationCode._(
    'assertion.dataHash.malformed',
    ValidationSeverity.failure,
  );

  /// A hard-binding data-hash assertion was redacted.
  static const assertionDataHashRedacted = ValidationCode._(
    'assertion.dataHash.redacted',
    ValidationSeverity.failure,
  );

  /// A BMFF hash assertion is malformed.
  static const assertionBmffHashMalformed = ValidationCode._(
    'assertion.bmffHash.malformed',
    ValidationSeverity.failure,
  );

  /// A boxes-hash assertion is malformed.
  static const assertionBoxesHashMalformed = ValidationCode._(
    'assertion.boxesHash.malformed',
    ValidationSeverity.failure,
  );

  /// A cloud-data assertion is malformed.
  static const assertionCloudDataMalformed = ValidationCode._(
    'assertion.cloud-data.malformed',
    ValidationSeverity.failure,
  );

  /// A collection-hash assertion does not match collection entries.
  static const assertionCollectionHashMismatch = ValidationCode._(
    'assertion.collectionHash.mismatch',
    ValidationSeverity.failure,
  );

  /// A collection-hash assertion has the wrong number of files.
  static const assertionCollectionHashIncorrectFileCount = ValidationCode._(
    'assertion.collectionHash.incorrectFileCount',
    ValidationSeverity.failure,
  );

  /// A collection-hash assertion contains an invalid entry URI.
  static const assertionCollectionHashInvalidUri = ValidationCode._(
    'assertion.collectionHash.invalidURI',
    ValidationSeverity.failure,
  );

  /// A collection-hash assertion is malformed.
  static const assertionCollectionHashMalformed = ValidationCode._(
    'assertion.collectionHash.malformed',
    ValidationSeverity.failure,
  );

  /// An ingredient assertion is malformed.
  static const assertionIngredientMalformed = ValidationCode._(
    'assertion.ingredient.malformed',
    ValidationSeverity.failure,
  );

  /// An assertion metadata field is disallowed by the spec.
  static const assertionMetadataDisallowed = ValidationCode._(
    'assertion.metadata.disallowed',
    ValidationSeverity.failure,
  );

  /// An ingredient assertion has no referenced manifest.
  static const ingredientManifestMissing = ValidationCode._(
    'ingredient.manifest.missing',
    ValidationSeverity.success,
    ValidationSeverity.failure,
  );

  /// An ingredient manifest hash does not match the referenced manifest.
  static const ingredientManifestMismatch = ValidationCode._(
    'ingredient.manifest.mismatch',
    ValidationSeverity.failure,
  );

  /// An ingredient manifest is missing its claim signature reference.
  static const ingredientClaimSignatureMissing = ValidationCode._(
    'ingredient.claimSignature.missing',
    ValidationSeverity.failure,
  );

  /// An ingredient claim signature hash does not match.
  static const ingredientClaimSignatureMismatch = ValidationCode._(
    'ingredient.claimSignature.mismatch',
    ValidationSeverity.failure,
  );

  /// A required hashed URI field is missing.
  static const hashedUriMissing = ValidationCode._(
    'hashedURI.missing',
    ValidationSeverity.failure,
  );

  /// A hashed URI digest does not match the referenced bytes.
  static const hashedUriMismatch = ValidationCode._(
    'hashedURI.mismatch',
    ValidationSeverity.failure,
  );

  /// An assertion timestamp is malformed.
  static const assertionTimestampMalformed = ValidationCode._(
    'assertion.timestamp.malformed',
    ValidationSeverity.failure,
  );

  /// Legacy alias for [assertionActionIngredientMismatch].
  static const actionAssertionIngredientMismatch =
      assertionActionIngredientMismatch;

  /// Legacy alias for [assertionActionRedacted].
  static const actionAssertionRedacted = assertionActionRedacted;

  /// All core C2PA SDK status codes in registry order.
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

  /// Enum-style alias for [all].
  static const List<ValidationCode> values = all;

  /// Lookup table keyed by exact C2PA status string.
  ///
  /// Contains core SDK codes only, not CAWG identity statuses.
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

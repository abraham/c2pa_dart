import 'package:c2pa/c2pa.dart';
import 'package:test/test.dart';

void main() {
  group('ValidationCode registry', () {
    test('contains all 89 v0.90.22 SDK status strings exactly once', () {
      const expected = '''
claimSignature.validated
claimSignature.insideValidity
signingCredential.trusted
signingCredential.ocsp.notRevoked
timeStamp.validated
timeStamp.trusted
assertion.hashedURI.match
assertion.dataHash.match
assertion.dataHash.additionalExclusionsPresent
assertion.bmffHash.match
assertion.boxesHash.match
assertion.collectionHash.match
assertion.accessible
ingredient.manifest.validated
ingredient.unknownProvenance
ingredient.claimSignature.validated
signingCredential.ocsp.skipped
signingCredential.ocsp.inaccessible
timeStamp.mismatch
timeStamp.malformed
timeStamp.outsideValidity
timeStamp.untrusted
manifest.unknownProvenance
manifest.unreferenced
algorithm.deprecated
timeOfSigning.insideValidity
claim.malformed
claim.missing
claim.multiple
claim.hardBindings.missing
assertion.multipleHardBindings
claim.required.missing
claim.cbor.invalid
ingredient.hashedURI.mismatch
claimSignature.missing
claimSignature.mismatch
manifest.inaccessible
manifest.multipleParents
manifest.update.invalid
manifest.update.wrongParents
signingCredential.untrusted
signingCredential.invalid
signingCredential.ocsp.revoked
signingCredential.expired
assertion.hashedURI.mismatch
assertion.missing
assertion.undeclared
assertion.inaccessible
assertion.notRedacted
assertion.selfRedacted
assertion.required.missing
assertion.json.invalid
assertion.cbor.invalid
assertion.action.ingredientMismatch
assertion.action.redacted
assertion.dataHash.mismatch
assertion.bmffHash.mismatch
assertion.boxesHash.mismatch
assertion.boxesHash.unknownBox
assertion.cloud-data.hardBinding
assertion.cloud-data.actions
algorithm.unsupported
general.error
claimSignature.outsideValidity
manifest.timestamp.invalid
manifest.timestamp.wrongParents
manifest.compressed.invalid
signingCredential.ocsp.unknown
assertion.outsideManifest
assertion.action.malformed
assertion.action.redactionMismatch
assertion.dataHash.malformed
assertion.dataHash.redacted
assertion.bmffHash.malformed
assertion.boxesHash.malformed
assertion.cloud-data.malformed
assertion.collectionHash.mismatch
assertion.collectionHash.incorrectFileCount
assertion.collectionHash.invalidURI
assertion.collectionHash.malformed
assertion.ingredient.malformed
assertion.metadata.disallowed
ingredient.manifest.missing
ingredient.manifest.mismatch
ingredient.claimSignature.missing
ingredient.claimSignature.mismatch
hashedURI.missing
hashedURI.mismatch
assertion.timestamp.malformed''';
      final expectedValues = expected.split('\n').toSet();

      expect(ValidationCode.all, hasLength(89));
      expect(ValidationCode.registry, hasLength(89));
      expect(ValidationCode.registry.keys.toSet(), expectedValues);
      expect(
        () => ValidationCode.registry['new'] = ValidationCode.generalError,
        throwsUnsupportedError,
      );
    });

    test('matches runtime log_kind categories exhaustively', () {
      const successful = {
        'claimSignature.validated',
        'claimSignature.insideValidity',
        'signingCredential.trusted',
        'signingCredential.ocsp.notRevoked',
        'timeStamp.trusted',
        'timeStamp.validated',
        'assertion.hashedURI.match',
        'assertion.dataHash.match',
        'assertion.bmffHash.match',
        'assertion.accessible',
        'assertion.boxesHash.match',
        'assertion.collectionHash.match',
        'ingredient.manifest.validated',
        'ingredient.manifest.missing',
        'ingredient.claimSignature.validated',
      };
      const informational = {
        'signingCredential.ocsp.skipped',
        'signingCredential.ocsp.inaccessible',
        'timeStamp.untrusted',
        'timeStamp.outsideValidity',
        'timeStamp.mismatch',
        'timeStamp.malformed',
        'manifest.unknownProvenance',
        'algorithm.deprecated',
        'timeOfSigning.insideValidity',
        'ingredient.unknownProvenance',
        'assertion.dataHash.additionalExclusionsPresent',
      };

      for (final code in ValidationCode.all) {
        final expected = successful.contains(code.value)
            ? ValidationSeverity.success
            : informational.contains(code.value)
            ? ValidationSeverity.informational
            : ValidationSeverity.failure;
        expect(code.runtimeSeverity, expected, reason: code.value);
        expect(ValidationCode.classify(code.value), expected);
      }
      expect(
        ValidationCode.classify('vendor.future.status'),
        ValidationSeverity.failure,
      );
    });

    test('preserves spec-oriented overrides separately', () {
      expect(
        ValidationCode.ingredientManifestMissing.runtimeSeverity,
        ValidationSeverity.success,
      );
      expect(
        ValidationCode.ingredientManifestMissing.specificationSeverity,
        ValidationSeverity.failure,
      );
      expect(
        ValidationCode.manifestUnreferenced.specificationSeverity,
        ValidationSeverity.informational,
      );
      expect(
        ValidationCode.ingredientProvenanceUnknown.specificationSeverity,
        ValidationSeverity.success,
      );
      expect(
        ValidationCode
            .assertionDataHashAdditionalExclusions
            .specificationSeverity,
        ValidationSeverity.success,
      );
    });

    test('keeps ingredient.manifest.missing runtime anomaly', () {
      final statuses = StatusCodes(
        statuses: [
          ValidationIssue.known(code: ValidationCode.ingredientManifestMissing),
        ],
      );

      expect(statuses.success.single.code, 'ingredient.manifest.missing');
      expect(statuses.failure, isEmpty);
      expect(
        ValidationCode.classify(
          'ingredient.manifest.missing',
          classification: ValidationClassification.specification,
        ),
        ValidationSeverity.failure,
      );
    });
  });

  group('ValidationIssue', () {
    test('derives runtime severity and retains unknown codes', () {
      final success = ValidationIssue.known(
        code: ValidationCode.claimSignatureValidated,
      );
      final unknown = ValidationIssue(code: 'vendor.future.status');

      expect(success.severity, ValidationSeverity.success);
      expect(success.passed, isTrue);
      expect(unknown.code, 'vendor.future.status');
      expect(unknown.severity, ValidationSeverity.failure);
      expect(unknown.passed, isFalse);
    });

    test('omits classification and ingredient routing from JSON', () {
      final issue = ValidationIssue(
        code: 'vendor.failure',
        url: 'self#jumbf=/claim',
        explanation: 'Failed.',
        ingredientUri: 'self#jumbf=/ingredient',
      );

      expect(issue.toJson(), {
        'code': 'vendor.failure',
        'url': 'self#jumbf=/claim',
        'explanation': 'Failed.',
      });
      expect(issue.toJson(), isNot(contains('severity')));
      expect(issue.toJson(), isNot(contains('ingredientUri')));
    });
  });

  group('ValidationResults state', () {
    test('missing active results is invalid', () {
      expect(ValidationResults().state, ValidationState.invalid);
      expect(
        ValidationResults.fromIssues([
          _known(
            ValidationCode.claimSignatureValidated,
            ingredientUri: 'ingredient',
          ),
        ]).state,
        ValidationState.invalid,
      );
    });

    test('requires both signature success codes', () {
      expect(
        ValidationResults.fromIssues([
          _known(ValidationCode.claimSignatureValidated),
        ]).state,
        ValidationState.invalid,
      );
      expect(
        ValidationResults.fromIssues([
          _known(ValidationCode.claimSignatureInsideValidity),
        ]).state,
        ValidationState.invalid,
      );
      expect(
        ValidationResults.fromIssues(_validStatuses()).state,
        ValidationState.valid,
      );
    });

    test('tolerates only untrusted failures across all groups', () {
      expect(
        ValidationResults.fromIssues([
          ..._validStatuses(),
          _known(ValidationCode.signingCredentialUntrusted),
          _known(
            ValidationCode.signingCredentialUntrusted,
            ingredientUri: 'ingredient-1',
          ),
        ]).state,
        ValidationState.valid,
      );
      expect(
        ValidationResults.fromIssues([
          ..._validStatuses(),
          _known(
            ValidationCode.assertionDataHashMismatch,
            ingredientUri: 'ingredient-1',
          ),
        ]).state,
        ValidationState.invalid,
      );
    });

    test('trusted requires trusted success and zero failures', () {
      expect(
        ValidationResults.fromIssues([
          ..._validStatuses(),
          _known(ValidationCode.signingCredentialTrusted),
        ]).state,
        ValidationState.trusted,
      );
      expect(
        ValidationResults.fromIssues([
          ..._validStatuses(),
          _known(ValidationCode.signingCredentialTrusted),
          _known(ValidationCode.signingCredentialUntrusted),
        ]).state,
        ValidationState.valid,
      );
    });
  });

  group('ValidationResults serialization', () {
    test('groups active and ingredient statuses using upstream shape', () {
      final results = ValidationResults.fromIssues([
        ..._validStatuses(),
        ValidationIssue.known(
          code: ValidationCode.timestampMalformed,
          explanation: 'Malformed timestamp.',
        ),
        _known(
          ValidationCode.signingCredentialUntrusted,
          ingredientUri: 'self#jumbf=/ingredient/1',
        ),
      ], validationTime: DateTime.utc(2026));

      final json = results.toJson();

      expect(json.keys, {'activeManifest', 'ingredientDeltas'});
      expect(json, isNot(contains('validationTime')));
      expect(
        (json['activeManifest']! as Map<String, Object?>)['success'],
        hasLength(2),
      );
      final deltas = json['ingredientDeltas']! as List<Object?>;
      expect(deltas, hasLength(1));
      final delta = deltas.single as Map<String, Object?>;
      expect(delta, isNot(contains('ingredientUri')));
      final deltaStatuses = delta['validationDeltas']! as Map<String, Object?>;
      final failure = deltaStatuses['failure']! as List<Object?>;
      expect(failure.single, isNot(contains('severity')));
      expect(failure.single, isNot(contains('ingredientUri')));
      expect(ValidationResults.fromJson(json).state, ValidationState.valid);
    });

    test('round-trips grouped results with immutable collections', () {
      final source = ValidationResults.fromIssues([
        ..._validStatuses(),
        _known(
          ValidationCode.assertionDataHashMismatch,
          ingredientUri: 'ingredient',
        ),
      ]);
      final decoded = ValidationResults.fromJson(source.toJson());

      expect(decoded, source);
      expect(() => decoded.issues.clear(), throwsUnsupportedError);
      expect(
        () => decoded.activeManifest!.success.clear(),
        throwsUnsupportedError,
      );
      expect(() => decoded.ingredientDeltas!.clear(), throwsUnsupportedError);
    });
  });
}

ValidationIssue _known(ValidationCode code, {String? ingredientUri}) =>
    ValidationIssue.known(code: code, ingredientUri: ingredientUri);

List<ValidationIssue> _validStatuses() => [
  _known(ValidationCode.claimSignatureValidated),
  _known(ValidationCode.claimSignatureInsideValidity),
];

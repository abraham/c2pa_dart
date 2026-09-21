part of '../cawg_identity.dart';

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

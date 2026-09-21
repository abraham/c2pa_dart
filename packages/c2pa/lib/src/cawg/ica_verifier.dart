part of '../cawg_identity.dart';

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

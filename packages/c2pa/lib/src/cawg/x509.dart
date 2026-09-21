part of '../cawg_identity.dart';

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

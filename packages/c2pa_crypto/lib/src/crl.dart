import 'dart:typed_data';

import 'byte_compare.dart';
import 'der_reader.dart';
import 'ocsp.dart';
import 'path_validation.dart';
import 'x509_certificate.dart';

/// Revocation reason codes from RFC 5280 section 5.3.1.
enum CrlRevocationReason {
  /// No specific revocation reason was supplied.
  unspecified(0),

  /// The subject certificate private key was compromised.
  keyCompromise(1),

  /// The issuing CA private key was compromised.
  caCompromise(2),

  /// The subject's affiliation changed.
  affiliationChanged(3),

  /// The certificate was superseded.
  superseded(4),

  /// The subject ceased operation.
  cessationOfOperation(5),

  /// The certificate is temporarily on hold.
  certificateHold(6),

  /// The certificate was removed from a CRL.
  removeFromCrl(8),

  /// The subject's privilege was withdrawn.
  privilegeWithdrawn(9),

  /// The attribute authority was compromised.
  aaCompromise(10);

  /// Creates a CRL reason carrying its RFC 5280 integer [value].
  const CrlRevocationReason(this.value);

  /// The integer value encoded in the CRLReason ENUMERATED.
  final int value;

  /// Parses an RFC 5280 CRLReason integer.
  ///
  /// Throws a [FormatException] if [value] is not supported.
  static CrlRevocationReason fromValue(int value) {
    for (final reason in values) {
      if (reason.value == value) {
        return reason;
      }
    }
    throw FormatException('Unsupported CRL reason code: $value');
  }
}

/// Scope declared by the IssuingDistributionPoint extension.
final class CrlIssuingDistributionPoint {
  /// Creates a parsed RFC 5280 IssuingDistributionPoint extension value.
  CrlIssuingDistributionPoint({
    required this.onlyContainsUserCertificates,
    required this.onlyContainsCaCertificates,
    required this.indirectCrl,
    required this.onlyContainsAttributeCertificates,
    required Set<CrlRevocationReason>? onlySomeReasons,
    List<int>? distributionPointDer,
  }) : onlySomeReasons = onlySomeReasons == null
           ? null
           : Set.unmodifiable(onlySomeReasons),
       _distributionPointDer = distributionPointDer == null
           ? null
           : Uint8List.fromList(distributionPointDer);

  /// Whether this CRL scope is limited to end-entity certificates.
  final bool onlyContainsUserCertificates;

  /// Whether this CRL scope is limited to CA certificates.
  final bool onlyContainsCaCertificates;

  /// Whether revoked entries may name certificate issuers other than the CRL issuer.
  final bool indirectCrl;

  /// Whether this CRL scope is limited to attribute certificates.
  final bool onlyContainsAttributeCertificates;

  /// The covered reason subset, or `null` when all reasons are covered.
  final Set<CrlRevocationReason>? onlySomeReasons;

  final Uint8List? _distributionPointDer;

  /// The encoded DistributionPointName, or `null` when not constrained.
  Uint8List? get distributionPointDer => _distributionPointDer == null
      ? null
      : Uint8List.fromList(_distributionPointDer);
}

/// One revoked-certificate entry with its effective certificate issuer.
final class CrlRevokedCertificate {
  CrlRevokedCertificate._({
    required this.serialNumber,
    required this.revocationTime,
    required this.reason,
    required this.invalidityDate,
    required this.effectiveIssuer,
  });

  /// The positive certificate serial number listed by the CRL entry.
  final BigInt serialNumber;

  /// The UTC revocationDate from RFC 5280 section 5.1.
  final DateTime revocationTime;

  /// The CRL reason extension value, or `null` when absent.
  final CrlRevocationReason? reason;

  /// The invalidityDate extension value, or `null` when absent.
  final DateTime? invalidityDate;

  /// The issuer in force for this entry, including indirect CRL entries.
  final X509DistinguishedName effectiveIssuer;
}

/// Strictly parsed DER X.509 CertificateList.
final class X509Crl {
  X509Crl._({
    required List<int> der,
    required List<int> tbsCertListDer,
    required this.version,
    required this.issuer,
    required this.thisUpdate,
    required this.nextUpdate,
    required List<int>? authorityKeyIdentifier,
    required this.crlNumber,
    required this.deltaCrlIndicator,
    required this.issuingDistributionPoint,
    required List<CrlRevokedCertificate> revokedCertificates,
    required this.signatureAlgorithm,
    required List<int> signature,
  }) : _der = Uint8List.fromList(der),
       _tbsCertListDer = Uint8List.fromList(tbsCertListDer),
       _authorityKeyIdentifier = authorityKeyIdentifier == null
           ? null
           : Uint8List.fromList(authorityKeyIdentifier),
       revokedCertificates = List.unmodifiable(revokedCertificates),
       _signature = Uint8List.fromList(signature);

  final Uint8List _der;
  final Uint8List _tbsCertListDer;

  /// The parsed CRL version, either 1 or 2.
  final int version;

  /// The CRL issuer Name from the TBSCertList.
  final X509DistinguishedName issuer;

  /// The UTC thisUpdate time from the TBSCertList.
  final DateTime thisUpdate;

  /// The UTC nextUpdate time, or `null` when the CRL omits it.
  final DateTime? nextUpdate;

  final Uint8List? _authorityKeyIdentifier;

  /// The CRLNumber extension value, or `null` when absent.
  final BigInt? crlNumber;

  /// The DeltaCRLIndicator base number, or `null` for a complete CRL.
  final BigInt? deltaCrlIndicator;

  /// The IssuingDistributionPoint extension value, or `null` when absent.
  final CrlIssuingDistributionPoint? issuingDistributionPoint;

  /// Immutable revoked-certificate entries parsed from the CRL.
  final List<CrlRevokedCertificate> revokedCertificates;

  /// The outer CertificateList signature AlgorithmIdentifier.
  final X509AlgorithmIdentifier signatureAlgorithm;

  final Uint8List _signature;

  /// A defensive copy of the complete DER CertificateList.
  Uint8List get der => Uint8List.fromList(_der);

  /// A defensive copy of the signed TBSCertList DER.
  Uint8List get tbsCertListDer => Uint8List.fromList(_tbsCertListDer);

  /// The authority key identifier bytes, or `null` when absent.
  Uint8List? get authorityKeyIdentifier => _authorityKeyIdentifier == null
      ? null
      : Uint8List.fromList(_authorityKeyIdentifier);

  /// A defensive copy of the byte-aligned CertificateList signature.
  Uint8List get signature => Uint8List.fromList(_signature);

  /// Parses one DER-encoded RFC 5280 CertificateList without network I/O.
  ///
  /// Throws a [FormatException] for malformed DER, invalid RFC 5280 structure,
  /// stale-field ordering, or unsupported critical extension semantics. Throws
  /// an [UnsupportedError] for unknown critical CRL extensions.
  factory X509Crl.parse(List<int> input) {
    _validateBytes(input);
    final der = Uint8List.fromList(input);
    final root = DerReader(der);
    final certificateList = root.read(0x30);
    root.requireEnd();
    final reader = certificateList.reader();
    final tbs = reader.read(0x30);
    final outerAlgorithm = _parseAlgorithmIdentifier(reader.read(0x30));
    final signature = _parseBitString(reader.read(0x03));
    reader.requireEnd();

    final parsed = _parseTbsCertList(tbs);
    if (!_sameAlgorithm(parsed.signatureAlgorithm, outerAlgorithm)) {
      throw const FormatException(
        'TBSCertList and outer signature algorithms differ',
      );
    }
    return X509Crl._(
      der: der,
      tbsCertListDer: tbs.encoded,
      version: parsed.version,
      issuer: parsed.issuer,
      thisUpdate: parsed.thisUpdate,
      nextUpdate: parsed.nextUpdate,
      authorityKeyIdentifier: parsed.authorityKeyIdentifier,
      crlNumber: parsed.crlNumber,
      deltaCrlIndicator: parsed.deltaCrlIndicator,
      issuingDistributionPoint: parsed.issuingDistributionPoint,
      revokedCertificates: parsed.revokedCertificates,
      signatureAlgorithm: outerAlgorithm,
      signature: signature,
    );
  }

  /// Finds the unique entry matching [issuer] and [serialNumber].
  CrlRevokedCertificate? findRevokedCertificate({
    required X509DistinguishedName issuer,
    required BigInt serialNumber,
  }) {
    final matches = revokedCertificates
        .where(
          (entry) =>
              entry.serialNumber == serialNumber &&
              constantTimeBytesEqual(entry.effectiveIssuer.der, issuer.der),
        )
        .toList();
    if (matches.length > 1) {
      throw const FormatException('CRL contains duplicate revoked entries');
    }
    return matches.firstOrNull;
  }
}

/// High-level CRL verification status produced by this package.
enum CrlStatus {
  /// Fresh, trusted CRL evidence says the certificate is not revoked.
  good,

  /// Fresh, trusted CRL evidence lists the certificate as revoked.
  revoked,

  /// The CRL was valid but not authoritative for the certificate.
  unknown,

  /// The CRL validity window does not cover the evaluation time.
  stale,

  /// The CRL or its signature failed structural validation.
  malformed,

  /// The CRL signer did not validate to the trust policy.
  untrusted,
}

/// Machine-readable CRL verification issue codes.
enum CrlIssueCode {
  /// The DER CertificateList could not be parsed as supported RFC 5280 CRL.
  malformedCrl,

  /// The target certificate, CRL issuer, or signer did not match.
  wrongIssuer,

  /// The CRL AKI did not match the signer subject key identifier.
  authorityKeyIdentifierMismatch,

  /// The CRL is older than its nextUpdate or configured maximum age.
  staleCrl,

  /// The CRL thisUpdate is after the evaluation time.
  futureCrl,

  /// The CertificateList signature was malformed or invalid.
  invalidSignature,

  /// The signer is not a CA permitted to sign CRLs.
  unauthorizedSigner,

  /// The signer certificate chain did not validate to the trust policy.
  untrustedSigner,

  /// The IssuingDistributionPoint excludes the target certificate.
  targetOutOfScope,

  /// The CRL covers only some reasons and cannot prove all reasons.
  partialReasonCoverage,

  /// A delta CRL was supplied without a verified base CRL.
  deltaBaseCrlRequired,

  /// The CRL contains an unsupported critical extension.
  unsupportedCriticalExtension,

  /// A required CRL signature algorithm is unsupported.
  unsupportedSignatureAlgorithm,
}

/// One CRL verification issue with a stable code and message.
final class CrlIssue {
  /// Creates a CRL issue with [code] and human-readable [message].
  const CrlIssue(this.code, this.message);

  /// The machine-readable category of the verification issue.
  final CrlIssueCode code;

  /// A human-readable description of the verification issue.
  final String message;
}

/// Structured CRL verification outcome.
final class CrlVerificationResult {
  /// Creates a CRL verification result with immutable [issues].
  CrlVerificationResult({
    required this.status,
    required List<CrlIssue> issues,
    this.crl,
    this.entry,
    this.signerCertificate,
    this.pathResult,
  }) : issues = List.unmodifiable(issues);

  /// The high-level status computed from parsed CRL and trust checks.
  final CrlStatus status;

  /// Immutable issues collected while verifying the CRL.
  final List<CrlIssue> issues;

  /// The parsed CRL, or `null` when parsing failed.
  final X509Crl? crl;

  /// The matching revoked entry, or `null` when the certificate is not listed.
  final CrlRevokedCertificate? entry;

  /// The certificate used to verify the CRL signature.
  final X509Certificate? signerCertificate;

  /// The signer path validation result, or `null` before path checks run.
  final CertificatePathValidationResult? pathResult;
}

/// Verifies one stapled CRL without performing network access.
///
/// Parses RFC 5280 section 5 DER, checks issuer and AKI linkage, thisUpdate
/// and nextUpdate freshness, signer authorization, signature, path trust, and
/// IssuingDistributionPoint scope. Malformed or stale CRLs return structured
/// statuses rather than being fetched or retried.
Future<CrlVerificationResult> verifyCrl(
  List<int> crlDer, {
  required X509Certificate certificate,
  required X509Certificate issuer,
  required TrustPolicy trustPolicy,
  X509Certificate? crlSigner,
  DateTime? evaluationTime,
  Duration maxAgeWithoutNextUpdate = const Duration(days: 7),
}) async {
  late X509Crl crl;
  try {
    crl = X509Crl.parse(crlDer);
  } on UnsupportedError catch (error) {
    return CrlVerificationResult(
      status: CrlStatus.malformed,
      issues: [
        CrlIssue(
          CrlIssueCode.unsupportedCriticalExtension,
          error.message ?? error.toString(),
        ),
      ],
    );
  } on FormatException catch (error) {
    return CrlVerificationResult(
      status: CrlStatus.malformed,
      issues: [CrlIssue(CrlIssueCode.malformedCrl, error.message)],
    );
  }
  final signer = crlSigner ?? issuer;
  final issues = <CrlIssue>[];
  final time = (evaluationTime ?? trustPolicy.evaluationTime).toUtc();

  try {
    final issuedByTargetIssuer =
        constantTimeBytesEqual(certificate.issuer.der, issuer.subject.der) &&
        await verifySignatureWithCertificatePublicKey(
          certificate: issuer,
          signatureAlgorithm: certificate.signatureAlgorithm,
          data: certificate.tbsCertificateDer,
          signature: certificate.signature,
        );
    if (!issuedByTargetIssuer) {
      issues.add(
        const CrlIssue(
          CrlIssueCode.wrongIssuer,
          'Target certificate was not issued by the supplied issuer',
        ),
      );
    }
  } on UnsupportedError catch (error) {
    issues.add(
      CrlIssue(
        CrlIssueCode.unsupportedSignatureAlgorithm,
        error.message ?? error.toString(),
      ),
    );
  } on FormatException {
    issues.add(
      const CrlIssue(
        CrlIssueCode.wrongIssuer,
        'Target certificate signature is malformed',
      ),
    );
  }

  if (!constantTimeBytesEqual(crl.issuer.der, signer.subject.der)) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.wrongIssuer,
        'CRL issuer does not match the signer certificate subject',
      ),
    );
  }
  final aki = crl.authorityKeyIdentifier;
  final ski = signer.subjectKeyIdentifier;
  if (aki != null && (ski == null || !constantTimeBytesEqual(aki, ski))) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.authorityKeyIdentifierMismatch,
        'CRL authority key identifier does not match its signer',
      ),
    );
  }
  if (time.isBefore(crl.thisUpdate)) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.futureCrl,
        'CRL thisUpdate is after the evaluation time',
      ),
    );
  } else if (crl.nextUpdate != null
      ? time.isAfter(crl.nextUpdate!)
      : time.difference(crl.thisUpdate) > maxAgeWithoutNextUpdate) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.staleCrl,
        'CRL is stale at the evaluation time',
      ),
    );
  }

  if (signer.basicConstraints?.isCa != true ||
      signer.keyUsage?.contains(X509KeyUsage.crlSign) != true) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.unauthorizedSigner,
        'CRL signer must be a CA whose KeyUsage permits cRLSign',
      ),
    );
  }
  try {
    if (!await verifySignatureWithCertificatePublicKey(
      certificate: signer,
      signatureAlgorithm: crl.signatureAlgorithm,
      data: crl.tbsCertListDer,
      signature: crl.signature,
    )) {
      issues.add(
        const CrlIssue(
          CrlIssueCode.invalidSignature,
          'CertificateList signature verification failed',
        ),
      );
    }
  } on UnsupportedError catch (error) {
    issues.add(
      CrlIssue(
        CrlIssueCode.unsupportedSignatureAlgorithm,
        error.message ?? error.toString(),
      ),
    );
  } on FormatException {
    issues.add(
      const CrlIssue(
        CrlIssueCode.invalidSignature,
        'CertificateList signature encoding is malformed',
      ),
    );
  }

  final policyAtTime = TrustPolicy(
    trustAnchors: trustPolicy.trustAnchors,
    intermediates: [...trustPolicy.intermediates, issuer.der],
    evaluationTime: time,
    maxDepth: trustPolicy.maxDepth,
  );
  final pathResult = await validateCertificateAuthorityPath(
    signer.der,
    policy: policyAtTime,
  );
  if (!pathResult.isTrusted) {
    issues.add(
      CrlIssue(
        CrlIssueCode.untrustedSigner,
        'CRL signer path validation failed: '
        '${pathResult.issues.map((issue) => issue.message).join('; ')}',
      ),
    );
  }

  final scope = crl.issuingDistributionPoint;
  if (scope?.onlyContainsAttributeCertificates == true ||
      (scope?.onlyContainsUserCertificates == true &&
          certificate.basicConstraints?.isCa == true) ||
      (scope?.onlyContainsCaCertificates == true &&
          certificate.basicConstraints?.isCa != true)) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.targetOutOfScope,
        'Target certificate is outside the issuing distribution point scope',
      ),
    );
  }
  if (scope?.distributionPointDer != null) {
    try {
      final targetPoints = _certificateDistributionPoints(certificate);
      if (!targetPoints.any(
        (point) => constantTimeBytesEqual(point, scope!.distributionPointDer!),
      )) {
        issues.add(
          const CrlIssue(
            CrlIssueCode.targetOutOfScope,
            'Target certificate does not name the CRL distribution point',
          ),
        );
      }
    } on FormatException catch (error) {
      issues.add(CrlIssue(CrlIssueCode.malformedCrl, error.message));
    }
  }

  CrlRevokedCertificate? entry;
  try {
    entry = crl.findRevokedCertificate(
      issuer: issuer.subject,
      serialNumber: certificate.serialNumber,
    );
  } on FormatException catch (error) {
    issues.add(CrlIssue(CrlIssueCode.malformedCrl, error.message));
  }
  if (scope?.onlySomeReasons != null) {
    if (entry == null ||
        entry.reason == null ||
        !scope!.onlySomeReasons!.contains(entry.reason)) {
      issues.add(
        const CrlIssue(
          CrlIssueCode.partialReasonCoverage,
          'CRL does not cover all revocation reasons for this certificate',
        ),
      );
    }
  }
  if (crl.deltaCrlIndicator != null) {
    issues.add(
      const CrlIssue(
        CrlIssueCode.deltaBaseCrlRequired,
        'A delta CRL requires a matching verified base CRL',
      ),
    );
  }

  final malformed = issues.any(
    (issue) =>
        issue.code == CrlIssueCode.malformedCrl ||
        issue.code == CrlIssueCode.invalidSignature ||
        issue.code == CrlIssueCode.wrongIssuer ||
        issue.code == CrlIssueCode.authorityKeyIdentifierMismatch ||
        issue.code == CrlIssueCode.unauthorizedSigner ||
        issue.code == CrlIssueCode.unsupportedCriticalExtension ||
        issue.code == CrlIssueCode.unsupportedSignatureAlgorithm,
  );
  final stale = issues.any(
    (issue) =>
        issue.code == CrlIssueCode.staleCrl ||
        issue.code == CrlIssueCode.futureCrl,
  );
  final unknown = issues.any(
    (issue) =>
        issue.code == CrlIssueCode.targetOutOfScope ||
        issue.code == CrlIssueCode.partialReasonCoverage ||
        issue.code == CrlIssueCode.deltaBaseCrlRequired,
  );
  final status = malformed
      ? CrlStatus.malformed
      : !pathResult.isTrusted
      ? CrlStatus.untrusted
      : stale
      ? CrlStatus.stale
      : unknown
      ? CrlStatus.unknown
      : entry != null &&
            entry.reason != CrlRevocationReason.removeFromCrl &&
            !entry.revocationTime.isAfter(time)
      ? CrlStatus.revoked
      : CrlStatus.good;
  return CrlVerificationResult(
    status: status,
    issues: issues,
    crl: crl,
    entry: entry,
    signerCertificate: signer,
    pathResult: pathResult,
  );
}

/// Combined status for already-verified OCSP and CRL evidence.
enum RevocationEvidenceStatus {
  /// Authoritative evidence says the certificate is not revoked.
  good,

  /// Authoritative evidence says the certificate is revoked.
  revoked,

  /// No authoritative evidence is available.
  unknown,

  /// Evidence exists but is outside its accepted freshness window.
  stale,

  /// OCSP and CRL evidence disagree on good versus revoked.
  conflict,

  /// OCSP evidence could not be fetched or delivered.
  inaccessible,

  /// Available evidence includes malformed proof.
  malformed,
}

/// Deterministic result from combining stapled OCSP and CRL evidence.
final class RevocationEvidenceResult {
  /// Creates a combined revocation evidence result.
  const RevocationEvidenceResult({required this.status, required this.reason});

  /// The combined status chosen from already-verified evidence.
  final RevocationEvidenceStatus status;

  /// A human-readable explanation for [status].
  final String reason;
}

/// Combines already-verified stapled evidence without fetching.
///
/// Conflicting authoritative good/revoked evidence is reported explicitly.
/// Otherwise authoritative evidence wins over unavailable or stale evidence.
RevocationEvidenceResult evaluateRevocationEvidence({
  OcspVerificationResult? ocsp,
  CrlVerificationResult? crl,
}) {
  final ocspStatus = ocsp?.status;
  final crlStatus = crl?.status;
  final ocspAuthoritative = ocspStatus == OcspResultStatus.good
      ? RevocationEvidenceStatus.good
      : ocspStatus == OcspResultStatus.revoked
      ? RevocationEvidenceStatus.revoked
      : null;
  final crlAuthoritative = crlStatus == CrlStatus.good
      ? RevocationEvidenceStatus.good
      : crlStatus == CrlStatus.revoked
      ? RevocationEvidenceStatus.revoked
      : null;
  if (ocspAuthoritative != null &&
      crlAuthoritative != null &&
      ocspAuthoritative != crlAuthoritative) {
    return const RevocationEvidenceResult(
      status: RevocationEvidenceStatus.conflict,
      reason: 'OCSP and CRL evidence conflict',
    );
  }
  final authoritative = ocspAuthoritative ?? crlAuthoritative;
  if (authoritative != null) {
    return RevocationEvidenceResult(
      status: authoritative,
      reason: 'Authoritative stapled revocation evidence is available',
    );
  }
  if (ocspStatus == OcspResultStatus.malformed ||
      crlStatus == CrlStatus.malformed) {
    return const RevocationEvidenceResult(
      status: RevocationEvidenceStatus.malformed,
      reason: 'All available evidence includes malformed proof',
    );
  }
  final ocspIsStale =
      ocsp?.issues.any((issue) => issue.code == OcspIssueCode.staleResponse) ==
      true;
  if (crlStatus == CrlStatus.stale || ocspIsStale) {
    return const RevocationEvidenceResult(
      status: RevocationEvidenceStatus.stale,
      reason: 'Revocation evidence is stale',
    );
  }
  if (ocspStatus == OcspResultStatus.inaccessible) {
    return const RevocationEvidenceResult(
      status: RevocationEvidenceStatus.inaccessible,
      reason: 'OCSP evidence was inaccessible',
    );
  }
  return const RevocationEvidenceResult(
    status: RevocationEvidenceStatus.unknown,
    reason: 'No authoritative revocation evidence is available',
  );
}

_ParsedTbsCrl _parseTbsCertList(DerValue tbs) {
  final reader = tbs.reader();
  var version = 1;
  if (!reader.isAtEnd && reader.peekTag() == 0x02) {
    if (_parseSmallInteger(reader.read(0x02)) != 1) {
      throw const FormatException('Only X.509 CRL version 2 is supported');
    }
    version = 2;
  }
  final signatureAlgorithm = _parseAlgorithmIdentifier(reader.read(0x30));
  final issuer = X509DistinguishedName.parse(reader.read(0x30).encoded);
  final thisUpdate = _parseTime(reader.read());
  DateTime? nextUpdate;
  if (!reader.isAtEnd &&
      (reader.peekTag() == 0x17 || reader.peekTag() == 0x18)) {
    nextUpdate = _parseTime(reader.read());
    if (nextUpdate.isBefore(thisUpdate)) {
      throw const FormatException('CRL nextUpdate precedes thisUpdate');
    }
  }

  final entries = <CrlRevokedCertificate>[];
  var effectiveIssuer = issuer;
  var sawEntryExtensions = false;
  if (!reader.isAtEnd && reader.peekTag() == 0x30) {
    final revoked = reader.read(0x30).reader();
    while (!revoked.isAtEnd) {
      final parsed = _parseRevokedEntry(revoked.read(0x30), effectiveIssuer);
      effectiveIssuer = parsed.effectiveIssuer;
      sawEntryExtensions |= parsed.hadExtensions;
      entries.add(parsed.entry);
    }
  }

  Uint8List? authorityKeyIdentifier;
  BigInt? crlNumber;
  BigInt? deltaCrlIndicator;
  CrlIssuingDistributionPoint? issuingDistributionPoint;
  var hasCrlExtensions = false;
  if (!reader.isAtEnd) {
    final explicit = reader.read(0xa0).reader();
    final extensions = _parseExtensions(explicit.read(0x30));
    explicit.requireEnd();
    hasCrlExtensions = true;
    for (final extension in extensions) {
      switch (extension.oid) {
        case '2.5.29.35':
          if (extension.critical) {
            throw const FormatException(
              'CRL AuthorityKeyIdentifier must be non-critical',
            );
          }
          authorityKeyIdentifier = _parseAuthorityKeyIdentifier(
            extension.value,
          );
        case '2.5.29.20':
          if (extension.critical) {
            throw const FormatException('CRLNumber must be non-critical');
          }
          crlNumber = _parseNonNegativeInteger(_single(extension.value, 0x02));
        case '2.5.29.27':
          if (!extension.critical) {
            throw const FormatException('DeltaCRLIndicator must be critical');
          }
          deltaCrlIndicator = _parseNonNegativeInteger(
            _single(extension.value, 0x02),
          );
        case '2.5.29.28':
          if (!extension.critical) {
            throw const FormatException(
              'IssuingDistributionPoint must be critical',
            );
          }
          issuingDistributionPoint = _parseIssuingDistributionPoint(
            extension.value,
          );
        default:
          if (extension.critical) {
            throw UnsupportedError(
              'Unsupported critical CRL extension: ${extension.oid}',
            );
          }
      }
    }
  }
  reader.requireEnd();
  if (version == 1 && (sawEntryExtensions || hasCrlExtensions)) {
    throw const FormatException('CRL extensions require version 2');
  }
  if (deltaCrlIndicator != null &&
      crlNumber != null &&
      deltaCrlIndicator >= crlNumber) {
    throw const FormatException(
      'Delta CRL base number must be less than CRL number',
    );
  }
  if (entries.any(
        (entry) =>
            !constantTimeBytesEqual(entry.effectiveIssuer.der, issuer.der),
      ) &&
      issuingDistributionPoint?.indirectCrl != true) {
    throw const FormatException(
      'certificateIssuer entries require an indirect CRL',
    );
  }
  final entryKeys = <String>{};
  for (final entry in entries) {
    final key = '${entry.effectiveIssuer.der.join(',')}:${entry.serialNumber}';
    if (!entryKeys.add(key)) {
      throw const FormatException(
        'CRL contains duplicate issuer and serial entries',
      );
    }
  }
  return _ParsedTbsCrl(
    version: version,
    signatureAlgorithm: signatureAlgorithm,
    issuer: issuer,
    thisUpdate: thisUpdate,
    nextUpdate: nextUpdate,
    authorityKeyIdentifier: authorityKeyIdentifier,
    crlNumber: crlNumber,
    deltaCrlIndicator: deltaCrlIndicator,
    issuingDistributionPoint: issuingDistributionPoint,
    revokedCertificates: entries,
  );
}

({
  CrlRevokedCertificate entry,
  X509DistinguishedName effectiveIssuer,
  bool hadExtensions,
})
_parseRevokedEntry(DerValue value, X509DistinguishedName inheritedIssuer) {
  final reader = value.reader();
  final serial = _parsePositiveInteger(reader.read(0x02));
  final revocationTime = _parseTime(reader.read());
  CrlRevocationReason? reason;
  DateTime? invalidityDate;
  X509DistinguishedName? certificateIssuer;
  var hadExtensions = false;
  if (!reader.isAtEnd) {
    hadExtensions = true;
    final extensions = _parseExtensions(reader.read(0x30));
    for (final extension in extensions) {
      switch (extension.oid) {
        case '2.5.29.21':
          if (extension.critical) {
            throw const FormatException('CRL reason must be non-critical');
          }
          final enumerated = _single(extension.value, 0x0a);
          if (enumerated.content.length != 1) {
            throw const FormatException('Malformed CRL reason code');
          }
          reason = CrlRevocationReason.fromValue(enumerated.content.single);
        case '2.5.29.24':
          if (extension.critical) {
            throw const FormatException('InvalidityDate must be non-critical');
          }
          invalidityDate = _parseGeneralizedTime(
            _single(extension.value, 0x18),
          );
        case '2.5.29.29':
          if (!extension.critical) {
            throw const FormatException('certificateIssuer must be critical');
          }
          certificateIssuer = _parseCertificateIssuer(extension.value);
        default:
          if (extension.critical) {
            throw UnsupportedError(
              'Unsupported critical CRL entry extension: ${extension.oid}',
            );
          }
      }
    }
  }
  reader.requireEnd();
  final effectiveIssuer = certificateIssuer ?? inheritedIssuer;
  return (
    entry: CrlRevokedCertificate._(
      serialNumber: serial,
      revocationTime: revocationTime,
      reason: reason,
      invalidityDate: invalidityDate,
      effectiveIssuer: effectiveIssuer,
    ),
    effectiveIssuer: effectiveIssuer,
    hadExtensions: hadExtensions,
  );
}

X509DistinguishedName _parseCertificateIssuer(List<int> der) {
  final names = _single(der, 0x30).reader();
  X509DistinguishedName? issuer;
  while (!names.isAtEnd) {
    final name = names.read();
    if (name.tag == 0xa4) {
      if (issuer != null) {
        throw const FormatException(
          'certificateIssuer contains multiple directory names',
        );
      }
      final explicit = name.reader();
      issuer = X509DistinguishedName.parse(explicit.read(0x30).encoded);
      explicit.requireEnd();
    } else {
      throw const FormatException('certificateIssuer requires a directoryName');
    }
  }
  if (issuer == null) {
    throw const FormatException('certificateIssuer must not be empty');
  }
  return issuer;
}

CrlIssuingDistributionPoint _parseIssuingDistributionPoint(List<int> der) {
  final reader = _single(der, 0x30).reader();
  List<int>? distributionPoint;
  var onlyUsers = false;
  var onlyCas = false;
  Set<CrlRevocationReason>? reasons;
  var indirect = false;
  var onlyAttributes = false;
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final field = reader.read();
    final rank = switch (field.tag) {
      0xa0 => 0,
      0x81 => 1,
      0x82 => 2,
      0x83 => 3,
      0x84 => 4,
      0x85 => 5,
      _ => -1,
    };
    if (rank < 0 || rank <= lastTag) {
      throw const FormatException('Malformed IssuingDistributionPoint');
    }
    lastTag = rank;
    switch (field.tag) {
      case 0xa0:
        final point = field.reader();
        final name = point.read();
        if (name.tag != 0xa0 && name.tag != 0xa1) {
          throw const FormatException('Malformed DistributionPointName');
        }
        point.requireEnd();
        distributionPoint = field.encoded;
      case 0x81:
        onlyUsers = _parseImplicitTrue(field);
      case 0x82:
        onlyCas = _parseImplicitTrue(field);
      case 0x83:
        reasons = _parseReasonFlags(field);
      case 0x84:
        indirect = _parseImplicitTrue(field);
      case 0x85:
        onlyAttributes = _parseImplicitTrue(field);
    }
  }
  if ([onlyUsers, onlyCas, onlyAttributes].where((value) => value).length > 1) {
    throw const FormatException(
      'IssuingDistributionPoint scopes are mutually exclusive',
    );
  }
  if (distributionPoint == null &&
      !onlyUsers &&
      !onlyCas &&
      reasons == null &&
      !indirect &&
      !onlyAttributes) {
    throw const FormatException(
      'IssuingDistributionPoint must not encode only defaults',
    );
  }
  return CrlIssuingDistributionPoint(
    onlyContainsUserCertificates: onlyUsers,
    onlyContainsCaCertificates: onlyCas,
    indirectCrl: indirect,
    onlyContainsAttributeCertificates: onlyAttributes,
    onlySomeReasons: reasons,
    distributionPointDer: distributionPoint,
  );
}

Set<CrlRevocationReason> _parseReasonFlags(DerValue field) {
  final bits = _parseImplicitBitString(field);
  final reasons = <CrlRevocationReason>{};
  final significantBits = bits.bytes.length * 8 - bits.unusedBits;
  for (var index = 1; index < significantBits && index <= 10; index++) {
    if (bits.bytes[index ~/ 8] & (0x80 >> (index % 8)) != 0 && index != 7) {
      reasons.add(CrlRevocationReason.fromValue(index));
    }
  }
  if (reasons.isEmpty || significantBits > 11) {
    throw const FormatException('Malformed CRL reason flags');
  }
  return Set.unmodifiable(reasons);
}

bool _parseImplicitTrue(DerValue value) {
  if (value.content.length != 1 || value.content.single != 0xff) {
    throw const FormatException(
      'IssuingDistributionPoint DEFAULT false must be omitted',
    );
  }
  return true;
}

Uint8List? _parseAuthorityKeyIdentifier(List<int> der) {
  final reader = _single(der, 0x30).reader();
  Uint8List? identifier;
  var lastTag = -1;
  var fields = 0;
  while (!reader.isAtEnd) {
    fields++;
    final field = reader.read();
    final rank = switch (field.tag) {
      0x80 => 0,
      0xa1 => 1,
      0x82 => 2,
      _ => -1,
    };
    if (rank < 0 || rank <= lastTag) {
      throw const FormatException('Malformed AuthorityKeyIdentifier');
    }
    lastTag = rank;
    if (field.tag == 0x80) {
      if (field.content.isEmpty) {
        throw const FormatException('AKI key identifier must not be empty');
      }
      identifier = field.content;
    }
  }
  if (fields == 0) {
    throw const FormatException('AuthorityKeyIdentifier must not be empty');
  }
  return identifier;
}

List<Uint8List> _certificateDistributionPoints(X509Certificate certificate) {
  final extension = certificate.extensions
      .where((item) => item.oid == '2.5.29.31')
      .firstOrNull;
  if (extension == null) {
    return const [];
  }
  final reader = _single(extension.value, 0x30).reader();
  final points = <Uint8List>[];
  while (!reader.isAtEnd) {
    final point = reader.read(0x30).reader();
    var lastTag = -1;
    while (!point.isAtEnd) {
      final field = point.read();
      final rank = switch (field.tag) {
        0xa0 => 0,
        0x81 => 1,
        0xa2 => 2,
        _ => -1,
      };
      if (rank < 0 || rank <= lastTag) {
        throw const FormatException(
          'Malformed CRLDistributionPoints extension',
        );
      }
      lastTag = rank;
      if (field.tag == 0xa0) {
        final wrapped = field.reader();
        final name = wrapped.read();
        if (name.tag != 0xa0 && name.tag != 0xa1) {
          throw const FormatException('Malformed DistributionPointName');
        }
        wrapped.requireEnd();
        points.add(field.encoded);
      }
    }
  }
  if (points.isEmpty) {
    throw const FormatException(
      'CRLDistributionPoints contains no distribution point names',
    );
  }
  return List.unmodifiable(points);
}

List<_CrlExtension> _parseExtensions(DerValue sequence) {
  final reader = sequence.reader();
  final extensions = <_CrlExtension>[];
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final extension = reader.read(0x30).reader();
    final oid = _parseOid(extension.read(0x06));
    if (!seen.add(oid)) {
      throw FormatException('Duplicate CRL extension: $oid');
    }
    var critical = false;
    if (!extension.isAtEnd && extension.peekTag() == 0x01) {
      critical = _parseBoolean(extension.read(0x01));
      if (!critical) {
        throw const FormatException(
          'DER DEFAULT false must be omitted for extension criticality',
        );
      }
    }
    final value = extension.read(0x04).content;
    extension.requireEnd();
    extensions.add(_CrlExtension(oid, critical, value));
  }
  if (extensions.isEmpty) {
    throw const FormatException('Extensions must not be empty');
  }
  return extensions;
}

X509AlgorithmIdentifier _parseAlgorithmIdentifier(DerValue value) {
  final reader = value.reader();
  final oid = _parseOid(reader.read(0x06));
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  reader.requireEnd();
  return X509AlgorithmIdentifier(oid, parameters);
}

bool _sameAlgorithm(
  X509AlgorithmIdentifier left,
  X509AlgorithmIdentifier right,
) =>
    left.oid == right.oid &&
    ((left.parametersDer == null && right.parametersDer == null) ||
        (left.parametersDer != null &&
            right.parametersDer != null &&
            constantTimeBytesEqual(left.parametersDer!, right.parametersDer!)));

DateTime _parseTime(DerValue value) {
  final text = String.fromCharCodes(value.content);
  late int year;
  late int offset;
  if (value.tag == 0x17 && RegExp(r'^\d{12}Z$').hasMatch(text)) {
    final shortYear = int.parse(text.substring(0, 2));
    year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
    offset = 2;
  } else if (value.tag == 0x18 && RegExp(r'^\d{14}Z$').hasMatch(text)) {
    year = int.parse(text.substring(0, 4));
    if (year < 2050) {
      throw const FormatException(
        'GeneralizedTime is non-canonical before 2050',
      );
    }
    offset = 4;
  } else {
    throw const FormatException('Invalid CRL time');
  }
  final month = int.parse(text.substring(offset, offset + 2));
  final day = int.parse(text.substring(offset + 2, offset + 4));
  final hour = int.parse(text.substring(offset + 4, offset + 6));
  final minute = int.parse(text.substring(offset + 6, offset + 8));
  final second = int.parse(text.substring(offset + 8, offset + 10));
  final result = DateTime.utc(year, month, day, hour, minute, second);
  if (result.year != year ||
      result.month != month ||
      result.day != day ||
      result.hour != hour ||
      result.minute != minute ||
      result.second != second) {
    throw const FormatException('Invalid CRL calendar time');
  }
  return result;
}

DateTime _parseGeneralizedTime(DerValue value) {
  final text = String.fromCharCodes(value.content);
  if (value.tag != 0x18 || !RegExp(r'^\d{14}Z$').hasMatch(text)) {
    throw const FormatException('Invalid GeneralizedTime');
  }
  final year = int.parse(text.substring(0, 4));
  final month = int.parse(text.substring(4, 6));
  final day = int.parse(text.substring(6, 8));
  final hour = int.parse(text.substring(8, 10));
  final minute = int.parse(text.substring(10, 12));
  final second = int.parse(text.substring(12, 14));
  final result = DateTime.utc(year, month, day, hour, minute, second);
  if (result.year != year ||
      result.month != month ||
      result.day != day ||
      result.hour != hour ||
      result.minute != minute ||
      result.second != second) {
    throw const FormatException('Invalid GeneralizedTime calendar value');
  }
  return result;
}

Uint8List _parseBitString(DerValue value) {
  final bits = _parseImplicitBitString(value);
  if (bits.unusedBits != 0 || bits.bytes.isEmpty) {
    throw const FormatException(
      'CRL signature must be non-empty and byte-aligned',
    );
  }
  return bits.bytes;
}

_BitString _parseImplicitBitString(DerValue value) {
  if (value.content.isEmpty) {
    throw const FormatException('BIT STRING is missing unused-bit count');
  }
  final unused = value.content.first;
  if (unused > 7 ||
      (value.content.length == 1 && unused != 0) ||
      (unused != 0 && value.content.last & ((1 << unused) - 1) != 0)) {
    throw const FormatException('Invalid DER BIT STRING');
  }
  return _BitString(value.content.sublist(1), unused);
}

bool _parseBoolean(DerValue value) {
  if (value.content.length != 1 ||
      (value.content.single != 0 && value.content.single != 0xff)) {
    throw const FormatException('Invalid DER BOOLEAN');
  }
  return value.content.single == 0xff;
}

int _parseSmallInteger(DerValue value) {
  final parsed = _parseNonNegativeInteger(value);
  if (parsed > BigInt.from(0x7fffffff)) {
    throw const FormatException('INTEGER is too large');
  }
  return parsed.toInt();
}

BigInt _parsePositiveInteger(DerValue value) {
  final parsed = _parseNonNegativeInteger(value);
  if (parsed == BigInt.zero) {
    throw const FormatException('INTEGER must be positive');
  }
  return parsed;
}

BigInt _parseNonNegativeInteger(DerValue value) {
  final bytes = value.content;
  if (bytes.isEmpty ||
      bytes.first & 0x80 != 0 ||
      (bytes.length > 1 && bytes.first == 0 && bytes[1] & 0x80 == 0)) {
    throw const FormatException('Invalid non-negative DER INTEGER');
  }
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

String _parseOid(DerValue value) {
  if (value.content.isEmpty) {
    throw const FormatException('Empty OBJECT IDENTIFIER');
  }
  final parts = <BigInt>[];
  var current = BigInt.zero;
  var atStart = true;
  for (final byte in value.content) {
    if (atStart && byte == 0x80) {
      throw const FormatException('Non-minimal OBJECT IDENTIFIER');
    }
    current = (current << 7) | BigInt.from(byte & 0x7f);
    atStart = false;
    if (byte & 0x80 == 0) {
      parts.add(current);
      current = BigInt.zero;
      atStart = true;
    }
  }
  if (!atStart || parts.isEmpty) {
    throw const FormatException('Truncated OBJECT IDENTIFIER');
  }
  final first = parts.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? 0
      : first < BigInt.from(80)
      ? 1
      : 2;
  return [
    BigInt.from(firstArc),
    first - BigInt.from(firstArc * 40),
    ...parts,
  ].join('.');
}

DerValue _single(List<int> bytes, int tag) {
  _validateBytes(bytes);
  final reader = DerReader(bytes);
  final value = reader.read(tag);
  reader.requireEnd();
  return value;
}

final class _ParsedTbsCrl {
  const _ParsedTbsCrl({
    required this.version,
    required this.signatureAlgorithm,
    required this.issuer,
    required this.thisUpdate,
    required this.nextUpdate,
    required this.authorityKeyIdentifier,
    required this.crlNumber,
    required this.deltaCrlIndicator,
    required this.issuingDistributionPoint,
    required this.revokedCertificates,
  });

  final int version;
  final X509AlgorithmIdentifier signatureAlgorithm;
  final X509DistinguishedName issuer;
  final DateTime thisUpdate;
  final DateTime? nextUpdate;
  final Uint8List? authorityKeyIdentifier;
  final BigInt? crlNumber;
  final BigInt? deltaCrlIndicator;
  final CrlIssuingDistributionPoint? issuingDistributionPoint;
  final List<CrlRevokedCertificate> revokedCertificates;
}

final class _CrlExtension {
  const _CrlExtension(this.oid, this.critical, this.value);
  final String oid;
  final bool critical;
  final Uint8List value;
}

final class _BitString {
  const _BitString(this.bytes, this.unusedBits);
  final Uint8List bytes;
  final int unusedBits;
}

void _validateBytes(List<int> bytes) {
  if (bytes.isEmpty || bytes.any((byte) => byte < 0 || byte > 255)) {
    throw const FormatException('DER input must be non-empty bytes');
  }
}

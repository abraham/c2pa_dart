import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cryptography;

import 'byte_compare.dart';
import 'certificate_profile.dart';
import 'der_reader.dart';
import 'hash_algorithm.dart';
import 'path_validation.dart';
import 'signing_algorithm.dart';
import 'x509_certificate.dart';

/// Sends an OCSP request to [endpoint] and returns the DER response.
typedef OcspTransport = Future<List<int>> Function(
  Uri endpoint,
  List<int> requestDer,
);

/// Object identifiers used in RFC 6960 OCSP messages.
abstract final class OcspOids {
  /// The id-pkix-ocsp-basic response type OID from RFC 6960.
  static const basicResponse = '1.3.6.1.5.5.7.48.1.1';

  /// The id-pkix-ocsp-nonce extension OID from RFC 6960.
  static const nonce = '1.3.6.1.5.5.7.48.1.2';
}

/// Digest algorithms accepted in OCSP CertID values.
enum OcspCertIdHashAlgorithm {
  /// SHA-1 CertID hash algorithm, encoded as a 20-byte digest.
  sha1('1.3.14.3.2.26', 20),

  /// SHA-256 CertID hash algorithm, encoded as a 32-byte digest.
  sha256('2.16.840.1.101.3.4.2.1', 32),

  /// SHA-384 CertID hash algorithm, encoded as a 48-byte digest.
  sha384('2.16.840.1.101.3.4.2.2', 48),

  /// SHA-512 CertID hash algorithm, encoded as a 64-byte digest.
  sha512('2.16.840.1.101.3.4.2.3', 64);

  /// Creates RFC 6960 CertID hash metadata.
  const OcspCertIdHashAlgorithm(this.oid, this.digestLength);

  /// The OBJECT IDENTIFIER used in the CertID AlgorithmIdentifier.
  final String oid;

  /// The exact number of bytes required for issuer name and key hashes.
  final int digestLength;

  /// Computes this CertID hash over [input] without performing network I/O.
  Future<List<int>> digest(List<int> input) async => switch (this) {
    sha1 => (await cryptography.Sha1().hash(input)).bytes,
    sha256 => await HashAlgorithm.sha256.digest(input),
    sha384 => await HashAlgorithm.sha384.digest(input),
    sha512 => await HashAlgorithm.sha512.digest(input),
  };
}

/// Top-level OCSPResponseStatus values from RFC 6960 section 4.2.1.
enum OcspResponseStatus {
  /// The responder produced a successful OCSP response.
  successful(0),

  /// The request is malformed according to the OCSP responder.
  malformedRequest(1),

  /// The responder encountered an internal error.
  internalError(2),

  /// The responder asks the client to try the request later.
  tryLater(3),

  /// The responder requires the OCSP request to be signed.
  signatureRequired(5),

  /// The responder is not authorized for this request.
  unauthorized(6);

  /// Creates a response status carrying its RFC 6960 integer [value].
  const OcspResponseStatus(this.value);

  /// The integer value encoded in the OCSPResponseStatus ENUMERATED.
  final int value;

  /// Parses an RFC 6960 OCSPResponseStatus integer.
  ///
  /// Throws a [FormatException] if [value] is not a defined status.
  static OcspResponseStatus fromValue(int value) {
    for (final status in values) {
      if (status.value == value) {
        return status;
      }
    }
    throw FormatException('Unknown OCSP response status: $value');
  }
}

/// Certificate status choices in an RFC 6960 SingleResponse.
enum OcspCertStatus {
  /// The responder asserts that the certificate is not revoked.
  good,

  /// The responder asserts that the certificate has been revoked.
  revoked,

  /// The responder does not know the certificate's status.
  unknown,
}

/// RevokedInfo reason codes carried by RFC 6960 OCSP responses.
enum OcspRevocationReason {
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

  /// Creates an OCSP revocation reason carrying its RFC 5280 code.
  const OcspRevocationReason(this.value);

  /// The integer value encoded in the CRLReason ENUMERATED.
  final int value;

  /// Parses an RFC 5280 CRLReason integer.
  ///
  /// Throws a [FormatException] if [value] is not a defined reason.
  static OcspRevocationReason fromValue(int value) {
    for (final reason in values) {
      if (reason.value == value) {
        return reason;
      }
    }
    throw FormatException('Unknown OCSP revocation reason: $value');
  }
}

/// A parsed OCSP CertID.
final class OcspCertId {
  OcspCertId._({
    required this.hashAlgorithm,
    required List<int> issuerNameHash,
    required List<int> issuerKeyHash,
    required this.serialNumber,
  }) : _issuerNameHash = Uint8List.fromList(issuerNameHash),
       _issuerKeyHash = Uint8List.fromList(issuerKeyHash);

  /// The hash algorithm used by the RFC 6960 CertID.
  final OcspCertIdHashAlgorithm hashAlgorithm;

  final Uint8List _issuerNameHash;
  final Uint8List _issuerKeyHash;

  /// The positive certificate serial number encoded in the CertID.
  final BigInt serialNumber;

  /// A defensive copy of the issuer Name hash bytes.
  Uint8List get issuerNameHash => Uint8List.fromList(_issuerNameHash);

  /// A defensive copy of the issuer SubjectPublicKey BIT STRING hash bytes.
  Uint8List get issuerKeyHash => Uint8List.fromList(_issuerKeyHash);
}

/// One parsed SingleResponse.
final class OcspSingleResponse {
  OcspSingleResponse._({
    required this.certId,
    required this.status,
    required this.thisUpdate,
    required this.nextUpdate,
    required this.revocationTime,
    required this.revocationReason,
  });

  /// The RFC 6960 CertID identifying the certificate this entry covers.
  final OcspCertId certId;

  /// The OCSP certificate status asserted by this SingleResponse.
  final OcspCertStatus status;

  /// The UTC time at which the responder knew this status to be correct.
  final DateTime thisUpdate;

  /// The UTC time by which newer information is expected, or `null`.
  final DateTime? nextUpdate;

  /// The UTC revocation time when [status] is `OcspCertStatus.revoked`.
  final DateTime? revocationTime;

  /// The optional revocation reason when [status] is `OcspCertStatus.revoked`.
  final OcspRevocationReason? revocationReason;
}

/// ResponderID selector from RFC 6960 response data.
sealed class OcspResponderId {
  /// Creates a responder identifier variant.
  const OcspResponderId();
}

/// ResponderID variant that identifies the responder by X.509 Name.
final class OcspResponderByName extends OcspResponderId {
  /// Creates a byName responder identifier from encoded Name [nameDer].
  OcspResponderByName(List<int> nameDer)
    : _nameDer = Uint8List.fromList(nameDer);

  final Uint8List _nameDer;

  /// A defensive copy of the DER-encoded responder Name.
  Uint8List get nameDer => Uint8List.fromList(_nameDer);
}

/// ResponderID variant that identifies the responder by SHA-1 key hash.
final class OcspResponderByKey extends OcspResponderId {
  /// Creates a byKey responder identifier from a 20-byte [keyHash].
  OcspResponderByKey(List<int> keyHash)
    : _keyHash = Uint8List.fromList(keyHash);

  final Uint8List _keyHash;

  /// A defensive copy of the responder SHA-1 key hash bytes.
  Uint8List get keyHash => Uint8List.fromList(_keyHash);
}

/// Parsed BasicOCSPResponse data and its outer protocol status.
final class OcspResponse {
  OcspResponse._({
    required List<int> der,
    required this.responseStatus,
    this.responderId,
    this.producedAt,
    List<OcspSingleResponse> responses = const [],
    List<int>? nonce,
    List<X509Certificate> certificates = const [],
    this.signatureAlgorithm,
    List<int>? signature,
    List<int>? tbsResponseDataDer,
  }) : _der = Uint8List.fromList(der),
       responses = List.unmodifiable(responses),
       _nonce = nonce == null ? null : Uint8List.fromList(nonce),
       certificates = List.unmodifiable(certificates),
       _signature = signature == null ? null : Uint8List.fromList(signature),
       _tbsResponseDataDer = tbsResponseDataDer == null
           ? null
           : Uint8List.fromList(tbsResponseDataDer);

  final Uint8List _der;

  /// The outer OCSPResponseStatus from RFC 6960 section 4.2.1.
  final OcspResponseStatus responseStatus;

  /// The BasicOCSPResponse responder identifier, or `null` on failure status.
  final OcspResponderId? responderId;

  /// The UTC time at which the responder produced the response data.
  final DateTime? producedAt;

  /// The immutable SingleResponse entries parsed from the basic response.
  final List<OcspSingleResponse> responses;

  final Uint8List? _nonce;

  /// Certificates embedded in the BasicOCSPResponse certificate list.
  final List<X509Certificate> certificates;

  /// The signature AlgorithmIdentifier, or `null` on non-success status.
  final X509AlgorithmIdentifier? signatureAlgorithm;

  final Uint8List? _signature;
  final Uint8List? _tbsResponseDataDer;

  /// A defensive copy of the complete DER OCSPResponse.
  Uint8List get der => Uint8List.fromList(_der);

  /// The response nonce bytes, or `null` when no nonce extension was present.
  Uint8List? get nonce => _nonce == null ? null : Uint8List.fromList(_nonce);

  /// The BasicOCSPResponse signature bytes, or `null` on non-success status.
  Uint8List? get signature =>
      _signature == null ? null : Uint8List.fromList(_signature);

  /// The signed ResponseData DER, or `null` on non-success status.
  Uint8List? get tbsResponseDataDer => _tbsResponseDataDer == null
      ? null
      : Uint8List.fromList(_tbsResponseDataDer);

  /// Parses a DER OCSPResponse without performing network I/O.
  ///
  /// Throws a [FormatException] for malformed DER or unsupported structure, and
  /// an [UnsupportedError] for unsupported CertID hash algorithms.
  factory OcspResponse.parse(List<int> input) {
    _validateBytes(input, 'input');
    final der = Uint8List.fromList(input);
    final root = DerReader(der);
    final outer = root.read(0x30);
    root.requireEnd();
    final reader = outer.reader();
    final statusElement = reader.read(0x0a);
    if (statusElement.content.length != 1) {
      throw const FormatException('Invalid OCSP response status');
    }
    final status = OcspResponseStatus.fromValue(statusElement.content.single);
    if (status != OcspResponseStatus.successful) {
      reader.requireEnd();
      return OcspResponse._(der: der, responseStatus: status);
    }
    final responseBytesWrapper = reader.read(0xa0);
    reader.requireEnd();
    final responseBytesReader = responseBytesWrapper.reader();
    final responseBytes = responseBytesReader.read(0x30).reader();
    responseBytesReader.requireEnd();
    if (_decodeOid(responseBytes.read(0x06).content) !=
        OcspOids.basicResponse) {
      throw const FormatException('Unsupported OCSP response type');
    }
    final basicDer = responseBytes.read(0x04).content;
    responseBytes.requireEnd();
    return _parseBasicResponse(der, status, basicDer);
  }
}

/// High-level OCSP verification status produced by this package.
enum OcspResultStatus {
  /// Fresh, trusted evidence says the certificate is not revoked.
  good,

  /// Fresh, trusted evidence says the certificate is revoked.
  revoked,

  /// Evidence was parsed but is not authoritative for the certificate.
  unknown,

  /// No usable responder response was obtained.
  inaccessible,

  /// The response or responder authorization failed validation.
  malformed,
}

/// Machine-readable OCSP verification issue codes.
enum OcspIssueCode {
  /// The configured transport failed to return a response.
  responseUnavailable,

  /// The DER OCSP request exceeded the configured request byte limit.
  requestTooLarge,

  /// The DER OCSP response exceeded the configured response byte limit.
  responseTooLarge,

  /// The responder returned a non-successful OCSPResponseStatus.
  unsuccessfulResponse,

  /// The OCSP response could not be parsed as supported RFC 6960 DER.
  malformedResponse,

  /// The response did not uniquely cover the target certificate and issuer.
  targetCertificateMismatch,

  /// The response nonce was missing or did not match the request nonce.
  nonceMismatch,

  /// The SingleResponse freshness window does not cover evaluation time.
  staleResponse,

  /// No embedded or issuer certificate matched the responder identifier.
  responderCertificateNotFound,

  /// The delegated responder was not authorized by the target issuer.
  unauthorizedResponder,

  /// The BasicOCSPResponse signature was malformed or invalid.
  invalidSignature,

  /// The responder certificate chain did not validate to the trust policy.
  untrustedResponder,

  /// A required hash or signature algorithm is unsupported.
  unsupportedAlgorithm,
}

/// One OCSP verification issue with a stable code and message.
final class OcspIssue {
  /// Creates an OCSP issue with [code] and human-readable [message].
  const OcspIssue(this.code, this.message);

  /// The machine-readable category of the verification issue.
  final OcspIssueCode code;

  /// A human-readable description of the verification issue.
  final String message;
}

/// Structured OCSP verification outcome.
final class OcspVerificationResult {
  /// Creates an OCSP verification result with immutable [issues].
  OcspVerificationResult({
    required this.status,
    required List<OcspIssue> issues,
    this.response,
    this.singleResponse,
    this.responderCertificate,
    this.pathResult,
  }) : issues = List.unmodifiable(issues);

  /// The high-level status computed from parsed evidence and trust checks.
  final OcspResultStatus status;

  /// Immutable issues collected while verifying the response.
  final List<OcspIssue> issues;

  /// The parsed OCSP response, or `null` when parsing failed.
  final OcspResponse? response;

  /// The unique SingleResponse for the target certificate, or `null`.
  final OcspSingleResponse? singleResponse;

  /// The certificate selected to verify the BasicOCSPResponse signature.
  final X509Certificate? responderCertificate;

  /// The responder path validation result, or `null` before path checks run.
  final CertificatePathValidationResult? pathResult;

  /// Whether [status] is exactly `OcspResultStatus.good`.
  bool get isGood => status == OcspResultStatus.good;
}

/// Creates an unsigned DER OCSPRequest for one certificate.
///
/// Implements the single-request form from RFC 6960 and adds a nonce
/// extension when [nonce] is supplied. This function performs no network I/O.
/// Throws an [ArgumentError] if [nonce] is empty, contains non-byte values,
/// or exceeds 32 bytes.
Future<Uint8List> createOcspRequest({
  required X509Certificate certificate,
  required X509Certificate issuer,
  HashAlgorithm hashAlgorithm = HashAlgorithm.sha256,
  List<int>? nonce,
}) async {
  if (nonce != null) {
    _validateBytes(nonce, 'nonce');
    if (nonce.length > 32) {
      throw ArgumentError.value(
        nonce,
        'nonce',
        'RFC 8954 limits OCSP nonces to 32 bytes',
      );
    }
  }
  final certId = await _encodeCertId(certificate, issuer, hashAlgorithm);
  final request = _sequence([certId]);
  final requestList = _sequence([request]);
  final tbsRequest = _sequence([
    requestList,
    if (nonce != null)
      _tlv(0xa2, _sequence([_extension(OcspOids.nonce, _octet(nonce))])),
  ]);
  return Uint8List.fromList(_sequence([tbsRequest]));
}

/// Fetches and verifies OCSP using a caller-provided transport.
///
/// Performs network I/O only through [transport]. Size-limit failures and
/// transport errors return `OcspResultStatus.inaccessible` instead of throwing.
/// Throws an [ArgumentError] if either configured byte limit is less than 1.
Future<OcspVerificationResult> fetchAndVerifyOcsp({
  required Uri endpoint,
  required X509Certificate certificate,
  required X509Certificate issuer,
  required TrustPolicy trustPolicy,
  required OcspTransport transport,
  HashAlgorithm requestHashAlgorithm = HashAlgorithm.sha256,
  List<int>? nonce,
  DateTime? evaluationTime,
  Duration maxAgeWithoutNextUpdate = const Duration(hours: 24),
  Duration clockSkew = const Duration(minutes: 5),
  int maxRequestBytes = 16 * 1024,
  int maxResponseBytes = 1024 * 1024,
}) async {
  if (maxRequestBytes < 1 || maxResponseBytes < 1) {
    throw ArgumentError('OCSP size limits must be positive');
  }
  final request = await createOcspRequest(
    certificate: certificate,
    issuer: issuer,
    hashAlgorithm: requestHashAlgorithm,
    nonce: nonce,
  );
  if (request.length > maxRequestBytes) {
    return OcspVerificationResult(
      status: OcspResultStatus.inaccessible,
      issues: const [
        OcspIssue(
          OcspIssueCode.requestTooLarge,
          'OCSP request exceeds the configured size limit',
        ),
      ],
    );
  }
  late List<int> response;
  try {
    response = await transport(endpoint, request);
  } catch (error) {
    return OcspVerificationResult(
      status: OcspResultStatus.inaccessible,
      issues: [
        OcspIssue(
          OcspIssueCode.responseUnavailable,
          'OCSP transport failed: $error',
        ),
      ],
    );
  }
  if (response.length > maxResponseBytes) {
    return OcspVerificationResult(
      status: OcspResultStatus.inaccessible,
      issues: const [
        OcspIssue(
          OcspIssueCode.responseTooLarge,
          'OCSP response exceeds the configured size limit',
        ),
      ],
    );
  }
  return verifyOcspResponse(
    response,
    certificate: certificate,
    issuer: issuer,
    trustPolicy: trustPolicy,
    expectedNonce: nonce,
    evaluationTime: evaluationTime,
    maxAgeWithoutNextUpdate: maxAgeWithoutNextUpdate,
    clockSkew: clockSkew,
  );
}

/// Verifies a BasicOCSPResponse for [certificate] issued by [issuer].
///
/// Parses RFC 6960 DER, checks a matching CertID, optional nonce,
/// thisUpdate/nextUpdate freshness, responder authorization, signature, and
/// certificate path. This function performs no network I/O. Throws an
/// [ArgumentError] if freshness durations are negative.
Future<OcspVerificationResult> verifyOcspResponse(
  List<int> responseDer, {
  required X509Certificate certificate,
  required X509Certificate issuer,
  required TrustPolicy trustPolicy,
  List<int>? expectedNonce,
  DateTime? evaluationTime,
  Duration maxAgeWithoutNextUpdate = const Duration(hours: 24),
  Duration clockSkew = const Duration(minutes: 5),
}) async {
  if (maxAgeWithoutNextUpdate.isNegative || clockSkew.isNegative) {
    throw ArgumentError('OCSP freshness durations must not be negative');
  }
  late OcspResponse response;
  try {
    response = OcspResponse.parse(responseDer);
  } on UnsupportedError catch (error) {
    return OcspVerificationResult(
      status: OcspResultStatus.malformed,
      issues: [
        OcspIssue(
          OcspIssueCode.unsupportedAlgorithm,
          error.message ?? error.toString(),
        ),
      ],
    );
  } on FormatException catch (error) {
    return OcspVerificationResult(
      status: OcspResultStatus.malformed,
      issues: [OcspIssue(OcspIssueCode.malformedResponse, error.message)],
    );
  }
  if (response.responseStatus != OcspResponseStatus.successful) {
    return OcspVerificationResult(
      status: OcspResultStatus.inaccessible,
      response: response,
      issues: [
        OcspIssue(
          OcspIssueCode.unsuccessfulResponse,
          'OCSP responder returned ${response.responseStatus.name}',
        ),
      ],
    );
  }

  final issues = <OcspIssue>[];
  try {
    final targetIssuedByIssuer =
        constantTimeBytesEqual(certificate.issuer.der, issuer.subject.der) &&
        await verifySignatureWithCertificatePublicKey(
          certificate: issuer,
          signatureAlgorithm: certificate.signatureAlgorithm,
          data: certificate.tbsCertificateDer,
          signature: certificate.signature,
        );
    if (!targetIssuedByIssuer) {
      issues.add(
        const OcspIssue(
          OcspIssueCode.targetCertificateMismatch,
          'Target certificate was not issued by the supplied issuer',
        ),
      );
    }
  } on UnsupportedError catch (error) {
    issues.add(
      OcspIssue(
        OcspIssueCode.unsupportedAlgorithm,
        error.message ?? error.toString(),
      ),
    );
  } on FormatException {
    issues.add(
      const OcspIssue(
        OcspIssueCode.targetCertificateMismatch,
        'Target certificate signature is malformed',
      ),
    );
  }
  final matches = <OcspSingleResponse>[];
  for (final candidate in response.responses) {
    if (await _certIdMatches(candidate.certId, certificate, issuer)) {
      matches.add(candidate);
    }
  }
  if (matches.length != 1) {
    issues.add(
      const OcspIssue(
        OcspIssueCode.targetCertificateMismatch,
        'OCSP response does not contain exactly one matching CertID',
      ),
    );
  }
  final single = matches.length == 1 ? matches.single : null;
  if (expectedNonce != null &&
      (response.nonce == null ||
          !constantTimeBytesEqual(expectedNonce, response.nonce!))) {
    issues.add(
      const OcspIssue(
        OcspIssueCode.nonceMismatch,
        'OCSP response nonce does not match the request',
      ),
    );
  }

  final time = (evaluationTime ?? trustPolicy.evaluationTime).toUtc();
  if (single != null) {
    final tooEarly = single.thisUpdate.isAfter(time.add(clockSkew));
    final tooLate = single.nextUpdate != null
        ? single.nextUpdate!.isBefore(time.subtract(clockSkew))
        : time.difference(single.thisUpdate) > maxAgeWithoutNextUpdate;
    final inconsistentProduction = response.producedAt!.isBefore(
      single.thisUpdate,
    );
    if (tooEarly || tooLate || inconsistentProduction) {
      issues.add(
        const OcspIssue(
          OcspIssueCode.staleResponse,
          'OCSP SingleResponse is not fresh at the evaluation time',
        ),
      );
    }
  }

  final responder = await _findResponderCertificate(response, issuer);
  if (responder == null) {
    issues.add(
      const OcspIssue(
        OcspIssueCode.responderCertificateNotFound,
        'No certificate matches the OCSP responder identifier',
      ),
    );
    return OcspVerificationResult(
      status: OcspResultStatus.malformed,
      response: response,
      singleResponse: single,
      issues: issues,
    );
  }

  late SigningAlgorithm signingAlgorithm;
  try {
    signingAlgorithm = _signingAlgorithm(response.signatureAlgorithm!);
    final valid = await verifySignatureWithCertificatePublicKey(
      certificate: responder,
      signatureAlgorithm: response.signatureAlgorithm!,
      data: response.tbsResponseDataDer!,
      signature: response.signature!,
    );
    if (!valid) {
      issues.add(
        const OcspIssue(
          OcspIssueCode.invalidSignature,
          'BasicOCSPResponse signature verification failed',
        ),
      );
    }
  } on UnsupportedError catch (error) {
    issues.add(
      OcspIssue(
        OcspIssueCode.unsupportedAlgorithm,
        error.message ?? error.toString(),
      ),
    );
    return OcspVerificationResult(
      status: OcspResultStatus.malformed,
      response: response,
      singleResponse: single,
      responderCertificate: responder,
      issues: issues,
    );
  } on FormatException {
    issues.add(
      const OcspIssue(
        OcspIssueCode.invalidSignature,
        'BasicOCSPResponse signature encoding is malformed',
      ),
    );
    signingAlgorithm = _algorithmForKey(responder);
  }

  final responderIsIssuer = constantTimeBytesEqual(responder.der, issuer.der);
  CertificatePathValidationResult pathResult;
  final policyAtTime = TrustPolicy(
    trustAnchors: trustPolicy.trustAnchors,
    intermediates: [
      ...trustPolicy.intermediates,
      issuer.der,
      ...response.certificates
          .where((item) => !constantTimeBytesEqual(item.der, responder.der))
          .map((item) => item.der),
    ],
    allowedEndEntitySha256Hashes: responderIsIssuer
        ? const []
        : trustPolicy.allowedEndEntitySha256Hashes,
    allowedEkuOids: const {ExtendedKeyUsageOids.ocspSigning},
    evaluationTime: time,
    maxDepth: trustPolicy.maxDepth,
  );
  if (responderIsIssuer) {
    pathResult = await validateCertificateAuthorityPath(
      issuer.der,
      policy: policyAtTime,
    );
  } else {
    var authorized = false;
    try {
      authorized =
          constantTimeBytesEqual(responder.issuer.der, issuer.subject.der) &&
          await verifySignatureWithCertificatePublicKey(
            certificate: issuer,
            signatureAlgorithm: responder.signatureAlgorithm,
            data: responder.tbsCertificateDer,
            signature: responder.signature,
          );
    } on UnsupportedError {
      authorized = false;
    } on FormatException {
      authorized = false;
    }
    if (!authorized) {
      issues.add(
        const OcspIssue(
          OcspIssueCode.unauthorizedResponder,
          'Delegated responder was not issued by the target issuer',
        ),
      );
    }
    pathResult = await validateOcspResponderCertificatePath(
      responder.der,
      algorithm: signingAlgorithm,
      policy: policyAtTime,
    );
  }
  if (!pathResult.isTrusted) {
    final profileFailure = pathResult.issues.any(
      (issue) => issue.code == CertificatePathIssueCode.leafProfile,
    );
    issues.add(
      OcspIssue(
        profileFailure
            ? OcspIssueCode.unauthorizedResponder
            : OcspIssueCode.untrustedResponder,
        'OCSP responder path validation failed: '
        '${pathResult.issues.map((issue) => issue.message).join('; ')}',
      ),
    );
  }

  final fatal = issues.any(
    (issue) =>
        issue.code != OcspIssueCode.staleResponse &&
        issue.code != OcspIssueCode.targetCertificateMismatch,
  );
  final evidenceUnavailable = issues.any(
    (issue) =>
        issue.code == OcspIssueCode.staleResponse ||
        issue.code == OcspIssueCode.targetCertificateMismatch,
  );
  final status = fatal
      ? OcspResultStatus.malformed
      : evidenceUnavailable || single == null
      ? OcspResultStatus.unknown
      : single.status == OcspCertStatus.revoked &&
            !single.revocationTime!.isAfter(time)
      ? OcspResultStatus.revoked
      : single.status == OcspCertStatus.good ||
            (single.status == OcspCertStatus.revoked &&
                single.revocationTime!.isAfter(time))
      ? OcspResultStatus.good
      : OcspResultStatus.unknown;
  return OcspVerificationResult(
    status: status,
    response: response,
    singleResponse: single,
    responderCertificate: responder,
    pathResult: pathResult,
    issues: issues,
  );
}

OcspResponse _parseBasicResponse(
  Uint8List outerDer,
  OcspResponseStatus status,
  List<int> basicDer,
) {
  final root = DerReader(basicDer);
  final basic = root.read(0x30);
  root.requireEnd();
  final reader = basic.reader();
  final tbs = reader.read(0x30);
  final parsed = _parseResponseData(tbs);
  final signatureAlgorithm = _parseAlgorithmIdentifier(reader.read(0x30));
  final signature = _bitString(reader.read(0x03));
  final certificates = <X509Certificate>[];
  if (!reader.isAtEnd) {
    final wrapper = reader.read(0xa0).reader();
    final sequence = wrapper.read(0x30).reader();
    wrapper.requireEnd();
    while (!sequence.isAtEnd) {
      certificates.add(
        X509Certificate.parse(
          sequence.read(0x30).encoded,
          allowUnknownCriticalExtensions: true,
        ),
      );
    }
  }
  reader.requireEnd();
  return OcspResponse._(
    der: outerDer,
    responseStatus: status,
    responderId: parsed.responderId,
    producedAt: parsed.producedAt,
    responses: parsed.responses,
    nonce: parsed.nonce,
    certificates: certificates,
    signatureAlgorithm: signatureAlgorithm,
    signature: signature,
    tbsResponseDataDer: tbs.encoded,
  );
}

({
  OcspResponderId responderId,
  DateTime producedAt,
  List<OcspSingleResponse> responses,
  List<int>? nonce,
})
_parseResponseData(DerValue element) {
  final reader = element.reader();
  if (!reader.isAtEnd && reader.peekTag() == 0xa0) {
    final version = reader.read(0xa0).reader();
    if (_positiveInteger(version.read(0x02).content) != BigInt.zero) {
      throw const FormatException('Unsupported OCSP response version');
    }
    version.requireEnd();
  }
  final responderElement = reader.read();
  final OcspResponderId responderId;
  if (responderElement.tag == 0xa1) {
    final byName = responderElement.reader();
    responderId = OcspResponderByName(byName.read(0x30).encoded);
    byName.requireEnd();
  } else if (responderElement.tag == 0x82 &&
      responderElement.content.length == 20) {
    responderId = OcspResponderByKey(responderElement.content);
  } else {
    throw const FormatException('Invalid OCSP responder identifier');
  }
  final producedAt = _generalizedTime(reader.read(0x18).content);
  final responseSequence = reader.read(0x30).reader();
  if (responseSequence.isAtEnd) {
    throw const FormatException('OCSP responses must not be empty');
  }
  final responses = <OcspSingleResponse>[];
  while (!responseSequence.isAtEnd) {
    responses.add(_parseSingleResponse(responseSequence.read(0x30)));
  }
  List<int>? nonce;
  if (!reader.isAtEnd) {
    final extensions = reader.read(0xa1).reader();
    nonce = _parseExtensions(extensions.read(0x30), allowNonce: true);
    extensions.requireEnd();
  }
  reader.requireEnd();
  return (
    responderId: responderId,
    producedAt: producedAt,
    responses: responses,
    nonce: nonce,
  );
}

OcspSingleResponse _parseSingleResponse(DerValue element) {
  final reader = element.reader();
  final certId = _parseCertId(reader.read(0x30));
  final status = reader.read();
  late OcspCertStatus certStatus;
  DateTime? revocationTime;
  OcspRevocationReason? revocationReason;
  if (status.tag == 0x80 && status.content.isEmpty) {
    certStatus = OcspCertStatus.good;
  } else if (status.tag == 0x82 && status.content.isEmpty) {
    certStatus = OcspCertStatus.unknown;
  } else if (status.tag == 0xa1) {
    certStatus = OcspCertStatus.revoked;
    final revoked = status.reader();
    revocationTime = _generalizedTime(revoked.read(0x18).content);
    if (!revoked.isAtEnd) {
      final reason = revoked.read(0xa0).reader();
      final value = reason.read(0x0a);
      if (value.content.length != 1) {
        throw const FormatException('Invalid OCSP revocation reason');
      }
      revocationReason = OcspRevocationReason.fromValue(value.content.single);
      reason.requireEnd();
    }
    revoked.requireEnd();
  } else {
    throw const FormatException('Invalid OCSP certificate status');
  }
  final thisUpdate = _generalizedTime(reader.read(0x18).content);
  DateTime? nextUpdate;
  if (!reader.isAtEnd && reader.peekTag() == 0xa0) {
    final next = reader.read(0xa0).reader();
    nextUpdate = _generalizedTime(next.read(0x18).content);
    next.requireEnd();
    if (nextUpdate.isBefore(thisUpdate)) {
      throw const FormatException('nextUpdate precedes thisUpdate');
    }
  }
  if (!reader.isAtEnd) {
    final extensions = reader.read(0xa1).reader();
    _parseExtensions(extensions.read(0x30), allowNonce: false);
    extensions.requireEnd();
  }
  reader.requireEnd();
  return OcspSingleResponse._(
    certId: certId,
    status: certStatus,
    thisUpdate: thisUpdate,
    nextUpdate: nextUpdate,
    revocationTime: revocationTime,
    revocationReason: revocationReason,
  );
}

OcspCertId _parseCertId(DerValue element) {
  final reader = element.reader();
  final hashAlgorithm = _parseOcspCertIdHashAlgorithm(
    _parseAlgorithmIdentifier(reader.read(0x30)),
  );
  final issuerNameHash = reader.read(0x04).content;
  final issuerKeyHash = reader.read(0x04).content;
  final serial = _positiveInteger(reader.read(0x02).content);
  reader.requireEnd();
  if (issuerNameHash.length != hashAlgorithm.digestLength ||
      issuerKeyHash.length != hashAlgorithm.digestLength) {
    throw const FormatException('OCSP CertID hash has the wrong length');
  }

  return OcspCertId._(
    hashAlgorithm: hashAlgorithm,
    issuerNameHash: issuerNameHash,
    issuerKeyHash: issuerKeyHash,
    serialNumber: serial,
  );
}

OcspCertIdHashAlgorithm _parseOcspCertIdHashAlgorithm(
  X509AlgorithmIdentifier algorithm,
) {
  final parameters = algorithm.parametersDer;
  if (parameters != null &&
      !(parameters.length == 2 &&
          parameters[0] == 0x05 &&
          parameters[1] == 0)) {
    throw const FormatException(
      'CertID hash parameters must be absent or NULL',
    );
  }
  return switch (algorithm.oid) {
    '1.3.14.3.2.26' => OcspCertIdHashAlgorithm.sha1,
    '2.16.840.1.101.3.4.2.1' => OcspCertIdHashAlgorithm.sha256,
    '2.16.840.1.101.3.4.2.2' => OcspCertIdHashAlgorithm.sha384,
    '2.16.840.1.101.3.4.2.3' => OcspCertIdHashAlgorithm.sha512,
    _ => throw UnsupportedError(
      'Unsupported OCSP CertID hash algorithm: ${algorithm.oid}',
    ),
  };
}

List<int>? _parseExtensions(DerValue element, {required bool allowNonce}) {
  final reader = element.reader();
  List<int>? nonce;
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final extension = reader.read(0x30).reader();
    final oid = _decodeOid(extension.read(0x06).content);
    if (!seen.add(oid)) {
      throw FormatException('Duplicate OCSP extension: $oid');
    }
    var critical = false;
    if (!extension.isAtEnd && extension.peekTag() == 0x01) {
      final value = extension.read(0x01).content;
      if (value.length != 1 || value.single != 0xff) {
        throw const FormatException('Invalid DER BOOLEAN');
      }
      critical = true;
    }
    final value = extension.read(0x04).content;
    extension.requireEnd();
    if (oid == OcspOids.nonce && allowNonce) {
      final nonceReader = DerReader(value);
      nonce = nonceReader.read(0x04).content;
      nonceReader.requireEnd();
      if (nonce.isEmpty || nonce.length > 32) {
        throw const FormatException('OCSP nonce must contain 1 to 32 bytes');
      }
    } else if (critical) {
      throw FormatException('Unsupported critical OCSP extension: $oid');
    }
  }
  return nonce;
}

Future<X509Certificate?> _findResponderCertificate(
  OcspResponse response,
  X509Certificate issuer,
) async {
  final candidates = <X509Certificate>[issuer, ...response.certificates];
  final matches = <X509Certificate>[];
  for (final candidate in candidates) {
    final matchesId = switch (response.responderId!) {
      OcspResponderByName() => constantTimeBytesEqual(
        candidate.subject.der,
        (response.responderId! as OcspResponderByName).nameDer,
      ),
      OcspResponderByKey() => constantTimeBytesEqual(
        await _sha1(candidate.subjectPublicKey),
        (response.responderId! as OcspResponderByKey).keyHash,
      ),
    };
    if (matchesId &&
        !matches.any(
          (item) => constantTimeBytesEqual(item.der, candidate.der),
        )) {
      matches.add(candidate);
    }
  }
  return matches.length == 1 ? matches.single : null;
}

Future<bool> _certIdMatches(
  OcspCertId certId,
  X509Certificate certificate,
  X509Certificate issuer,
) async =>
    certId.serialNumber == certificate.serialNumber &&
    constantTimeBytesEqual(
      certId.issuerNameHash,
      await certId.hashAlgorithm.digest(issuer.subject.der),
    ) &&
    constantTimeBytesEqual(
      certId.issuerKeyHash,
      await certId.hashAlgorithm.digest(issuer.subjectPublicKey),
    );

Future<List<int>> _encodeCertId(
  X509Certificate certificate,
  X509Certificate issuer,
  HashAlgorithm hashAlgorithm,
) async => _sequence([
  _algorithmIdentifier(_hashOid(hashAlgorithm)),
  _octet(await hashAlgorithm.digest(issuer.subject.der)),
  _octet(await hashAlgorithm.digest(issuer.subjectPublicKey)),
  _integer(certificate.serialNumber),
]);

SigningAlgorithm _signingAlgorithm(X509AlgorithmIdentifier signature) =>
    switch (signature.oid) {
      '1.2.840.10045.4.3.2' => SigningAlgorithm.es256,
      '1.2.840.10045.4.3.3' => SigningAlgorithm.es384,
      '1.2.840.10045.4.3.4' => SigningAlgorithm.es512,
      '1.2.840.113549.1.1.11' => SigningAlgorithm.ps256,
      '1.2.840.113549.1.1.12' => SigningAlgorithm.ps384,
      '1.2.840.113549.1.1.13' => SigningAlgorithm.ps512,
      '1.2.840.113549.1.1.10' => _rsaPssAlgorithm(signature.parametersDer),
      '1.3.101.112' => SigningAlgorithm.ed25519,
      _ => throw UnsupportedError(
        'Unsupported OCSP signature algorithm: ${signature.oid}',
      ),
    };

SigningAlgorithm _algorithmForKey(X509Certificate certificate) =>
    switch (certificate.subjectPublicKeyAlgorithm.oid) {
      '1.3.101.112' => SigningAlgorithm.ed25519,
      '1.2.840.10045.2.1' => switch (_parameterOid(
        certificate.subjectPublicKeyAlgorithm,
      )) {
        '1.2.840.10045.3.1.7' => SigningAlgorithm.es256,
        '1.3.132.0.34' => SigningAlgorithm.es384,
        '1.3.132.0.35' => SigningAlgorithm.es512,
        _ => throw UnsupportedError('Unsupported responder EC curve'),
      },
      '1.2.840.113549.1.1.1' => SigningAlgorithm.ps256,
      _ => throw UnsupportedError('Unsupported responder public key'),
    };

SigningAlgorithm _rsaPssAlgorithm(List<int>? parameters) {
  if (parameters == null) {
    throw const FormatException('RSA-PSS parameters are required');
  }
  final root = DerReader(parameters);
  final sequence = root.read(0x30);
  root.requireEnd();
  final reader = sequence.reader();
  if (reader.isAtEnd || reader.peekTag() != 0xa0) {
    throw const FormatException('RSA-PSS SHA-2 parameters are required');
  }
  final hash = reader.read(0xa0).reader();
  final algorithm = _parseHashAlgorithm(
    _parseAlgorithmIdentifier(hash.read(0x30)),
  );
  hash.requireEnd();
  return switch (algorithm) {
    HashAlgorithm.sha256 => SigningAlgorithm.ps256,
    HashAlgorithm.sha384 => SigningAlgorithm.ps384,
    HashAlgorithm.sha512 => SigningAlgorithm.ps512,
  };
}

String _parameterOid(X509AlgorithmIdentifier algorithm) {
  final parameters = algorithm.parametersDer;
  if (parameters == null) {
    throw const FormatException('Missing EC named-curve parameters');
  }
  final reader = DerReader(parameters);
  final oid = _decodeOid(reader.read(0x06).content);
  reader.requireEnd();
  return oid;
}

X509AlgorithmIdentifier _parseAlgorithmIdentifier(DerValue element) {
  final reader = element.reader();
  final oid = _decodeOid(reader.read(0x06).content);
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  reader.requireEnd();
  return X509AlgorithmIdentifier(oid, parameters);
}

HashAlgorithm _parseHashAlgorithm(X509AlgorithmIdentifier algorithm) {
  final parameters = algorithm.parametersDer;
  if (parameters != null &&
      !(parameters.length == 2 &&
          parameters[0] == 0x05 &&
          parameters[1] == 0)) {
    throw const FormatException(
      'Hash AlgorithmIdentifier parameters must be absent or NULL',
    );
  }
  return switch (algorithm.oid) {
    '2.16.840.1.101.3.4.2.1' => HashAlgorithm.sha256,
    '2.16.840.1.101.3.4.2.2' => HashAlgorithm.sha384,
    '2.16.840.1.101.3.4.2.3' => HashAlgorithm.sha512,
    _ => throw UnsupportedError(
      'Unsupported OCSP CertID hash algorithm: ${algorithm.oid}',
    ),
  };
}

String _hashOid(HashAlgorithm algorithm) => switch (algorithm) {
  HashAlgorithm.sha256 => '2.16.840.1.101.3.4.2.1',
  HashAlgorithm.sha384 => '2.16.840.1.101.3.4.2.2',
  HashAlgorithm.sha512 => '2.16.840.1.101.3.4.2.3',
};

Future<List<int>> _sha1(List<int> input) async =>
    (await cryptography.Sha1().hash(input)).bytes;

DateTime _generalizedTime(List<int> bytes) {
  final text = String.fromCharCodes(bytes);
  final match = RegExp(r'^(\d{14})(?:\.(\d*[1-9]))?Z$').firstMatch(text);
  if (match == null) {
    throw const FormatException('Invalid DER GeneralizedTime');
  }
  final base = match.group(1)!;
  final fraction = match.group(2);
  final microsecond = fraction == null
      ? 0
      : int.parse('${fraction}000000'.substring(0, 6));
  final year = int.parse(base.substring(0, 4));
  final month = int.parse(base.substring(4, 6));
  final day = int.parse(base.substring(6, 8));
  final hour = int.parse(base.substring(8, 10));
  final minute = int.parse(base.substring(10, 12));
  final second = int.parse(base.substring(12, 14));
  final value = DateTime.utc(
    year,
    month,
    day,
    hour,
    minute,
    second,
    0,
    microsecond,
  );
  if (value.year != year ||
      value.month != month ||
      value.day != day ||
      value.hour != hour ||
      value.minute != minute ||
      value.second != second) {
    throw const FormatException('Invalid calendar time');
  }
  return value;
}

List<int> _bitString(DerValue element) {
  if (element.content.isEmpty || element.content.first != 0) {
    throw const FormatException(
      'OCSP signature must be a byte-aligned BIT STRING',
    );
  }
  final signature = element.content.sublist(1);
  if (signature.isEmpty) {
    throw const FormatException('OCSP signature must not be empty');
  }
  return signature;
}

BigInt _positiveInteger(List<int> bytes) {
  if (bytes.isEmpty ||
      bytes.first & 0x80 != 0 ||
      (bytes.length > 1 && bytes.first == 0 && bytes[1] & 0x80 == 0)) {
    throw const FormatException('Invalid non-negative DER INTEGER');
  }
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

String _decodeOid(List<int> bytes) {
  if (bytes.isEmpty) {
    throw const FormatException('Empty OBJECT IDENTIFIER');
  }
  final values = <BigInt>[];
  var value = BigInt.zero;
  var continued = false;
  for (final byte in bytes) {
    if (!continued && byte == 0x80) {
      throw const FormatException('Non-minimal OBJECT IDENTIFIER');
    }
    value = (value << 7) | BigInt.from(byte & 0x7f);
    continued = byte & 0x80 != 0;
    if (!continued) {
      values.add(value);
      value = BigInt.zero;
    }
  }
  if (continued || values.isEmpty) {
    throw const FormatException('Truncated OBJECT IDENTIFIER');
  }
  final first = values.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? 0
      : first < BigInt.from(80)
      ? 1
      : 2;
  return [
    BigInt.from(firstArc),
    first - BigInt.from(firstArc * 40),
    ...values,
  ].join('.');
}

List<int> _algorithmIdentifier(String oid) =>
    _sequence([_oid(oid), _tlv(0x05, const [])]);

List<int> _extension(String oid, List<int> value) =>
    _sequence([_oid(oid), _octet(value)]);

List<int> _sequence(List<List<int>> values) =>
    _tlv(0x30, values.expand((value) => value).toList());

List<int> _octet(List<int> value) => _tlv(0x04, value);

List<int> _integer(BigInt value) {
  if (value < BigInt.zero) {
    throw ArgumentError.value(value, 'value', 'Must not be negative');
  }
  final bytes = <int>[];
  var remaining = value;
  do {
    bytes.insert(0, (remaining & BigInt.from(0xff)).toInt());
    remaining >>= 8;
  } while (remaining != BigInt.zero);
  if (bytes.first & 0x80 != 0) {
    bytes.insert(0, 0);
  }
  return _tlv(0x02, bytes);
}

List<int> _oid(String oid) {
  final arcs = oid.split('.').map(BigInt.parse).toList();
  if (arcs.length < 2 ||
      arcs[0] < BigInt.zero ||
      arcs[0] > BigInt.from(2) ||
      arcs[1] < BigInt.zero ||
      (arcs[0] < BigInt.from(2) && arcs[1] >= BigInt.from(40))) {
    throw ArgumentError.value(oid, 'oid', 'Invalid OBJECT IDENTIFIER');
  }
  final output = <int>[];
  void append(BigInt value) {
    final bytes = <int>[(value & BigInt.from(0x7f)).toInt()];
    value >>= 7;
    while (value != BigInt.zero) {
      bytes.insert(0, (value & BigInt.from(0x7f)).toInt() | 0x80);
      value >>= 7;
    }
    output.addAll(bytes);
  }

  append(arcs[0] * BigInt.from(40) + arcs[1]);
  for (final arc in arcs.skip(2)) {
    if (arc < BigInt.zero) {
      throw ArgumentError.value(oid, 'oid', 'Invalid OBJECT IDENTIFIER');
    }
    append(arc);
  }
  return _tlv(0x06, output);
}

List<int> _tlv(int tag, List<int> content) {
  if (content.length < 128) {
    return [tag, content.length, ...content];
  }
  final bytes = <int>[];
  var length = content.length;
  while (length != 0) {
    bytes.insert(0, length & 0xff);
    length >>= 8;
  }
  return [tag, 0x80 | bytes.length, ...bytes, ...content];
}

void _validateBytes(List<int> bytes, String name) {
  if (bytes.isEmpty) {
    throw ArgumentError.value(bytes, name, 'Must not be empty');
  }
  for (final byte in bytes) {
    if (byte < 0 || byte > 255) {
      throw ArgumentError.value(bytes, name, 'Contains a non-byte value');
    }
  }
}

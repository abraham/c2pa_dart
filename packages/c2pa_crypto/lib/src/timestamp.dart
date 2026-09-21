import 'dart:typed_data';

import 'byte_compare.dart';
import 'certificate_profile.dart';
import 'der_reader.dart';
import 'hash_algorithm.dart';
import 'path_validation.dart';
import 'signing_algorithm.dart';
import 'x509_certificate.dart';

/// Sends an RFC 3161 request and returns the DER response.
typedef TimestampTransport = Future<List<int>> Function(List<int> requestDer);

/// CMS OIDs used by the RFC 3161 timestamp token subset.
abstract final class CmsOids {
  /// The CMS `signedData` content type OID.
  static const signedData = '1.2.840.113549.1.7.2';

  /// The CMS signed-attribute OID for content type.
  static const contentType = '1.2.840.113549.1.9.3';

  /// The CMS signed-attribute OID for message digest.
  static const messageDigest = '1.2.840.113549.1.9.4';

  /// The CMS signed-attribute OID for signing time.
  static const signingTime = '1.2.840.113549.1.9.5';

  /// The RFC 3161 TSTInfo eContentType OID.
  static const tstInfo = '1.2.840.113549.1.9.16.1.4';
}

/// The signer identifier carried by CMS SignerInfo.
sealed class CmsSignerIdentifier {
  const CmsSignerIdentifier();
}

/// A CMS signer identifier based on issuer name and certificate serial.
final class CmsIssuerAndSerialNumber extends CmsSignerIdentifier {
  /// Creates a signer identifier from issuer DER and certificate serial.
  CmsIssuerAndSerialNumber(List<int> issuerDer, this.serialNumber)
    : _issuerDer = Uint8List.fromList(issuerDer);

  final Uint8List _issuerDer;

  /// The non-negative X.509 certificate serial number.
  final BigInt serialNumber;

  /// A defensive copy of the DER-encoded issuer name.
  Uint8List get issuerDer => Uint8List.fromList(_issuerDer);
}

/// A CMS signer identifier based on subject key identifier bytes.
final class CmsSubjectKeyIdentifier extends CmsSignerIdentifier {
  /// Creates a signer identifier from a subject key identifier value.
  CmsSubjectKeyIdentifier(List<int> identifier)
    : _identifier = Uint8List.fromList(identifier);

  final Uint8List _identifier;

  /// A defensive copy of the subject key identifier bytes.
  Uint8List get identifier => Uint8List.fromList(_identifier);
}

/// Parsed CMS SignerInfo fields used by timestamp validation.
final class CmsSignerInfo {
  CmsSignerInfo._({
    required this.identifier,
    required this.digestAlgorithm,
    required List<int> signedAttributesDer,
    required List<int> signedAttributesSignatureInput,
    required this.contentType,
    required List<int>? messageDigest,
    required this.signingTime,
    required this.signatureAlgorithm,
    required List<int> signature,
  }) : _signedAttributesDer = Uint8List.fromList(signedAttributesDer),
       _signedAttributesSignatureInput = Uint8List.fromList(
         signedAttributesSignatureInput,
       ),
       _messageDigest = messageDigest == null
           ? null
           : Uint8List.fromList(messageDigest),
       _signature = Uint8List.fromList(signature);

  /// The CMS SignerIdentifier used to locate the TSA certificate.
  final CmsSignerIdentifier identifier;

  /// The SignerInfo digest algorithm declared for signed attributes.
  final HashAlgorithm digestAlgorithm;
  final Uint8List _signedAttributesDer;
  final Uint8List _signedAttributesSignatureInput;

  /// The signed contentType attribute value, or `null` if absent.
  final String? contentType;
  final Uint8List? _messageDigest;

  /// The signed signingTime attribute, or `null` if absent.
  final DateTime? signingTime;

  /// The SignerInfo signature AlgorithmIdentifier.
  final X509AlgorithmIdentifier signatureAlgorithm;
  final Uint8List _signature;

  /// Exact context-specific `[0]` DER from SignerInfo.
  Uint8List get signedAttributesDer => Uint8List.fromList(_signedAttributesDer);

  /// Exact signed-attribute encoding used for signature verification.
  ///
  /// CMS signs the IMPLICIT field as a DER SET OF, so only the outer tag is
  /// changed from `[0]` to SET while preserving the encoded length and content.
  Uint8List get signedAttributesSignatureInput =>
      Uint8List.fromList(_signedAttributesSignatureInput);

  /// A defensive copy of the signed messageDigest attribute, or `null`.
  Uint8List? get messageDigest =>
      _messageDigest == null ? null : Uint8List.fromList(_messageDigest);

  /// A defensive copy of the CMS SignerInfo signature bytes.
  Uint8List get signature => Uint8List.fromList(_signature);
}

/// Parsed RFC 3161 TSTInfo.
final class TimestampInfo {
  TimestampInfo._({
    required this.policyOid,
    required this.messageImprintAlgorithm,
    required List<int> messageImprint,
    required this.serialNumber,
    required this.genTime,
    required this.nonce,
  }) : _messageImprint = Uint8List.fromList(messageImprint);

  /// The RFC 3161 policy OID asserted by the timestamp authority.
  final String policyOid;

  /// The hash algorithm used for the RFC 3161 message imprint.
  final HashAlgorithm messageImprintAlgorithm;
  final Uint8List _messageImprint;

  /// The RFC 3161 timestamp token serial number.
  final BigInt serialNumber;

  /// The RFC 3161 `genTime` instant in UTC.
  final DateTime genTime;

  /// The RFC 3161 nonce copied from the request, or `null` if absent.
  final BigInt? nonce;

  /// A defensive copy of the RFC 3161 message imprint digest.
  Uint8List get messageImprint => Uint8List.fromList(_messageImprint);
}

/// Strictly parsed CMS SignedData timestamp token.
final class CmsTimestampToken {
  CmsTimestampToken._({
    required List<int> der,
    required List<int> encapsulatedContent,
    required List<X509Certificate> certificates,
    required this.signerInfo,
    required this.timestampInfo,
  }) : _der = Uint8List.fromList(der),
       _encapsulatedContent = Uint8List.fromList(encapsulatedContent),
       certificates = List.unmodifiable(certificates);

  final Uint8List _der;
  final Uint8List _encapsulatedContent;

  /// The unauthenticated CMS certificate bag included in the token.
  final List<X509Certificate> certificates;

  /// The single CMS SignerInfo parsed from the timestamp token.
  final CmsSignerInfo signerInfo;

  /// The parsed RFC 3161 TSTInfo encapsulated by the token.
  final TimestampInfo timestampInfo;

  /// A defensive copy of the original DER-encoded CMS token.
  Uint8List get der => Uint8List.fromList(_der);

  /// A defensive copy of the embedded TSTInfo DER bytes.
  Uint8List get encapsulatedContent => Uint8List.fromList(_encapsulatedContent);

  /// Parses a strict DER CMS SignedData timestamp token.
  ///
  /// Throws [FormatException] for malformed or unsupported CMS/RFC 3161
  /// structure and [UnsupportedError] for unsupported hash algorithms.
  factory CmsTimestampToken.parse(List<int> input) {
    _validateBytes(input, 'input');
    final der = Uint8List.fromList(input);
    final root = DerReader(der);
    final contentInfo = root.read(0x30);
    root.requireEnd();
    final contentReader = contentInfo.reader();
    if (_decodeOid(contentReader.read(0x06).content) != CmsOids.signedData) {
      throw const FormatException('CMS ContentInfo is not SignedData');
    }
    final wrapper = contentReader.read(0xa0);
    contentReader.requireEnd();
    final wrapperReader = wrapper.reader();
    final signedData = wrapperReader.read(0x30);
    wrapperReader.requireEnd();
    final signedDataReader = signedData.reader();
    final version = _positiveInteger(signedDataReader.read(0x02).content);
    if (version != BigInt.one && version != BigInt.from(3)) {
      throw const FormatException('Unsupported CMS SignedData version');
    }

    final digestSet = signedDataReader.read(0x31);
    final digestReader = digestSet.reader();
    final declaredDigests = <HashAlgorithm>{};
    while (!digestReader.isAtEnd) {
      final digestElement = digestReader.read(0x30);
      final digest = _parseHashAlgorithm(
        _parseAlgorithmIdentifier(digestElement),
      );
      if (!declaredDigests.add(digest)) {
        throw const FormatException('Duplicate CMS digest algorithm');
      }
    }
    if (declaredDigests.isEmpty) {
      throw const FormatException('CMS digestAlgorithms must not be empty');
    }

    final encap = signedDataReader.read(0x30);
    final encapReader = encap.reader();
    if (_decodeOid(encapReader.read(0x06).content) != CmsOids.tstInfo) {
      throw const FormatException('CMS content is not TSTInfo');
    }
    if (encapReader.isAtEnd || encapReader.peekTag() != 0xa0) {
      throw const FormatException('Timestamp token must embed TSTInfo');
    }
    final eContentWrapper = encapReader.read(0xa0);
    encapReader.requireEnd();
    final eContentReader = eContentWrapper.reader();
    final eContent = eContentReader.read(0x04).content;
    eContentReader.requireEnd();

    final certificates = <X509Certificate>[];
    if (!signedDataReader.isAtEnd && signedDataReader.peekTag() == 0xa0) {
      // The CertificateSet is an unauthenticated bag: it is not covered by the
      // signature, and the signer is located by issuer and serial number from
      // SignerInfo rather than by position. DER SET-OF ordering therefore
      // carries no security meaning here, while real timestamp authorities
      // routinely emit the chain in leaf-to-root order. Enforcing the ordering
      // rejected otherwise valid tokens.
      final certificateSet = signedDataReader.read(0xa0).reader();
      while (!certificateSet.isAtEnd) {
        final certificateDer = certificateSet.read(0x30).encoded;
        certificates.add(
          X509Certificate.parse(
            certificateDer,
            allowUnknownCriticalExtensions: true,
          ),
        );
      }
    }
    if (!signedDataReader.isAtEnd && signedDataReader.peekTag() == 0xa1) {
      throw const FormatException(
        'CMS revocation information is outside the supported subset',
      );
    }
    final signerInfos = signedDataReader.read(0x31).reader();
    final signerInfoElement = signerInfos.read(0x30);
    if (!signerInfos.isAtEnd) {
      throw const FormatException(
        'Timestamp token must contain exactly one SignerInfo',
      );
    }
    signedDataReader.requireEnd();
    final signerInfo = _parseSignerInfo(signerInfoElement);
    if (!declaredDigests.contains(signerInfo.digestAlgorithm)) {
      throw const FormatException(
        'SignerInfo digest is absent from SignedData digestAlgorithms',
      );
    }
    return CmsTimestampToken._(
      der: der,
      encapsulatedContent: eContent,
      certificates: certificates,
      signerInfo: signerInfo,
      timestampInfo: _parseTimestampInfo(eContent),
    );
  }
}

/// The high-level result of RFC 3161 timestamp validation.
enum TimestampStatus {
  /// All CMS, imprint, nonce, signature, profile, and path checks succeeded.
  valid,

  /// The token parsed, but one or more cryptographic or profile checks failed.
  invalid,

  /// The token is structurally valid but no trusted TSA path was found.
  untrusted,

  /// The input was not supported DER CMS/RFC 3161 syntax.
  malformed,

  /// The token uses an algorithm outside the supported subset.
  unsupported,
}

/// Machine-readable RFC 3161 timestamp validation issue codes.
enum TimestampIssueCode {
  /// The token could not be parsed as supported CMS/RFC 3161 DER.
  malformedToken,

  /// SignerInfo lacks the required contentType signed attribute.
  missingContentTypeAttribute,

  /// The contentType signed attribute is not RFC 3161 TSTInfo.
  wrongContentTypeAttribute,

  /// SignerInfo lacks the required messageDigest signed attribute.
  missingMessageDigestAttribute,

  /// The signed messageDigest does not match the embedded TSTInfo.
  messageDigestMismatch,

  /// The TSTInfo message imprint does not match the supplied bytes.
  messageImprintMismatch,

  /// The TSTInfo nonce does not match the expected request nonce.
  nonceMismatch,

  /// No included certificate uniquely matches the SignerInfo identifier.
  signerCertificateNotFound,

  /// SignerInfo digest and signature algorithm parameters disagree.
  signatureAlgorithmMismatch,

  /// The CMS SignerInfo signature is malformed or fails verification.
  invalidCmsSignature,

  /// The TSA certificate fails RFC 3161 profile or validity checks.
  tsaCertificateProfile,

  /// No trusted certificate path reaches a configured TSA trust anchor.
  untrustedCertificatePath,

  /// The token uses a hash or signature algorithm this SDK does not support.
  unsupportedAlgorithm,
}

/// One issue found while parsing or validating a timestamp token.
final class TimestampIssue {
  /// Creates a timestamp validation issue with [code] and [message].
  const TimestampIssue(this.code, this.message);

  /// The machine-readable timestamp validation issue code.
  final TimestampIssueCode code;

  /// The human-readable timestamp validation issue detail.
  final String message;
}

/// Structured outcome of CMS/RFC 3161 timestamp validation.
final class TimestampVerificationResult {
  /// Creates a structured timestamp verification result.
  TimestampVerificationResult({
    required this.status,
    required List<TimestampIssue> issues,
    this.token,
    this.signerCertificate,
    this.pathResult,
  }) : issues = List.unmodifiable(issues);

  /// The overall timestamp verification status.
  final TimestampStatus status;

  /// The immutable timestamp verification issues collected.
  final List<TimestampIssue> issues;

  /// The parsed token, or `null` when parsing failed.
  final CmsTimestampToken? token;

  /// The included TSA certificate that matched SignerInfo, or `null`.
  final X509Certificate? signerCertificate;

  /// The TSA certificate path result, or `null` before path validation.
  final CertificatePathValidationResult? pathResult;

  /// Whether [status] is [TimestampStatus.valid].
  bool get isValid => status == TimestampStatus.valid;
}

/// Verifies a C2PA RFC 3161 timestamp token.
Future<TimestampVerificationResult> verifyTimestampToken(
  List<int> tokenDer, {
  required List<int> signedBytes,
  required TrustPolicy trustPolicy,
  BigInt? expectedNonce,
}) async {
  late CmsTimestampToken token;
  try {
    token = CmsTimestampToken.parse(tokenDer);
  } on UnsupportedError catch (error) {
    return TimestampVerificationResult(
      status: TimestampStatus.unsupported,
      issues: [
        TimestampIssue(
          TimestampIssueCode.unsupportedAlgorithm,
          error.message ?? error.toString(),
        ),
      ],
    );
  } on FormatException catch (error) {
    return TimestampVerificationResult(
      status: TimestampStatus.malformed,
      issues: [
        TimestampIssue(TimestampIssueCode.malformedToken, error.message),
      ],
    );
  }

  final issues = <TimestampIssue>[];
  final signerInfo = token.signerInfo;
  if (signerInfo.contentType == null) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.missingContentTypeAttribute,
        'SignerInfo is missing the contentType signed attribute',
      ),
    );
  } else if (signerInfo.contentType != CmsOids.tstInfo) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.wrongContentTypeAttribute,
        'SignerInfo contentType is not TSTInfo',
      ),
    );
  }
  final messageDigest = signerInfo.messageDigest;
  if (messageDigest == null) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.missingMessageDigestAttribute,
        'SignerInfo is missing the messageDigest signed attribute',
      ),
    );
  } else {
    final actual = await signerInfo.digestAlgorithm.digest(
      token.encapsulatedContent,
    );
    if (!constantTimeBytesEqual(actual, messageDigest)) {
      issues.add(
        const TimestampIssue(
          TimestampIssueCode.messageDigestMismatch,
          'Signed messageDigest does not match the embedded TSTInfo',
        ),
      );
    }
  }

  final imprint = await token.timestampInfo.messageImprintAlgorithm.digest(
    signedBytes,
  );
  if (!constantTimeBytesEqual(imprint, token.timestampInfo.messageImprint)) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.messageImprintMismatch,
        'Timestamp message imprint does not match the supplied signed bytes',
      ),
    );
  }
  if (expectedNonce != null && token.timestampInfo.nonce != expectedNonce) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.nonceMismatch,
        'Timestamp nonce does not match the request nonce',
      ),
    );
  }

  final signerCertificate = _findSignerCertificate(token);
  if (signerCertificate == null) {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.signerCertificateNotFound,
        'No included certificate matches the SignerInfo identifier',
      ),
    );
    return TimestampVerificationResult(
      status: TimestampStatus.invalid,
      token: token,
      issues: issues,
    );
  }

  late SigningAlgorithm signingAlgorithm;
  late X509AlgorithmIdentifier verificationAlgorithm;
  try {
    final resolved = _resolveSignatureAlgorithm(
      signerInfo.signatureAlgorithm,
      signerInfo.digestAlgorithm,
    );
    signingAlgorithm = resolved.$1;
    verificationAlgorithm = resolved.$2;
  } on UnsupportedError catch (error) {
    issues.add(
      TimestampIssue(
        TimestampIssueCode.unsupportedAlgorithm,
        error.message ?? error.toString(),
      ),
    );
    return TimestampVerificationResult(
      status: TimestampStatus.unsupported,
      token: token,
      signerCertificate: signerCertificate,
      issues: issues,
    );
  } on FormatException catch (error) {
    issues.add(
      TimestampIssue(
        TimestampIssueCode.signatureAlgorithmMismatch,
        error.message,
      ),
    );
    return TimestampVerificationResult(
      status: TimestampStatus.invalid,
      token: token,
      signerCertificate: signerCertificate,
      issues: issues,
    );
  }

  try {
    final signatureValid = await verifySignatureWithCertificatePublicKey(
      certificate: signerCertificate,
      signatureAlgorithm: verificationAlgorithm,
      data: signerInfo.signedAttributesSignatureInput,
      signature: signerInfo.signature,
    );
    if (!signatureValid) {
      issues.add(
        const TimestampIssue(
          TimestampIssueCode.invalidCmsSignature,
          'CMS SignerInfo signature verification failed',
        ),
      );
    }
  } on UnsupportedError catch (error) {
    issues.add(
      TimestampIssue(
        TimestampIssueCode.unsupportedAlgorithm,
        error.message ?? error.toString(),
      ),
    );
  } on FormatException {
    issues.add(
      const TimestampIssue(
        TimestampIssueCode.invalidCmsSignature,
        'CMS signature encoding is malformed',
      ),
    );
  }

  final evaluationPolicy = TrustPolicy(
    trustAnchors: trustPolicy.trustAnchors,
    intermediates: [
      ...trustPolicy.intermediates,
      ...token.certificates
          .where((certificate) => certificate != signerCertificate)
          .map((certificate) => certificate.der),
    ],
    allowedEndEntitySha256Hashes: trustPolicy.allowedEndEntitySha256Hashes,
    allowedEkuOids: const {ExtendedKeyUsageOids.timeStamping},
    evaluationTime: token.timestampInfo.genTime,
    maxDepth: trustPolicy.maxDepth,
  );
  final pathResult = await validateTsaCertificatePath(
    signerCertificate.der,
    algorithm: signingAlgorithm,
    policy: evaluationPolicy,
  );
  if (!pathResult.isTrusted) {
    final profileFailure = pathResult.issues.any(
      (issue) =>
          issue.code == CertificatePathIssueCode.leafProfile ||
          issue.code == CertificatePathIssueCode.certificateExpired ||
          issue.code == CertificatePathIssueCode.certificateNotYetValid,
    );
    issues.add(
      TimestampIssue(
        profileFailure
            ? TimestampIssueCode.tsaCertificateProfile
            : TimestampIssueCode.untrustedCertificatePath,
        'TSA certificate path validation failed: '
        '${pathResult.issues.map((issue) => issue.message).join('; ')}',
      ),
    );
  }

  final hasUnsupported = issues.any(
    (issue) => issue.code == TimestampIssueCode.unsupportedAlgorithm,
  );
  final onlyTrustFailure =
      issues.isNotEmpty &&
      issues.every(
        (issue) => issue.code == TimestampIssueCode.untrustedCertificatePath,
      ) &&
      pathResult.status == CertificatePathStatus.untrusted;
  return TimestampVerificationResult(
    status: hasUnsupported
        ? TimestampStatus.unsupported
        : issues.isEmpty
        ? TimestampStatus.valid
        : onlyTrustFailure
        ? TimestampStatus.untrusted
        : TimestampStatus.invalid,
    token: token,
    signerCertificate: signerCertificate,
    pathResult: pathResult,
    issues: issues,
  );
}

/// Creates a strict DER RFC 3161 TimeStampReq.
Future<Uint8List> createTimestampRequest({
  required List<int> signedBytes,
  HashAlgorithm hashAlgorithm = HashAlgorithm.sha256,
  String? policyOid,
  BigInt? nonce,
  bool requestCertificates = true,
}) async {
  _validateBytes(signedBytes, 'signedBytes', allowEmpty: true);
  if (nonce != null && nonce < BigInt.zero) {
    throw ArgumentError.value(nonce, 'nonce', 'Must not be negative');
  }
  final imprint = await hashAlgorithm.digest(signedBytes);
  final fields = <int>[
    ..._integer(BigInt.one),
    ..._sequence([
      ..._algorithmIdentifier(_hashOid(hashAlgorithm)),
      ..._octetString(imprint),
    ]),
    if (policyOid != null) ..._oid(policyOid),
    if (nonce != null) ..._integer(nonce),
    if (requestCertificates) ..._tlv(0x01, [0xff]),
  ];
  return Uint8List.fromList(_sequence(fields));
}

/// Creates and sends an RFC 3161 request through a caller-supplied transport.
///
/// No network implementation is provided by this package.
Future<Uint8List> requestTimestamp({
  required List<int> signedBytes,
  required TimestampTransport transport,
  HashAlgorithm hashAlgorithm = HashAlgorithm.sha256,
  String? policyOid,
  BigInt? nonce,
  bool requestCertificates = true,
}) async {
  final request = await createTimestampRequest(
    signedBytes: signedBytes,
    hashAlgorithm: hashAlgorithm,
    policyOid: policyOid,
    nonce: nonce,
    requestCertificates: requestCertificates,
  );
  final response = await transport(request);
  _validateBytes(response, 'transport response');
  return Uint8List.fromList(response);
}

CmsSignerInfo _parseSignerInfo(DerValue element) {
  final reader = element.reader();
  final version = _positiveInteger(reader.read(0x02).content);
  final sidElement = reader.read();
  late CmsSignerIdentifier identifier;
  if (sidElement.tag == 0x30) {
    if (version != BigInt.one) {
      throw const FormatException(
        'IssuerAndSerialNumber requires SignerInfo version 1',
      );
    }
    final sidReader = sidElement.reader();
    final issuer = sidReader.read(0x30).encoded;
    final serial = _positiveInteger(sidReader.read(0x02).content);
    sidReader.requireEnd();
    identifier = CmsIssuerAndSerialNumber(issuer, serial);
  } else if (sidElement.tag == 0x80) {
    if (version != BigInt.from(3) || sidElement.content.isEmpty) {
      throw const FormatException(
        'SubjectKeyIdentifier requires SignerInfo version 3',
      );
    }
    identifier = CmsSubjectKeyIdentifier(sidElement.content);
  } else {
    throw const FormatException('Unsupported CMS signer identifier');
  }
  final digestAlgorithm = _parseHashAlgorithm(
    _parseAlgorithmIdentifier(reader.read(0x30)),
  );
  if (reader.isAtEnd || reader.peekTag() != 0xa0) {
    throw const FormatException(
      'Timestamp SignerInfo requires signed attributes',
    );
  }
  final signedAttributes = reader.read(0xa0);
  if (signedAttributes.content.isEmpty) {
    throw const FormatException('CMS signed attributes must not be empty');
  }
  final parsedAttributes = _parseSignedAttributes(signedAttributes);
  final signatureAlgorithm = _parseAlgorithmIdentifier(reader.read(0x30));
  final signature = reader.read(0x04).content;
  if (signature.isEmpty) {
    throw const FormatException('CMS signature must not be empty');
  }
  if (!reader.isAtEnd) {
    if (reader.peekTag() != 0xa1) {
      throw const FormatException('Unexpected data after CMS signature');
    }
    _validateUnsignedAttributes(reader.read(0xa1));
  }

  reader.requireEnd();
  final signatureInput = Uint8List.fromList(signedAttributes.encoded);
  signatureInput[0] = 0x31;
  return CmsSignerInfo._(
    identifier: identifier,
    digestAlgorithm: digestAlgorithm,
    signedAttributesDer: signedAttributes.encoded,
    signedAttributesSignatureInput: signatureInput,
    contentType: parsedAttributes.contentType,
    messageDigest: parsedAttributes.messageDigest,
    signingTime: parsedAttributes.signingTime,
    signatureAlgorithm: signatureAlgorithm,
    signature: signature,
  );
}

void _validateUnsignedAttributes(DerValue attributes) {
  final reader = attributes.reader();
  if (reader.isAtEnd) {
    throw const FormatException('CMS unsigned attributes must not be empty');
  }
  // Unsigned attributes are not covered by the signature, so their SET-OF
  // ordering is not security relevant and is not enforced here.
  while (!reader.isAtEnd) {
    final attribute = reader.read(0x30);
    final attributeReader = attribute.reader();
    _decodeOid(attributeReader.read(0x06).content);
    final values = attributeReader.read(0x31).reader();
    if (values.isAtEnd) {
      throw const FormatException('CMS attribute values must not be empty');
    }
    while (!values.isAtEnd) {
      values.read();
    }
    attributeReader.requireEnd();
  }
}

({String? contentType, List<int>? messageDigest, DateTime? signingTime})
_parseSignedAttributes(DerValue signedAttributes) {
  final reader = signedAttributes.reader();
  String? contentType;
  List<int>? messageDigest;
  DateTime? signingTime;
  List<int>? previous;
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final attribute = reader.read(0x30);
    if (previous != null && compareBytes(previous, attribute.encoded) >= 0) {
      throw const FormatException(
        'CMS signed attributes are not in canonical DER order',
      );
    }
    previous = attribute.encoded;
    final attributeReader = attribute.reader();
    final oid = _decodeOid(attributeReader.read(0x06).content);
    if (!seen.add(oid)) {
      throw FormatException('Duplicate CMS signed attribute: $oid');
    }
    final values = attributeReader.read(0x31).reader();
    final value = values.read();
    values.requireEnd();
    attributeReader.requireEnd();
    switch (oid) {
      case CmsOids.contentType:
        if (value.tag != 0x06) {
          throw const FormatException('Invalid contentType attribute value');
        }
        contentType = _decodeOid(value.content);
      case CmsOids.messageDigest:
        if (value.tag != 0x04 || value.content.isEmpty) {
          throw const FormatException('Invalid messageDigest attribute value');
        }
        messageDigest = value.content;
      case CmsOids.signingTime:
        if (value.tag != 0x17 && value.tag != 0x18) {
          throw const FormatException('Invalid signingTime attribute value');
        }
        signingTime = _parseTime(value);
    }
  }
  return (
    contentType: contentType,
    messageDigest: messageDigest,
    signingTime: signingTime,
  );
}

TimestampInfo _parseTimestampInfo(List<int> der) {
  final root = DerReader(der);
  final sequence = root.read(0x30);
  root.requireEnd();
  final reader = sequence.reader();
  if (_positiveInteger(reader.read(0x02).content) != BigInt.one) {
    throw const FormatException('Unsupported TSTInfo version');
  }
  final policy = _decodeOid(reader.read(0x06).content);
  final messageImprintReader = reader.read(0x30).reader();
  final imprintAlgorithm = _parseHashAlgorithm(
    _parseAlgorithmIdentifier(messageImprintReader.read(0x30)),
  );
  final imprint = messageImprintReader.read(0x04).content;
  messageImprintReader.requireEnd();
  if (imprint.length != imprintAlgorithm.digestLength) {
    throw const FormatException('TSTInfo message imprint has wrong length');
  }
  final serial = _positiveInteger(reader.read(0x02).content);
  final genTimeElement = reader.read(0x18);
  final genTime = _parseGeneralizedTime(genTimeElement.content);

  BigInt? nonce;
  var lastOptionalTag = 0;
  while (!reader.isAtEnd) {
    final element = reader.read();
    if (element.tag == 0x30) {
      if (lastOptionalTag >= 1) {
        throw const FormatException('Invalid TSTInfo optional field order');
      }
      lastOptionalTag = 1;
      _validateAccuracy(element);
    } else if (element.tag == 0x01) {
      if (lastOptionalTag >= 2 ||
          element.content.length != 1 ||
          element.content.single != 0xff) {
        throw const FormatException('Invalid TSTInfo ordering field');
      }
      lastOptionalTag = 2;
    } else if (element.tag == 0x02) {
      if (lastOptionalTag >= 3) {
        throw const FormatException('Invalid TSTInfo nonce field');
      }
      lastOptionalTag = 3;
      nonce = _positiveInteger(element.content);
    } else if (element.tag == 0xa0) {
      if (lastOptionalTag >= 4) {
        throw const FormatException('Invalid TSTInfo tsa field');
      }
      lastOptionalTag = 4;
      final tsa = element.reader();
      tsa.read();
      tsa.requireEnd();
    } else if (element.tag == 0xa1) {
      if (lastOptionalTag >= 5) {
        throw const FormatException('Invalid TSTInfo extensions field');
      }
      lastOptionalTag = 5;
      final extensions = element.reader();
      if (extensions.isAtEnd) {
        throw const FormatException('TSTInfo extensions must not be empty');
      }
      while (!extensions.isAtEnd) {
        extensions.read(0x30);
      }
    } else {
      throw const FormatException('Unexpected TSTInfo field');
    }
  }
  return TimestampInfo._(
    policyOid: policy,
    messageImprintAlgorithm: imprintAlgorithm,
    messageImprint: imprint,
    serialNumber: serial,
    genTime: genTime,
    nonce: nonce,
  );
}

void _validateAccuracy(DerValue element) {
  final reader = element.reader();
  if (reader.isAtEnd) {
    throw const FormatException('TSTInfo accuracy must not be empty');
  }
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final field = reader.read();
    final order = switch (field.tag) {
      0x02 => 0,
      0x80 => 1,
      0x81 => 2,
      _ => throw const FormatException('Invalid TSTInfo accuracy field'),
    };
    if (order <= lastTag) {
      throw const FormatException('Invalid TSTInfo accuracy field order');
    }
    lastTag = order;
    final value = _positiveInteger(field.content);
    if ((field.tag == 0x80 || field.tag == 0x81) &&
        (value < BigInt.one || value > BigInt.from(999))) {
      throw const FormatException('TSTInfo accuracy value is out of range');
    }
  }
}

X509Certificate? _findSignerCertificate(CmsTimestampToken token) {
  final identifier = token.signerInfo.identifier;
  final matches = token.certificates.where((certificate) {
    return switch (identifier) {
      CmsIssuerAndSerialNumber() =>
        certificate.serialNumber == identifier.serialNumber &&
            constantTimeBytesEqual(
              certificate.issuer.der,
              identifier.issuerDer,
            ),
      CmsSubjectKeyIdentifier() =>
        certificate.subjectKeyIdentifier != null &&
            constantTimeBytesEqual(
              certificate.subjectKeyIdentifier!,
              identifier.identifier,
            ),
    };
  }).toList();
  return matches.length == 1 ? matches.single : null;
}

(SigningAlgorithm, X509AlgorithmIdentifier) _resolveSignatureAlgorithm(
  X509AlgorithmIdentifier signature,
  HashAlgorithm digest,
) {
  if (signature.oid == '1.2.840.113549.1.1.10') {
    final pssDigest = _parsePssDigest(signature.parametersDer);
    if (pssDigest != digest) {
      throw const FormatException(
        'SignerInfo digest and RSA-PSS parameters disagree',
      );
    }
  }
  final expectedDigest = switch (signature.oid) {
    '1.2.840.113549.1.1.11' || '1.2.840.10045.4.3.2' => HashAlgorithm.sha256,
    '1.2.840.113549.1.1.12' || '1.2.840.10045.4.3.3' => HashAlgorithm.sha384,
    '1.2.840.113549.1.1.13' || '1.2.840.10045.4.3.4' => HashAlgorithm.sha512,
    _ => null,
  };
  if (expectedDigest != null && expectedDigest != digest) {
    throw const FormatException(
      'SignerInfo digest and signature algorithms disagree',
    );
  }

  return switch (signature.oid) {
    '1.2.840.10045.4.3.2' => (SigningAlgorithm.es256, signature),
    '1.2.840.10045.4.3.3' => (SigningAlgorithm.es384, signature),
    '1.2.840.10045.4.3.4' => (SigningAlgorithm.es512, signature),
    '1.2.840.113549.1.1.11' => (SigningAlgorithm.ps256, signature),
    '1.2.840.113549.1.1.12' => (SigningAlgorithm.ps384, signature),
    '1.2.840.113549.1.1.13' => (SigningAlgorithm.ps512, signature),
    '1.2.840.113549.1.1.1' => (
      switch (digest) {
        HashAlgorithm.sha256 => SigningAlgorithm.ps256,
        HashAlgorithm.sha384 => SigningAlgorithm.ps384,
        HashAlgorithm.sha512 => SigningAlgorithm.ps512,
      },
      X509AlgorithmIdentifier(switch (digest) {
        HashAlgorithm.sha256 => '1.2.840.113549.1.1.11',
        HashAlgorithm.sha384 => '1.2.840.113549.1.1.12',
        HashAlgorithm.sha512 => '1.2.840.113549.1.1.13',
      }, signature.parametersDer),
    ),
    '1.2.840.113549.1.1.10' => (
      switch (digest) {
        HashAlgorithm.sha256 => SigningAlgorithm.ps256,
        HashAlgorithm.sha384 => SigningAlgorithm.ps384,
        HashAlgorithm.sha512 => SigningAlgorithm.ps512,
      },
      signature,
    ),
    '1.3.101.112' => (SigningAlgorithm.ed25519, signature),
    _ => throw UnsupportedError(
      'Unsupported CMS signature algorithm: ${signature.oid}',
    ),
  };
}

HashAlgorithm _parsePssDigest(List<int>? parametersDer) {
  if (parametersDer == null) {
    throw const FormatException('RSA-PSS parameters are required');
  }
  final root = DerReader(parametersDer);
  final sequence = root.read(0x30);
  root.requireEnd();
  final reader = sequence.reader();
  HashAlgorithm? hash;
  HashAlgorithm? mgfHash;
  int? saltLength;
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final field = reader.read();
    if (field.tag < 0xa0 || field.tag > 0xa3 || field.tag <= lastTag) {
      throw const FormatException('Invalid RSA-PSS parameters');
    }
    lastTag = field.tag;
    final explicit = field.reader();
    switch (field.tag) {
      case 0xa0:
        hash = _parseHashAlgorithm(
          _parseAlgorithmIdentifier(explicit.read(0x30)),
        );
      case 0xa1:
        final mgf = _parseAlgorithmIdentifier(explicit.read(0x30));
        if (mgf.oid != '1.2.840.113549.1.1.8' || mgf.parametersDer == null) {
          throw const FormatException('RSA-PSS requires MGF1');
        }
        final inner = DerReader(mgf.parametersDer!);
        mgfHash = _parseHashAlgorithm(
          _parseAlgorithmIdentifier(inner.read(0x30)),
        );
        inner.requireEnd();
      case 0xa2:
        saltLength = _positiveInteger(explicit.read(0x02).content).toInt();
      case 0xa3:
        if (_positiveInteger(explicit.read(0x02).content) != BigInt.one) {
          throw const FormatException('Unsupported RSA-PSS trailer field');
        }
    }
    explicit.requireEnd();
  }
  if (hash == null || mgfHash != hash || saltLength != hash.digestLength) {
    throw const FormatException(
      'RSA-PSS must use matching hash, MGF1, and digest-sized salt',
    );
  }
  return hash;
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
      'Unsupported timestamp hash algorithm: ${algorithm.oid}',
    ),
  };
}

String _hashOid(HashAlgorithm algorithm) => switch (algorithm) {
  HashAlgorithm.sha256 => '2.16.840.1.101.3.4.2.1',
  HashAlgorithm.sha384 => '2.16.840.1.101.3.4.2.2',
  HashAlgorithm.sha512 => '2.16.840.1.101.3.4.2.3',
};

DateTime _parseTime(DerValue element) => switch (element.tag) {
  0x17 => _parseUtcTime(element.content),
  0x18 => _parseGeneralizedTime(element.content),
  _ => throw const FormatException('Unsupported time encoding'),
};

DateTime _parseUtcTime(List<int> bytes) {
  final text = String.fromCharCodes(bytes);
  if (!RegExp(r'^\d{12}Z$').hasMatch(text)) {
    throw const FormatException('Invalid DER UTCTime');
  }
  final year = int.parse(text.substring(0, 2));
  return _checkedDateTime(
    year >= 50 ? 1900 + year : 2000 + year,
    text.substring(2),
  );
}

DateTime _parseGeneralizedTime(List<int> bytes) {
  final text = String.fromCharCodes(bytes);
  final match = RegExp(r'^(\d{14})(?:\.(\d*[1-9]))?Z$').firstMatch(text);
  if (match == null) {
    throw const FormatException('Invalid DER GeneralizedTime');
  }
  final base = match.group(1)!;
  final fraction = match.group(2);
  final micros = fraction == null
      ? 0
      : int.parse('${fraction}000000'.substring(0, 6));
  return _checkedDateTime(
    int.parse(base.substring(0, 4)),
    base.substring(4),
    microsecond: micros,
  );
}

DateTime _checkedDateTime(int year, String tail, {int microsecond = 0}) {
  final month = int.parse(tail.substring(0, 2));
  final day = int.parse(tail.substring(2, 4));
  final hour = int.parse(tail.substring(4, 6));
  final minute = int.parse(tail.substring(6, 8));
  final second = int.parse(tail.substring(8, 10));
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
  var inComponent = false;
  for (final byte in bytes) {
    if (!inComponent && byte == 0x80) {
      throw const FormatException('Non-minimal OBJECT IDENTIFIER');
    }
    value = (value << 7) | BigInt.from(byte & 0x7f);
    inComponent = byte & 0x80 != 0;
    if (!inComponent) {
      values.add(value);
      value = BigInt.zero;
    }
  }
  if (inComponent || values.isEmpty) {
    throw const FormatException('Truncated OBJECT IDENTIFIER');
  }
  final first = values.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? 0
      : first < BigInt.from(80)
      ? 1
      : 2;
  final secondArc = first - BigInt.from(firstArc * 40);
  return [BigInt.from(firstArc), secondArc, ...values].join('.');
}

List<int> _algorithmIdentifier(String oid) =>
    _sequence([..._oid(oid), ..._tlv(0x05, const [])]);

List<int> _sequence(List<int> content) => _tlv(0x30, content);
List<int> _octetString(List<int> content) => _tlv(0x04, content);

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
  final encoded = <int>[];
  void append(BigInt value) {
    final component = <int>[(value & BigInt.from(0x7f)).toInt()];
    value >>= 7;
    while (value != BigInt.zero) {
      component.insert(0, (value & BigInt.from(0x7f)).toInt() | 0x80);
      value >>= 7;
    }
    encoded.addAll(component);
  }

  append(arcs[0] * BigInt.from(40) + arcs[1]);
  for (final arc in arcs.skip(2)) {
    if (arc < BigInt.zero) {
      throw ArgumentError.value(oid, 'oid', 'Invalid OBJECT IDENTIFIER');
    }
    append(arc);
  }
  return _tlv(0x06, encoded);
}

List<int> _tlv(int tag, List<int> content) {
  final length = content.length;
  if (length < 128) {
    return [tag, length, ...content];
  }
  final lengthBytes = <int>[];
  var remaining = length;
  while (remaining != 0) {
    lengthBytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return [tag, 0x80 | lengthBytes.length, ...lengthBytes, ...content];
}

void _validateBytes(List<int> bytes, String name, {bool allowEmpty = false}) {
  if (!allowEmpty && bytes.isEmpty) {
    throw ArgumentError.value(bytes, name, 'Must not be empty');
  }
  for (final byte in bytes) {
    if (byte < 0 || byte > 255) {
      throw ArgumentError.value(bytes, name, 'Contains a non-byte value');
    }
  }
}

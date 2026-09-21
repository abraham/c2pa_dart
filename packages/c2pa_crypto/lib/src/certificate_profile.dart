import 'signing_algorithm.dart';
import 'x509_certificate.dart';

/// Extended Key Usage OIDs relevant to certificate profiles.
abstract final class ExtendedKeyUsageOids {
  static const any = '2.5.29.37.0';
  static const codeSigning = '1.3.6.1.5.5.7.3.3';
  static const emailProtection = '1.3.6.1.5.5.7.3.4';
  static const timeStamping = '1.3.6.1.5.5.7.3.8';
  static const ocspSigning = '1.3.6.1.5.5.7.3.9';
  static const documentSigning = '1.3.6.1.5.5.7.3.36';
}

/// Validates an RFC 6960 delegated OCSP responder certificate.
List<CertificateProfileIssue> validateOcspResponderCertificate(
  X509Certificate certificate, {
  required SigningAlgorithm algorithm,
  DateTime? atTime,
}) {
  final issues = _validateCommon(
    certificate,
    algorithm: algorithm,
    atTime: atTime,
  );
  final eku = certificate.extendedKeyUsage;
  if (eku == null || !eku.contains(ExtendedKeyUsageOids.ocspSigning)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.missingExtendedKeyUsage,
        'A delegated OCSP responder requires the id-kp-OCSPSigning EKU',
      ),
    );
  } else if (eku.any((oid) => oid != ExtendedKeyUsageOids.ocspSigning)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.disallowedExtendedKeyUsage,
        'A delegated OCSP responder must contain only id-kp-OCSPSigning',
      ),
    );
  }
  return List.unmodifiable(issues);
}

/// A machine-readable certificate profile problem.
enum CertificateProfileIssueCode {
  notYetValid,
  expired,
  caCertificate,
  missingBasicConstraints,
  missingKeyUsage,
  missingDigitalSignature,
  missingExtendedKeyUsage,
  disallowedExtendedKeyUsage,
  extendedKeyUsageNotCritical,
  keyAlgorithmMismatch,
  unsupportedCriticalExtension,
}

/// One validation issue found in a certificate profile.
final class CertificateProfileIssue {
  const CertificateProfileIssue(this.code, this.message);

  final CertificateProfileIssueCode code;
  final String message;
}

/// Validates C2PA signer certificate leaf-profile requirements.
///
/// Mirrors `check_certificate_profile` and `CertificateTrustPolicy::
/// has_allowed_eku` in c2pa-rs v0.90.22. The EKU extension only has to carry
/// *one* recognised purpose; unrecognised OIDs alongside it are ignored rather
/// than rejected, which is what lets real-world signers such as Adobe's carry
/// vendor OIDs next to `id-kp-emailProtection`.
List<CertificateProfileIssue> validateC2paSignerCertificate(
  X509Certificate certificate, {
  required SigningAlgorithm algorithm,
  DateTime? atTime,
  Set<String> allowedExtendedKeyUsageOids = const {
    ExtendedKeyUsageOids.codeSigning,
    ExtendedKeyUsageOids.emailProtection,
    ExtendedKeyUsageOids.documentSigning,
  },
}) {
  final issues = _validateCommon(
    certificate,
    algorithm: algorithm,
    atTime: atTime,
  );
  final eku = certificate.extendedKeyUsage;
  if (eku == null || eku.isEmpty) {
    // c2pa-rs treats an absent EKU extension as acceptable for a CA
    // certificate (`None => tbscert.is_ca()`), and only as a profile failure
    // for an end-entity signer.
    if (certificate.basicConstraints?.isCa != true) {
      issues.add(
        const CertificateProfileIssue(
          CertificateProfileIssueCode.missingExtendedKeyUsage,
          'A C2PA signer certificate requires an ExtendedKeyUsage extension',
        ),
      );
    }
  } else if (eku.contains(ExtendedKeyUsageOids.any)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.disallowedExtendedKeyUsage,
        'A C2PA signer certificate must not assert the anyExtendedKeyUsage EKU',
      ),
    );
  } else {
    // `id-kp-OCSPSigning` and `id-kp-timeStamping` identify OCSP responders
    // and time-stamping authorities, which this SDK validates through
    // [validateOcspResponderCertificate] and [validateTsaCertificate]. A claim
    // signer must not assert either purpose.
    //
    // This is deliberately stricter than c2pa-rs, whose `has_allowed_eku`
    // accepts a signer whose only purpose is time-stamping or OCSP signing.
    // Rejecting a cross-purpose credential can only reject a certificate the
    // C2PA specification already disallows, whereas matching upstream here
    // would admit one. A caller that deliberately lists one of these OIDs in
    // [allowedExtendedKeyUsageOids] opts back into the upstream behaviour.
    final crossPurpose = eku
        .where(
          (oid) =>
              !allowedExtendedKeyUsageOids.contains(oid) &&
              (oid == ExtendedKeyUsageOids.ocspSigning ||
                  oid == ExtendedKeyUsageOids.timeStamping),
        )
        .toList();
    if (crossPurpose.isNotEmpty) {
      issues.add(
        CertificateProfileIssue(
          CertificateProfileIssueCode.disallowedExtendedKeyUsage,
          'Disallowed signer EKU values: ${crossPurpose.join(', ')}',
        ),
      );
    } else if (!eku.any(allowedExtendedKeyUsageOids.contains)) {
      issues.add(
        CertificateProfileIssue(
          CertificateProfileIssueCode.missingExtendedKeyUsage,
          'No recognised signer EKU among: ${eku.join(', ')}',
        ),
      );
    }
  }
  return List.unmodifiable(issues);
}

/// Validates RFC 3161 TSA certificate leaf-profile requirements.
List<CertificateProfileIssue> validateTsaCertificate(
  X509Certificate certificate, {
  required SigningAlgorithm algorithm,
  DateTime? atTime,
}) {
  final issues = _validateCommon(
    certificate,
    algorithm: algorithm,
    atTime: atTime,
  );
  final eku = certificate.extendedKeyUsage;
  if (eku == null || eku.isEmpty) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.missingExtendedKeyUsage,
        'A TSA certificate requires the timeStamping EKU',
      ),
    );
  } else if (eku.length != 1 ||
      eku.single != ExtendedKeyUsageOids.timeStamping) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.disallowedExtendedKeyUsage,
        'A TSA certificate must contain only the timeStamping EKU',
      ),
    );
  }
  final ekuExtension = certificate.extensions
      .where((extension) => extension.oid == '2.5.29.37')
      .firstOrNull;
  if (ekuExtension != null && !ekuExtension.critical) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.extendedKeyUsageNotCritical,
        'A TSA ExtendedKeyUsage extension must be critical',
      ),
    );
  }
  return List.unmodifiable(issues);
}

List<CertificateProfileIssue> _validateCommon(
  X509Certificate certificate, {
  required SigningAlgorithm algorithm,
  DateTime? atTime,
}) {
  final issues = <CertificateProfileIssue>[];
  final time = (atTime ?? DateTime.now()).toUtc();
  if (time.isBefore(certificate.notBefore)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.notYetValid,
        'Certificate is not yet valid',
      ),
    );
  }
  if (time.isAfter(certificate.notAfter)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.expired,
        'Certificate has expired',
      ),
    );
  }
  final constraints = certificate.basicConstraints;
  if (constraints == null) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.missingBasicConstraints,
        'End-entity certificates require BasicConstraints',
      ),
    );
  } else if (constraints.isCa) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.caCertificate,
        'A signer or TSA certificate must be an end-entity certificate',
      ),
    );
  }
  final keyUsage = certificate.keyUsage;
  if (keyUsage == null) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.missingKeyUsage,
        'Certificate requires a KeyUsage extension',
      ),
    );
  } else if (!keyUsage.contains(X509KeyUsage.digitalSignature)) {
    issues.add(
      const CertificateProfileIssue(
        CertificateProfileIssueCode.missingDigitalSignature,
        'KeyUsage must permit digitalSignature',
      ),
    );
  }
  if (!_keyMatchesAlgorithm(certificate.subjectPublicKeyAlgorithm, algorithm)) {
    issues.add(
      CertificateProfileIssue(
        CertificateProfileIssueCode.keyAlgorithmMismatch,
        'Subject public key is incompatible with ${algorithm.name}',
      ),
    );
  }
  for (final extension in certificate.criticalUnknownExtensions) {
    issues.add(
      CertificateProfileIssue(
        CertificateProfileIssueCode.unsupportedCriticalExtension,
        'Unsupported critical extension: ${extension.oid}',
      ),
    );
  }
  return issues;
}

bool _keyMatchesAlgorithm(
  X509AlgorithmIdentifier keyAlgorithm,
  SigningAlgorithm algorithm,
) {
  switch (algorithm) {
    case SigningAlgorithm.es256:
      return keyAlgorithm.oid == '1.2.840.10045.2.1' &&
          _parametersOid(keyAlgorithm) == '1.2.840.10045.3.1.7';
    case SigningAlgorithm.es384:
      return keyAlgorithm.oid == '1.2.840.10045.2.1' &&
          _parametersOid(keyAlgorithm) == '1.3.132.0.34';
    case SigningAlgorithm.es512:
      return keyAlgorithm.oid == '1.2.840.10045.2.1' &&
          _parametersOid(keyAlgorithm) == '1.3.132.0.35';
    case SigningAlgorithm.ps256:
    case SigningAlgorithm.ps384:
    case SigningAlgorithm.ps512:
      return _rsaKeyMatches(keyAlgorithm, algorithm);
    case SigningAlgorithm.ed25519:
      return keyAlgorithm.oid == '1.3.101.112' &&
          keyAlgorithm.parametersDer == null;
  }
}

bool _rsaKeyMatches(
  X509AlgorithmIdentifier keyAlgorithm,
  SigningAlgorithm algorithm,
) {
  if (keyAlgorithm.oid == '1.2.840.113549.1.1.1') {
    final parameters = keyAlgorithm.parametersDer;
    return parameters == null ||
        (parameters.length == 2 && parameters[0] == 0x05 && parameters[1] == 0);
  }
  if (keyAlgorithm.oid != '1.2.840.113549.1.1.10') {
    return false;
  }
  final expectedHash = switch (algorithm) {
    SigningAlgorithm.ps256 => '2.16.840.1.101.3.4.2.1',
    SigningAlgorithm.ps384 => '2.16.840.1.101.3.4.2.2',
    SigningAlgorithm.ps512 => '2.16.840.1.101.3.4.2.3',
    _ => throw StateError('Not an RSA-PSS algorithm'),
  };
  final expectedSaltLength = algorithm.hashAlgorithm!.digestLength;
  final parameters = _parsePssParameters(keyAlgorithm.parametersDer);
  return parameters != null &&
      parameters.hashOid == expectedHash &&
      parameters.mgfHashOid == expectedHash &&
      parameters.saltLength == expectedSaltLength &&
      parameters.trailerField == 1;
}

({String hashOid, String mgfHashOid, int saltLength, int trailerField})?
_parsePssParameters(List<int>? der) {
  if (der == null) {
    return null;
  }
  try {
    final root = _ProfileDerReader(der).single(0x30);
    final reader = _ProfileDerReader(root);
    var hashOid = '1.3.14.3.2.26';
    var mgfHashOid = '1.3.14.3.2.26';
    var saltLength = 20;
    var trailerField = 1;
    var lastTag = -1;
    while (!reader.isAtEnd) {
      final field = reader.read();
      if (field.tag < 0xa0 || field.tag > 0xa3 || field.tag <= lastTag) {
        return null;
      }
      lastTag = field.tag;
      switch (field.tag) {
        case 0xa0:
          hashOid = _parseProfileAlgorithm(field.content).$1;
        case 0xa1:
          final maskAlgorithm = _parseProfileAlgorithm(field.content);
          if (maskAlgorithm.$1 != '1.2.840.113549.1.1.8' ||
              maskAlgorithm.$2 == null) {
            return null;
          }
          mgfHashOid = _parseProfileAlgorithm(maskAlgorithm.$2!).$1;
        case 0xa2:
          saltLength = _parseProfileInteger(field.content);
        case 0xa3:
          trailerField = _parseProfileInteger(field.content);
      }
    }
    return (
      hashOid: hashOid,
      mgfHashOid: mgfHashOid,
      saltLength: saltLength,
      trailerField: trailerField,
    );
  } on FormatException {
    return null;
  }
}

(String, List<int>?) _parseProfileAlgorithm(List<int> der) {
  final sequence = _ProfileDerReader(der).single(0x30);
  final reader = _ProfileDerReader(sequence);
  final oid = _profileOid(reader.read(0x06).content);
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  if (!reader.isAtEnd) {
    throw const FormatException('Invalid AlgorithmIdentifier');
  }
  return (oid, parameters);
}

int _parseProfileInteger(List<int> der) {
  final bytes = _ProfileDerReader(der).single(0x02);
  if (bytes.isEmpty ||
      bytes.first & 0x80 != 0 ||
      (bytes.length > 1 && bytes.first == 0 && bytes[1] & 0x80 == 0)) {
    throw const FormatException('Invalid INTEGER');
  }
  var value = 0;
  for (final byte in bytes) {
    value = value << 8 | byte;
  }
  return value;
}

String? _parametersOid(X509AlgorithmIdentifier algorithm) {
  final der = algorithm.parametersDer;
  if (der == null || der.length < 3 || der.first != 0x06) {
    return null;
  }
  final length = der[1];
  if (length >= 0x80 || length != der.length - 2 || length == 0) {
    return null;
  }
  final bytes = der.sublist(2);
  final values = <BigInt>[];
  var current = BigInt.zero;
  var start = true;
  for (final byte in bytes) {
    if (start && byte == 0x80) {
      return null;
    }
    current = current << 7 | BigInt.from(byte & 0x7f);
    start = false;
    if (byte & 0x80 == 0) {
      values.add(current);
      current = BigInt.zero;
      start = true;
    }
  }
  if (!start || values.isEmpty) {
    return null;
  }
  final first = values.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? BigInt.zero
      : first < BigInt.from(80)
      ? BigInt.one
      : BigInt.two;
  final secondArc = first - firstArc * BigInt.from(40);
  return [firstArc, secondArc, ...values].join('.');
}

String _profileOid(List<int> bytes) {
  if (bytes.isEmpty) {
    throw const FormatException('Invalid OID');
  }
  final values = <BigInt>[];
  var current = BigInt.zero;
  var start = true;
  for (final byte in bytes) {
    if (start && byte == 0x80) {
      throw const FormatException('Invalid OID');
    }
    current = current << 7 | BigInt.from(byte & 0x7f);
    start = false;
    if (byte & 0x80 == 0) {
      values.add(current);
      current = BigInt.zero;
      start = true;
    }
  }
  if (!start || values.isEmpty) {
    throw const FormatException('Invalid OID');
  }
  final first = values.removeAt(0);
  final firstArc = first < BigInt.from(40)
      ? BigInt.zero
      : first < BigInt.from(80)
      ? BigInt.one
      : BigInt.two;
  final secondArc = first - firstArc * BigInt.from(40);
  return [firstArc, secondArc, ...values].join('.');
}

final class _ProfileDerValue {
  const _ProfileDerValue(this.tag, this.content, this.encoded);

  final int tag;
  final List<int> content;
  final List<int> encoded;
}

final class _ProfileDerReader {
  _ProfileDerReader(this.bytes);

  final List<int> bytes;
  int offset = 0;

  bool get isAtEnd => offset == bytes.length;

  _ProfileDerValue read([int? expectedTag]) {
    final start = offset;
    if (offset >= bytes.length) {
      throw const FormatException('Truncated DER');
    }
    final tag = bytes[offset++];
    if (tag & 0x1f == 0x1f || (expectedTag != null && tag != expectedTag)) {
      throw const FormatException('Invalid DER tag');
    }
    if (offset >= bytes.length) {
      throw const FormatException('Truncated DER');
    }
    final firstLength = bytes[offset++];
    int length;
    if (firstLength < 0x80) {
      length = firstLength;
    } else {
      final count = firstLength & 0x7f;
      if (count == 0 ||
          count > 4 ||
          count > bytes.length - offset ||
          bytes[offset] == 0) {
        throw const FormatException('Invalid DER length');
      }
      length = 0;
      for (var index = 0; index < count; index++) {
        length = length << 8 | bytes[offset++];
      }
      if (length < 0x80) {
        throw const FormatException('Non-minimal DER length');
      }
    }
    if (length > bytes.length - offset) {
      throw const FormatException('Truncated DER value');
    }
    final contentStart = offset;
    offset += length;
    return _ProfileDerValue(
      tag,
      bytes.sublist(contentStart, offset),
      bytes.sublist(start, offset),
    );
  }

  List<int> single(int tag) {
    final value = read(tag);
    if (!isAtEnd) {
      throw const FormatException('Trailing DER data');
    }
    return value.content;
  }
}

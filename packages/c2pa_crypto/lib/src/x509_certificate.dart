import 'dart:convert';
import 'dart:typed_data';

/// A parsed X.509 algorithm identifier.
final class X509AlgorithmIdentifier {
  X509AlgorithmIdentifier(this.oid, List<int>? parametersDer)
    : _parametersDer = parametersDer == null
          ? null
          : Uint8List.fromList(parametersDer);

  final String oid;
  final Uint8List? _parametersDer;

  Uint8List? get parametersDer =>
      _parametersDer == null ? null : Uint8List.fromList(_parametersDer);
}

/// One attribute in an X.509 distinguished name.
final class X509NameAttribute {
  const X509NameAttribute(this.oid, this.value);

  final String oid;
  final String value;
}

/// A parsed X.509 distinguished name, retaining its exact DER.
final class X509DistinguishedName {
  X509DistinguishedName(List<X509NameAttribute> attributes, List<int> der)
    : attributes = List.unmodifiable(attributes),
      _der = Uint8List.fromList(der);

  final List<X509NameAttribute> attributes;
  final Uint8List _der;

  Uint8List get der => Uint8List.fromList(_der);

  /// Strictly parses one DER Name value.
  factory X509DistinguishedName.parse(List<int> der) {
    _validateBytes(der);
    return _parseName(_single(der, 0x30));
  }
}

/// The BasicConstraints extension.
final class X509BasicConstraints {
  const X509BasicConstraints({required this.isCa, this.pathLength});

  final bool isCa;
  final int? pathLength;
}

enum X509GeneralNameType { dns, ipAddress, email, uri }

/// One supported GeneralName value.
final class X509GeneralName {
  X509GeneralName(this.type, {this.text, List<int>? bytes})
    : _bytes = bytes == null ? null : Uint8List.fromList(bytes);

  final X509GeneralNameType type;
  final String? text;
  final Uint8List? _bytes;

  Uint8List? get bytes => _bytes == null ? null : Uint8List.fromList(_bytes);
}

/// One supported GeneralSubtree base from NameConstraints.
final class X509NameConstraint {
  X509NameConstraint(
    this.type, {
    this.text,
    List<int>? address,
    List<int>? mask,
  }) : _address = address == null ? null : Uint8List.fromList(address),
       _mask = mask == null ? null : Uint8List.fromList(mask);

  final X509GeneralNameType type;
  final String? text;
  final Uint8List? _address;
  final Uint8List? _mask;

  Uint8List? get address =>
      _address == null ? null : Uint8List.fromList(_address);
  Uint8List? get mask => _mask == null ? null : Uint8List.fromList(_mask);
}

/// Parsed NameConstraints subtrees supported by this package.
final class X509NameConstraints {
  X509NameConstraints({
    required Iterable<X509NameConstraint> permitted,
    required Iterable<X509NameConstraint> excluded,
  }) : permitted = List.unmodifiable(permitted),
       excluded = List.unmodifiable(excluded);

  final List<X509NameConstraint> permitted;
  final List<X509NameConstraint> excluded;
}

final class X509PolicyMapping {
  const X509PolicyMapping(this.issuerDomainPolicy, this.subjectDomainPolicy);

  final String issuerDomainPolicy;
  final String subjectDomainPolicy;
}

final class X509PolicyConstraints {
  const X509PolicyConstraints({
    this.requireExplicitPolicy,
    this.inhibitPolicyMapping,
  });

  final int? requireExplicitPolicy;
  final int? inhibitPolicyMapping;
}

/// KeyUsage bits defined by RFC 5280.
enum X509KeyUsage {
  digitalSignature,
  contentCommitment,
  keyEncipherment,
  dataEncipherment,
  keyAgreement,
  keyCertSign,
  crlSign,
  encipherOnly,
  decipherOnly,
}

/// A parsed X.509 extension.
final class X509Extension {
  X509Extension({
    required this.oid,
    required this.critical,
    required List<int> value,
  }) : _value = Uint8List.fromList(value);

  final String oid;
  final bool critical;
  final Uint8List _value;

  Uint8List get value => Uint8List.fromList(_value);
}

/// Strictly parsed fields needed for C2PA certificate processing.
final class X509Certificate {
  X509Certificate._({
    required List<int> der,
    required List<int> tbsCertificateDer,
    required this.serialNumber,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required List<int> subjectPublicKeyInfoDer,
    required this.subjectPublicKeyAlgorithm,
    required List<int> subjectPublicKey,
    required this.signatureAlgorithm,
    required List<int> signature,
    required this.basicConstraints,
    required this.keyUsage,
    required this.extendedKeyUsage,
    required List<int>? subjectKeyIdentifier,
    required List<int>? authorityKeyIdentifier,
    required this.ocspUrls,
    required this.subjectAlternativeNames,
    required this.nameConstraints,
    required this.certificatePolicies,
    required this.policyMappings,
    required this.policyConstraints,
    required this.inhibitAnyPolicy,
    required this.extensions,
    required this.criticalUnknownExtensions,
  }) : _der = Uint8List.fromList(der),
       _tbsCertificateDer = Uint8List.fromList(tbsCertificateDer),
       _subjectPublicKeyInfoDer = Uint8List.fromList(subjectPublicKeyInfoDer),
       _subjectPublicKey = Uint8List.fromList(subjectPublicKey),
       _signature = Uint8List.fromList(signature),
       _subjectKeyIdentifier = subjectKeyIdentifier == null
           ? null
           : Uint8List.fromList(subjectKeyIdentifier),
       _authorityKeyIdentifier = authorityKeyIdentifier == null
           ? null
           : Uint8List.fromList(authorityKeyIdentifier);

  final Uint8List _der;
  final Uint8List _tbsCertificateDer;
  final BigInt serialNumber;
  final X509DistinguishedName issuer;
  final X509DistinguishedName subject;
  final DateTime notBefore;
  final DateTime notAfter;
  final Uint8List _subjectPublicKeyInfoDer;
  final X509AlgorithmIdentifier subjectPublicKeyAlgorithm;
  final Uint8List _subjectPublicKey;
  final X509AlgorithmIdentifier signatureAlgorithm;
  final Uint8List _signature;
  final X509BasicConstraints? basicConstraints;
  final Set<X509KeyUsage>? keyUsage;
  final List<String>? extendedKeyUsage;
  final Uint8List? _subjectKeyIdentifier;
  final Uint8List? _authorityKeyIdentifier;
  final List<Uri> ocspUrls;
  final List<X509GeneralName> subjectAlternativeNames;
  final X509NameConstraints? nameConstraints;
  final List<String>? certificatePolicies;
  final List<X509PolicyMapping>? policyMappings;
  final X509PolicyConstraints? policyConstraints;
  final int? inhibitAnyPolicy;
  final List<X509Extension> extensions;
  final List<X509Extension> criticalUnknownExtensions;

  Uint8List get der => Uint8List.fromList(_der);
  Uint8List get tbsCertificateDer => Uint8List.fromList(_tbsCertificateDer);
  Uint8List get subjectPublicKeyInfoDer =>
      Uint8List.fromList(_subjectPublicKeyInfoDer);
  Uint8List get subjectPublicKey => Uint8List.fromList(_subjectPublicKey);
  Uint8List get signature => Uint8List.fromList(_signature);
  Uint8List? get subjectKeyIdentifier => _subjectKeyIdentifier == null
      ? null
      : Uint8List.fromList(_subjectKeyIdentifier);
  Uint8List? get authorityKeyIdentifier => _authorityKeyIdentifier == null
      ? null
      : Uint8List.fromList(_authorityKeyIdentifier);

  /// Parses one DER-encoded X.509 certificate.
  ///
  /// Unknown critical extensions are rejected unless
  /// [allowUnknownCriticalExtensions] is true.
  factory X509Certificate.parse(
    List<int> input, {
    bool allowUnknownCriticalExtensions = false,
  }) {
    _validateBytes(input);
    final der = Uint8List.fromList(input);
    final rootReader = _DerReader(der);
    final certificate = rootReader.read(0x30);
    rootReader.requireEnd();
    final certificateReader = certificate.reader();

    final tbs = certificateReader.read(0x30);
    final outerSignatureAlgorithm = _parseAlgorithmIdentifier(
      certificateReader.read(0x30),
    );
    final signature = _parseBitString(certificateReader.read(0x03));
    if (signature.unusedBits != 0 || signature.bytes.isEmpty) {
      throw const FormatException(
        'Certificate signature must be non-empty and byte-aligned',
      );
    }
    certificateReader.requireEnd();

    final parsedTbs = _parseTbs(tbs);
    if (!_sameAlgorithm(
      parsedTbs.signatureAlgorithm,
      outerSignatureAlgorithm,
    )) {
      throw const FormatException(
        'TBSCertificate and certificate signature algorithms differ',
      );
    }
    final unknownCritical = parsedTbs.extensions
        .where(
          (extension) =>
              extension.critical &&
              !supportedX509CriticalExtensionOids.contains(extension.oid),
        )
        .toList(growable: false);
    if (!allowUnknownCriticalExtensions && unknownCritical.isNotEmpty) {
      throw FormatException(
        'Unsupported critical extension: ${unknownCritical.first.oid}',
      );
    }

    return X509Certificate._(
      der: der,
      tbsCertificateDer: tbs.encoded,
      serialNumber: parsedTbs.serialNumber,
      issuer: parsedTbs.issuer,
      subject: parsedTbs.subject,
      notBefore: parsedTbs.notBefore,
      notAfter: parsedTbs.notAfter,
      subjectPublicKeyInfoDer: parsedTbs.subjectPublicKeyInfoDer,
      subjectPublicKeyAlgorithm: parsedTbs.subjectPublicKeyAlgorithm,
      subjectPublicKey: parsedTbs.subjectPublicKey,
      signatureAlgorithm: outerSignatureAlgorithm,
      signature: signature.bytes,
      basicConstraints: parsedTbs.basicConstraints,
      keyUsage: parsedTbs.keyUsage,
      extendedKeyUsage: parsedTbs.extendedKeyUsage,
      subjectKeyIdentifier: parsedTbs.subjectKeyIdentifier,
      authorityKeyIdentifier: parsedTbs.authorityKeyIdentifier,
      ocspUrls: parsedTbs.ocspUrls,
      subjectAlternativeNames: parsedTbs.subjectAlternativeNames,
      nameConstraints: parsedTbs.nameConstraints,
      certificatePolicies: parsedTbs.certificatePolicies,
      policyMappings: parsedTbs.policyMappings,
      policyConstraints: parsedTbs.policyConstraints,
      inhibitAnyPolicy: parsedTbs.inhibitAnyPolicy,
      extensions: parsedTbs.extensions,
      criticalUnknownExtensions: unknownCritical,
    );
  }
}

const _basicConstraintsOid = '2.5.29.19';
const _keyUsageOid = '2.5.29.15';
const _extendedKeyUsageOid = '2.5.29.37';
const _subjectKeyIdentifierOid = '2.5.29.14';
const _authorityKeyIdentifierOid = '2.5.29.35';
const _authorityInformationAccessOid = '1.3.6.1.5.5.7.1.1';
const _ocspAccessMethodOid = '1.3.6.1.5.5.7.48.1';
const _subjectAlternativeNameOid = '2.5.29.17';
const _nameConstraintsOid = '2.5.29.30';
const _certificatePoliciesOid = '2.5.29.32';
const _policyMappingsOid = '2.5.29.33';
const _policyConstraintsOid = '2.5.29.36';
const _inhibitAnyPolicyOid = '2.5.29.54';
const _anyPolicyOid = '2.5.29.32.0';

/// Critical X.509 extensions understood and enforced by this package.
const supportedX509CriticalExtensionOids = <String>{
  _basicConstraintsOid,
  _keyUsageOid,
  _extendedKeyUsageOid,
  _subjectKeyIdentifierOid,
  _authorityKeyIdentifierOid,
  _authorityInformationAccessOid,
  _subjectAlternativeNameOid,
  _nameConstraintsOid,
  _certificatePoliciesOid,
  _policyMappingsOid,
  _policyConstraintsOid,
  _inhibitAnyPolicyOid,
};

_ParsedTbs _parseTbs(_DerValue tbs) {
  final reader = tbs.reader();
  var version = 0;
  if (reader.peekTag() == 0xa0) {
    final explicitVersion = reader.read(0xa0).reader();
    version = _parseSmallInteger(explicitVersion.read(0x02));
    explicitVersion.requireEnd();
    if (version <= 0 || version > 2) {
      throw const FormatException('Unsupported certificate version');
    }
  }
  final serial = _parsePositiveInteger(reader.read(0x02), maxBytes: 20);
  final tbsSignatureAlgorithm = _parseAlgorithmIdentifier(reader.read(0x30));
  final issuer = _parseName(reader.read(0x30));
  final validityReader = reader.read(0x30).reader();
  final notBefore = _parseTime(validityReader.read());
  final notAfter = _parseTime(validityReader.read());
  validityReader.requireEnd();
  if (notAfter.isBefore(notBefore)) {
    throw const FormatException('Certificate validity interval is reversed');
  }
  final subject = _parseName(reader.read(0x30));
  final spki = reader.read(0x30);
  final spkiReader = spki.reader();
  final spkiAlgorithm = _parseAlgorithmIdentifier(spkiReader.read(0x30));
  final publicKey = _parseBitString(spkiReader.read(0x03));
  if (publicKey.unusedBits != 0 || publicKey.bytes.isEmpty) {
    throw const FormatException(
      'Subject public key must be non-empty and byte-aligned',
    );
  }
  spkiReader.requireEnd();

  var sawIssuerUniqueId = false;
  var sawSubjectUniqueId = false;
  var sawExtensions = false;
  var extensions = <X509Extension>[];
  while (!reader.isAtEnd) {
    switch (reader.peekTag()) {
      case 0x81:
        if (sawIssuerUniqueId || sawSubjectUniqueId || sawExtensions) {
          throw const FormatException('Invalid issuerUniqueID field ordering');
        }
        _validateImplicitBitString(reader.read(0x81));
        sawIssuerUniqueId = true;
      case 0x82:
        if (sawSubjectUniqueId || sawExtensions) {
          throw const FormatException('Invalid subjectUniqueID field ordering');
        }
        _validateImplicitBitString(reader.read(0x82));
        sawSubjectUniqueId = true;
      case 0xa3:
        if (sawExtensions || version != 2) {
          throw const FormatException(
            'Extensions require a unique version 3 field',
          );
        }
        extensions = _parseExtensions(reader.read(0xa3));
        sawExtensions = true;
      default:
        throw const FormatException('Unexpected TBSCertificate field');
    }
  }

  X509BasicConstraints? basicConstraints;
  Set<X509KeyUsage>? keyUsage;
  List<String>? extendedKeyUsage;
  Uint8List? subjectKeyIdentifier;
  Uint8List? authorityKeyIdentifier;
  var ocspUrls = <Uri>[];
  var subjectAlternativeNames = <X509GeneralName>[];
  X509NameConstraints? nameConstraints;
  List<String>? certificatePolicies;
  List<X509PolicyMapping>? policyMappings;
  X509PolicyConstraints? policyConstraints;
  int? inhibitAnyPolicy;
  for (final extension in extensions) {
    switch (extension.oid) {
      case _basicConstraintsOid:
        basicConstraints = _parseBasicConstraints(extension.value);
      case _keyUsageOid:
        keyUsage = _parseKeyUsage(extension.value);
      case _extendedKeyUsageOid:
        extendedKeyUsage = _parseExtendedKeyUsage(extension.value);
      case _subjectKeyIdentifierOid:
        subjectKeyIdentifier = _parseSingleOctetString(extension.value);
      case _authorityKeyIdentifierOid:
        authorityKeyIdentifier = _parseAuthorityKeyIdentifier(extension.value);
      case _authorityInformationAccessOid:
        ocspUrls = _parseOcspUrls(extension.value);
      case _subjectAlternativeNameOid:
        subjectAlternativeNames = _parseGeneralNames(extension.value);
      case _nameConstraintsOid:
        if (!extension.critical) {
          throw const FormatException('NameConstraints must be critical');
        }
        nameConstraints = _parseNameConstraints(extension.value);
      case _certificatePoliciesOid:
        certificatePolicies = _parseCertificatePolicies(extension.value);
      case _policyMappingsOid:
        policyMappings = _parsePolicyMappings(extension.value);
      case _policyConstraintsOid:
        policyConstraints = _parsePolicyConstraints(extension.value);
      case _inhibitAnyPolicyOid:
        if (!extension.critical) {
          throw const FormatException('InhibitAnyPolicy must be critical');
        }
        inhibitAnyPolicy = _parseSkipCerts(extension.value);
    }
  }

  return _ParsedTbs(
    serialNumber: serial,
    signatureAlgorithm: tbsSignatureAlgorithm,
    issuer: issuer,
    subject: subject,
    notBefore: notBefore,
    notAfter: notAfter,
    subjectPublicKeyInfoDer: spki.encoded,
    subjectPublicKeyAlgorithm: spkiAlgorithm,
    subjectPublicKey: publicKey.bytes,
    extensions: extensions,
    basicConstraints: basicConstraints,
    keyUsage: keyUsage,
    extendedKeyUsage: extendedKeyUsage,
    subjectKeyIdentifier: subjectKeyIdentifier,
    authorityKeyIdentifier: authorityKeyIdentifier,
    ocspUrls: ocspUrls,
    subjectAlternativeNames: subjectAlternativeNames,
    nameConstraints: nameConstraints,
    certificatePolicies: certificatePolicies,
    policyMappings: policyMappings,
    policyConstraints: policyConstraints,
    inhibitAnyPolicy: inhibitAnyPolicy,
  );
}

X509AlgorithmIdentifier _parseAlgorithmIdentifier(_DerValue value) {
  final reader = value.reader();
  final oid = _parseOid(reader.read(0x06));
  final parameters = reader.isAtEnd ? null : reader.read().encoded;
  reader.requireEnd();
  return X509AlgorithmIdentifier(oid, parameters);
}

X509DistinguishedName _parseName(_DerValue value) {
  final attributes = <X509NameAttribute>[];
  final reader = value.reader();
  while (!reader.isAtEnd) {
    final set = reader.read(0x31);
    final setReader = set.reader();
    List<int>? previous;
    while (!setReader.isAtEnd) {
      final attributeValue = setReader.read(0x30);
      if (previous != null &&
          _compareBytes(previous, attributeValue.encoded) > 0) {
        throw const FormatException('RDN SET is not DER-sorted');
      }
      previous = attributeValue.encoded;
      final attributeReader = attributeValue.reader();
      final oid = _parseOid(attributeReader.read(0x06));
      final string = _parseDirectoryString(attributeReader.read());
      attributeReader.requireEnd();
      attributes.add(X509NameAttribute(oid, string));
    }
    if (previous == null) {
      throw const FormatException('RDN SET must not be empty');
    }
  }
  return X509DistinguishedName(attributes, value.encoded);
}

String _parseDirectoryString(_DerValue value) {
  switch (value.tag) {
    case 0x0c:
      try {
        return utf8.decode(value.content);
      } on FormatException {
        throw const FormatException('Invalid UTF8String');
      }
    case 0x13:
    case 0x16:
      if (value.content.any((byte) => byte > 0x7f)) {
        throw const FormatException('Invalid ASCII certificate string');
      }
      return ascii.decode(value.content);
    case 0x1e:
      if (value.content.length.isOdd) {
        throw const FormatException('Invalid BMPString length');
      }
      final units = <int>[];
      for (var index = 0; index < value.content.length; index += 2) {
        final unit = value.content[index] << 8 | value.content[index + 1];
        if (unit >= 0xd800 && unit <= 0xdfff) {
          throw const FormatException('Invalid BMPString surrogate');
        }
        units.add(unit);
      }
      return String.fromCharCodes(units);
    default:
      throw FormatException(
        'Unsupported distinguished-name string tag 0x'
        '${value.tag.toRadixString(16)}',
      );
  }
}

DateTime _parseTime(_DerValue value) {
  if (value.content.any((byte) => byte > 0x7f)) {
    throw const FormatException('Certificate time is not ASCII');
  }
  final text = ascii.decode(value.content);
  late int year;
  late int offset;
  if (value.tag == 0x17 && text.length == 13 && text.endsWith('Z')) {
    final shortYear = _digits(text, 0, 2);
    year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
    offset = 2;
  } else if (value.tag == 0x18 && text.length == 15 && text.endsWith('Z')) {
    year = _digits(text, 0, 4);
    if (year < 2050) {
      throw const FormatException(
        'GeneralizedTime is non-canonical before 2050',
      );
    }
    offset = 4;
  } else {
    throw const FormatException('Invalid DER certificate time');
  }
  final month = _digits(text, offset, offset + 2);
  final day = _digits(text, offset + 2, offset + 4);
  final hour = _digits(text, offset + 4, offset + 6);
  final minute = _digits(text, offset + 6, offset + 8);
  final second = _digits(text, offset + 8, offset + 10);
  final parsed = DateTime.utc(year, month, day, hour, minute, second);
  if (parsed.year != year ||
      parsed.month != month ||
      parsed.day != day ||
      parsed.hour != hour ||
      parsed.minute != minute ||
      parsed.second != second) {
    throw const FormatException('Invalid certificate time value');
  }
  return parsed;
}

int _digits(String value, int start, int end) {
  final part = value.substring(start, end);
  if (!RegExp(r'^[0-9]+$').hasMatch(part)) {
    throw const FormatException('Invalid certificate time digits');
  }
  return int.parse(part);
}

List<X509Extension> _parseExtensions(_DerValue explicit) {
  final explicitReader = explicit.reader();
  final sequence = explicitReader.read(0x30);
  explicitReader.requireEnd();
  final reader = sequence.reader();
  final extensions = <X509Extension>[];
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final extensionReader = reader.read(0x30).reader();
    final oid = _parseOid(extensionReader.read(0x06));
    if (!seen.add(oid)) {
      throw FormatException('Duplicate certificate extension: $oid');
    }
    var critical = false;
    if (extensionReader.peekTag() == 0x01) {
      critical = _parseBoolean(extensionReader.read(0x01));
      if (!critical) {
        throw const FormatException(
          'DER DEFAULT false must be omitted for extension criticality',
        );
      }
    }
    final value = extensionReader.read(0x04).content;
    extensionReader.requireEnd();
    extensions.add(X509Extension(oid: oid, critical: critical, value: value));
  }
  if (extensions.isEmpty) {
    throw const FormatException('Extensions sequence must not be empty');
  }
  return List.unmodifiable(extensions);
}

X509BasicConstraints _parseBasicConstraints(List<int> der) {
  final outer = _single(der, 0x30).reader();
  var isCa = false;
  int? pathLength;
  if (outer.peekTag() == 0x01) {
    isCa = _parseBoolean(outer.read(0x01));
    if (!isCa) {
      throw const FormatException('BasicConstraints default false is encoded');
    }
  }
  if (outer.peekTag() == 0x02) {
    pathLength = _parseSmallInteger(outer.read(0x02));
    if (!isCa) {
      throw const FormatException('pathLenConstraint requires CA=true');
    }
  }
  outer.requireEnd();
  return X509BasicConstraints(isCa: isCa, pathLength: pathLength);
}

Set<X509KeyUsage> _parseKeyUsage(List<int> der) {
  final bits = _parseBitString(_single(der, 0x03));
  if (bits.bytes.isEmpty) {
    throw const FormatException('KeyUsage must contain at least one bit');
  }
  final significantBits = bits.bytes.length * 8 - bits.unusedBits;
  if (significantBits > X509KeyUsage.values.length) {
    throw const FormatException('KeyUsage contains undefined bits');
  }
  if (bits.bytes.last == 0 || bits.bytes.last & (1 << bits.unusedBits) == 0) {
    throw const FormatException('KeyUsage BIT STRING is not minimal');
  }
  final usages = <X509KeyUsage>{};
  for (var index = 0; index < significantBits; index++) {
    if (bits.bytes[index ~/ 8] & (0x80 >> (index % 8)) != 0) {
      usages.add(X509KeyUsage.values[index]);
    }
  }
  return Set.unmodifiable(usages);
}

List<String> _parseExtendedKeyUsage(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final values = <String>[];
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final oid = _parseOid(reader.read(0x06));
    if (!seen.add(oid)) {
      throw FormatException('Duplicate ExtendedKeyUsage OID: $oid');
    }
    values.add(oid);
  }
  if (values.isEmpty) {
    throw const FormatException('ExtendedKeyUsage must not be empty');
  }
  return List.unmodifiable(values);
}

Uint8List _parseSingleOctetString(List<int> der) => _single(der, 0x04).content;

Uint8List? _parseAuthorityKeyIdentifier(List<int> der) {
  final reader = _single(der, 0x30).reader();
  Uint8List? keyIdentifier;
  var lastRank = -1;
  var fields = 0;
  while (!reader.isAtEnd) {
    final value = reader.read();
    final rank = switch (value.tag) {
      0x80 => 0,
      0xa1 => 1,
      0x82 => 2,
      _ => -1,
    };
    if (rank < 0 || rank <= lastRank) {
      throw const FormatException('Malformed AuthorityKeyIdentifier');
    }
    lastRank = rank;
    fields++;
    if (value.tag == 0x80) {
      if (value.content.isEmpty) {
        throw const FormatException('AKI keyIdentifier must not be empty');
      }
      keyIdentifier = value.content;
    } else if (value.tag == 0xa1) {
      final names = value.reader();
      if (names.isAtEnd) {
        throw const FormatException('AKI authorityCertIssuer is empty');
      }
      while (!names.isAtEnd) {
        names.read();
      }
    } else {
      _parsePositiveInteger(
        _DerValue(tag: 0x02, encoded: value.encoded, content: value.content),
      );
    }
  }
  if (fields == 0) {
    throw const FormatException('AuthorityKeyIdentifier must not be empty');
  }
  return keyIdentifier;
}

List<Uri> _parseOcspUrls(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final urls = <Uri>[];
  var descriptions = 0;
  while (!reader.isAtEnd) {
    descriptions++;
    final accessReader = reader.read(0x30).reader();
    final method = _parseOid(accessReader.read(0x06));
    final location = accessReader.read();
    accessReader.requireEnd();
    if (method == _ocspAccessMethodOid) {
      if (location.tag != 0x86 ||
          location.content.isEmpty ||
          location.content.any((byte) => byte > 0x7f)) {
        throw const FormatException('OCSP AIA location must be an IA5 URI');
      }
      final uri = Uri.tryParse(ascii.decode(location.content));
      if (uri == null || !uri.hasScheme) {
        throw const FormatException('Invalid OCSP URI');
      }
      urls.add(uri);
    }
  }
  if (descriptions == 0) {
    throw const FormatException('Malformed AuthorityInformationAccess');
  }
  return List.unmodifiable(urls);
}

List<X509GeneralName> _parseGeneralNames(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final names = <X509GeneralName>[];
  var count = 0;
  while (!reader.isAtEnd) {
    count++;
    final value = reader.read();
    switch (value.tag) {
      case 0x81:
        names.add(
          X509GeneralName(
            X509GeneralNameType.email,
            text: _parseEmailName(value.content),
          ),
        );
      case 0x82:
        names.add(
          X509GeneralName(
            X509GeneralNameType.dns,
            text: _parseDnsName(value.content, allowLeadingDot: false),
          ),
        );
      case 0x86:
        final text = _parseIa5(value.content, 'uniformResourceIdentifier');
        final uri = Uri.tryParse(text);
        if (uri == null || !uri.hasScheme || uri.host.isEmpty) {
          throw const FormatException('Invalid URI subjectAltName');
        }
        names.add(X509GeneralName(X509GeneralNameType.uri, text: text));
      case 0x87:
        if (value.content.length != 4 && value.content.length != 16) {
          throw const FormatException('Invalid IP address subjectAltName');
        }
        names.add(
          X509GeneralName(X509GeneralNameType.ipAddress, bytes: value.content),
        );
      default:
        throw FormatException(
          'Unsupported SubjectAlternativeName tag 0x'
          '${value.tag.toRadixString(16)}',
        );
    }
  }
  if (count == 0) {
    throw const FormatException('SubjectAlternativeName must not be empty');
  }
  return List.unmodifiable(names);
}

X509NameConstraints _parseNameConstraints(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final permitted = <X509NameConstraint>[];
  final excluded = <X509NameConstraint>[];
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final field = reader.read();
    if ((field.tag != 0xa0 && field.tag != 0xa1) || field.tag <= lastTag) {
      throw const FormatException('Malformed NameConstraints');
    }
    lastTag = field.tag;
    final destination = field.tag == 0xa0 ? permitted : excluded;
    final subtrees = field.reader();
    if (subtrees.isAtEnd) {
      throw const FormatException('GeneralSubtrees must not be empty');
    }
    while (!subtrees.isAtEnd) {
      destination.add(_parseGeneralSubtree(subtrees.read(0x30)));
    }
  }
  if (permitted.isEmpty && excluded.isEmpty) {
    throw const FormatException('NameConstraints must not be empty');
  }
  return X509NameConstraints(permitted: permitted, excluded: excluded);
}

X509NameConstraint _parseGeneralSubtree(_DerValue subtree) {
  final reader = subtree.reader();
  final base = reader.read();
  late X509NameConstraint constraint;
  switch (base.tag) {
    case 0x81:
      final email = _parseIa5(
        base.content,
        'rfc822Name constraint',
      ).toLowerCase();
      _validateEmailConstraint(email);
      constraint = X509NameConstraint(X509GeneralNameType.email, text: email);
    case 0x82:
      constraint = X509NameConstraint(
        X509GeneralNameType.dns,
        text: _parseDnsName(base.content, allowLeadingDot: true),
      );
    case 0x86:
      final host = _parseIa5(base.content, 'URI constraint').toLowerCase();
      _validateDomainConstraint(host);
      constraint = X509NameConstraint(X509GeneralNameType.uri, text: host);
    case 0x87:
      if (base.content.length != 8 && base.content.length != 32) {
        throw const FormatException(
          'IP name constraint must contain address and mask',
        );
      }
      final half = base.content.length ~/ 2;
      final address = base.content.sublist(0, half);
      final mask = base.content.sublist(half);
      _validateIpMask(mask);
      for (var index = 0; index < half; index++) {
        if (address[index] & ~mask[index] != 0) {
          throw const FormatException('IP name constraint has host bits set');
        }
      }
      constraint = X509NameConstraint(
        X509GeneralNameType.ipAddress,
        address: address,
        mask: mask,
      );
    default:
      throw FormatException(
        'Unsupported NameConstraints GeneralName tag 0x'
        '${base.tag.toRadixString(16)}',
      );
  }
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final distance = reader.read();
    if ((distance.tag != 0x80 && distance.tag != 0x81) ||
        distance.tag <= lastTag) {
      throw const FormatException('Malformed GeneralSubtree bounds');
    }
    lastTag = distance.tag;
    final value = _parseNonNegativeInteger(
      _DerValue(
        tag: 0x02,
        encoded: distance.encoded,
        content: distance.content,
      ),
    );
    if (distance.tag == 0x80 && value == BigInt.zero) {
      throw const FormatException(
        'GeneralSubtree minimum DEFAULT zero must be omitted',
      );
    }
    throw const FormatException(
      'Non-default GeneralSubtree bounds are unsupported',
    );
  }
  return constraint;
}

List<String> _parseCertificatePolicies(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final policies = <String>[];
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final information = reader.read(0x30).reader();
    final oid = _parseOid(information.read(0x06));
    if (!seen.add(oid)) {
      throw FormatException('Duplicate certificate policy: $oid');
    }
    policies.add(oid);
    if (!information.isAtEnd) {
      final qualifiers = information.read(0x30).reader();
      if (qualifiers.isAtEnd) {
        throw const FormatException('PolicyQualifiers must not be empty');
      }
      while (!qualifiers.isAtEnd) {
        final qualifier = qualifiers.read(0x30).reader();
        _parseOid(qualifier.read(0x06));
        qualifier.read();
        qualifier.requireEnd();
      }
    }
    information.requireEnd();
  }
  if (policies.isEmpty) {
    throw const FormatException('CertificatePolicies must not be empty');
  }
  return List.unmodifiable(policies);
}

List<X509PolicyMapping> _parsePolicyMappings(List<int> der) {
  final reader = _single(der, 0x30).reader();
  final mappings = <X509PolicyMapping>[];
  final seen = <String>{};
  while (!reader.isAtEnd) {
    final mapping = reader.read(0x30).reader();
    final issuer = _parseOid(mapping.read(0x06));
    final subject = _parseOid(mapping.read(0x06));
    mapping.requireEnd();
    if (issuer == _anyPolicyOid || subject == _anyPolicyOid) {
      throw const FormatException('anyPolicy must not appear in mappings');
    }
    if (!seen.add('$issuer>$subject')) {
      throw const FormatException('Duplicate certificate policy mapping');
    }
    mappings.add(X509PolicyMapping(issuer, subject));
  }
  if (mappings.isEmpty) {
    throw const FormatException('PolicyMappings must not be empty');
  }
  return List.unmodifiable(mappings);
}

X509PolicyConstraints _parsePolicyConstraints(List<int> der) {
  final reader = _single(der, 0x30).reader();
  int? requireExplicitPolicy;
  int? inhibitPolicyMapping;
  var lastTag = -1;
  while (!reader.isAtEnd) {
    final field = reader.read();
    if ((field.tag != 0x80 && field.tag != 0x81) || field.tag <= lastTag) {
      throw const FormatException('Malformed PolicyConstraints');
    }
    lastTag = field.tag;
    final value = _parseSmallInteger(
      _DerValue(tag: 0x02, encoded: field.encoded, content: field.content),
    );
    if (field.tag == 0x80) {
      requireExplicitPolicy = value;
    } else {
      inhibitPolicyMapping = value;
    }
  }
  if (requireExplicitPolicy == null && inhibitPolicyMapping == null) {
    throw const FormatException('PolicyConstraints must not be empty');
  }
  return X509PolicyConstraints(
    requireExplicitPolicy: requireExplicitPolicy,
    inhibitPolicyMapping: inhibitPolicyMapping,
  );
}

int _parseSkipCerts(List<int> der) => _parseSmallInteger(_single(der, 0x02));

String _parseIa5(List<int> bytes, String field) {
  if (bytes.isEmpty || bytes.any((byte) => byte > 0x7f || byte == 0)) {
    throw FormatException('$field must be non-empty IA5String data');
  }
  return ascii.decode(bytes);
}

String _parseDnsName(List<int> bytes, {required bool allowLeadingDot}) {
  final value = _parseIa5(bytes, 'dNSName').toLowerCase();
  if (value.startsWith('.') && !allowLeadingDot) {
    throw const FormatException('Subject dNSName must not start with a dot');
  }
  final domain = !allowLeadingDot && value.startsWith('*.')
      ? value.substring(2)
      : value;
  _validateDomainConstraint(domain);
  return value;
}

String _parseEmailName(List<int> bytes) {
  final value = _parseIa5(bytes, 'rfc822Name').toLowerCase();
  final separator = value.lastIndexOf('@');
  if (separator <= 0 || separator == value.length - 1) {
    throw const FormatException('Invalid rfc822Name');
  }
  _validateDomainConstraint(value.substring(separator + 1));
  return value;
}

void _validateEmailConstraint(String value) {
  final separator = value.lastIndexOf('@');
  if (separator >= 0) {
    if (separator == 0 || separator == value.length - 1) {
      throw const FormatException('Invalid rfc822Name constraint');
    }
    _validateDomainConstraint(value.substring(separator + 1));
  } else {
    _validateDomainConstraint(value);
  }
}

void _validateDomainConstraint(String value) {
  final domain = value.startsWith('.') ? value.substring(1) : value;
  if (domain.isEmpty ||
      domain.length > 253 ||
      domain.endsWith('.') ||
      domain
          .split('.')
          .any(
            (label) =>
                label.isEmpty ||
                label.length > 63 ||
                label.startsWith('-') ||
                label.endsWith('-') ||
                !RegExp(r'^[a-z0-9-]+$').hasMatch(label),
          )) {
    throw const FormatException('Invalid DNS name or domain constraint');
  }
}

void _validateIpMask(List<int> mask) {
  var sawZero = false;
  for (final byte in mask) {
    for (var bit = 7; bit >= 0; bit--) {
      final set = byte & (1 << bit) != 0;
      if (!set) {
        sawZero = true;
      } else if (sawZero) {
        throw const FormatException(
          'IP name constraint mask is not contiguous',
        );
      }
    }
  }
}

_DerValue _single(List<int> der, int tag) {
  _validateBytes(der);
  final reader = _DerReader(Uint8List.fromList(der));
  final value = reader.read(tag);
  reader.requireEnd();
  return value;
}

_BitString _parseBitString(_DerValue value) {
  if (value.content.isEmpty) {
    throw const FormatException('BIT STRING is missing unused-bit count');
  }
  final unusedBits = value.content.first;
  if (unusedBits > 7 ||
      (value.content.length == 1 && unusedBits != 0) ||
      (unusedBits != 0 && value.content.last & ((1 << unusedBits) - 1) != 0)) {
    throw const FormatException('Invalid DER BIT STRING');
  }
  return _BitString(value.content.sublist(1), unusedBits);
}

void _validateImplicitBitString(_DerValue value) {
  _parseBitString(
    _DerValue(tag: 0x03, encoded: value.encoded, content: value.content),
  );
}

bool _parseBoolean(_DerValue value) {
  if (value.content.length != 1 ||
      (value.content.first != 0 && value.content.first != 0xff)) {
    throw const FormatException('Invalid DER BOOLEAN');
  }
  return value.content.first == 0xff;
}

int _parseSmallInteger(_DerValue value) {
  final integer = _parseNonNegativeInteger(value);
  if (integer > BigInt.from(0x7fffffff)) {
    throw const FormatException('INTEGER is too large');
  }
  return integer.toInt();
}

BigInt _parsePositiveInteger(_DerValue value, {int? maxBytes}) {
  final integer = _parseNonNegativeInteger(value, maxBytes: maxBytes);
  if (integer == BigInt.zero) {
    throw const FormatException('INTEGER must be positive');
  }
  return integer;
}

BigInt _parseNonNegativeInteger(_DerValue value, {int? maxBytes}) {
  final bytes = value.content;
  if (bytes.isEmpty ||
      bytes.first & 0x80 != 0 ||
      (bytes.length > 1 && bytes.first == 0 && bytes[1] & 0x80 == 0)) {
    throw const FormatException('Invalid non-negative DER INTEGER');
  }
  final significantLength = bytes.length - (bytes.first == 0 ? 1 : 0);
  if (maxBytes != null && significantLength > maxBytes) {
    throw FormatException('INTEGER exceeds $maxBytes bytes');
  }
  var result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

String _parseOid(_DerValue value) {
  if (value.content.isEmpty) {
    throw const FormatException('OID must not be empty');
  }
  final subidentifiers = <BigInt>[];
  var current = BigInt.zero;
  var atStart = true;
  for (final byte in value.content) {
    if (atStart && byte == 0x80) {
      throw const FormatException('OID subidentifier is not minimal');
    }
    current = (current << 7) | BigInt.from(byte & 0x7f);
    atStart = false;
    if (byte & 0x80 == 0) {
      subidentifiers.add(current);
      current = BigInt.zero;
      atStart = true;
    }
  }
  if (!atStart || subidentifiers.isEmpty) {
    throw const FormatException('Truncated OID');
  }
  final first = subidentifiers.removeAt(0);
  late BigInt firstArc;
  late BigInt secondArc;
  if (first < BigInt.from(40)) {
    firstArc = BigInt.zero;
    secondArc = first;
  } else if (first < BigInt.from(80)) {
    firstArc = BigInt.one;
    secondArc = first - BigInt.from(40);
  } else {
    firstArc = BigInt.two;
    secondArc = first - BigInt.from(80);
  }
  return [firstArc, secondArc, ...subidentifiers].join('.');
}

bool _sameAlgorithm(
  X509AlgorithmIdentifier left,
  X509AlgorithmIdentifier right,
) =>
    left.oid == right.oid &&
    _equalNullableBytes(left.parametersDer, right.parametersDer);

bool _equalNullableBytes(List<int>? left, List<int>? right) {
  if (left == null || right == null) {
    return left == right;
  }
  return _compareBytes(left, right) == 0;
}

int _compareBytes(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final comparison = left[index].compareTo(right[index]);
    if (comparison != 0) {
      return comparison;
    }
  }
  return left.length.compareTo(right.length);
}

void _validateBytes(List<int> input) {
  if (input.isEmpty || input.any((byte) => byte < 0 || byte > 0xff)) {
    throw const FormatException('DER input must be non-empty bytes');
  }
}

final class _ParsedTbs {
  const _ParsedTbs({
    required this.serialNumber,
    required this.signatureAlgorithm,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.subjectPublicKeyInfoDer,
    required this.subjectPublicKeyAlgorithm,
    required this.subjectPublicKey,
    required this.extensions,
    required this.basicConstraints,
    required this.keyUsage,
    required this.extendedKeyUsage,
    required this.subjectKeyIdentifier,
    required this.authorityKeyIdentifier,
    required this.ocspUrls,
    required this.subjectAlternativeNames,
    required this.nameConstraints,
    required this.certificatePolicies,
    required this.policyMappings,
    required this.policyConstraints,
    required this.inhibitAnyPolicy,
  });

  final BigInt serialNumber;
  final X509AlgorithmIdentifier signatureAlgorithm;
  final X509DistinguishedName issuer;
  final X509DistinguishedName subject;
  final DateTime notBefore;
  final DateTime notAfter;
  final Uint8List subjectPublicKeyInfoDer;
  final X509AlgorithmIdentifier subjectPublicKeyAlgorithm;
  final Uint8List subjectPublicKey;
  final List<X509Extension> extensions;
  final X509BasicConstraints? basicConstraints;
  final Set<X509KeyUsage>? keyUsage;
  final List<String>? extendedKeyUsage;
  final Uint8List? subjectKeyIdentifier;
  final Uint8List? authorityKeyIdentifier;
  final List<Uri> ocspUrls;
  final List<X509GeneralName> subjectAlternativeNames;
  final X509NameConstraints? nameConstraints;
  final List<String>? certificatePolicies;
  final List<X509PolicyMapping>? policyMappings;
  final X509PolicyConstraints? policyConstraints;
  final int? inhibitAnyPolicy;
}

final class _BitString {
  const _BitString(this.bytes, this.unusedBits);

  final Uint8List bytes;
  final int unusedBits;
}

final class _DerValue {
  const _DerValue({
    required this.tag,
    required this.encoded,
    required this.content,
  });

  final int tag;
  final Uint8List encoded;
  final Uint8List content;

  _DerReader reader() => _DerReader(content);
}

final class _DerReader {
  _DerReader(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  bool get isAtEnd => offset == bytes.length;

  int? peekTag() => isAtEnd ? null : bytes[offset];

  _DerValue read([int? expectedTag]) {
    final start = offset;
    final tag = _readByte();
    if (tag & 0x1f == 0x1f) {
      throw const FormatException('High-tag-number DER is unsupported');
    }
    if (expectedTag != null && tag != expectedTag) {
      throw FormatException(
        'Expected DER tag 0x${expectedTag.toRadixString(16)}, '
        'found 0x${tag.toRadixString(16)}',
      );
    }
    final length = _readLength();
    if (length > bytes.length - offset) {
      throw const FormatException('DER value exceeds its container');
    }
    final contentStart = offset;
    offset += length;
    return _DerValue(
      tag: tag,
      encoded: Uint8List.fromList(bytes.sublist(start, offset)),
      content: Uint8List.fromList(bytes.sublist(contentStart, offset)),
    );
  }

  void requireEnd() {
    if (!isAtEnd) {
      throw const FormatException('Trailing DER data');
    }
  }

  int _readLength() {
    final first = _readByte();
    if (first < 0x80) {
      return first;
    }
    final count = first & 0x7f;
    if (count == 0) {
      throw const FormatException('Indefinite DER length is forbidden');
    }
    if (count > 4 || count > bytes.length - offset || bytes[offset] == 0) {
      throw const FormatException('Invalid DER length');
    }
    var length = 0;
    for (var index = 0; index < count; index++) {
      length = length << 8 | _readByte();
    }
    if (length < 0x80) {
      throw const FormatException('Non-minimal DER length');
    }
    return length;
  }

  int _readByte() {
    if (offset >= bytes.length) {
      throw const FormatException('Truncated DER');
    }
    return bytes[offset++];
  }
}

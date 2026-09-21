@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('strict X.509 parsing', () {
    for (final fixture in [
      (
        name: 'RSA',
        algorithm: SigningAlgorithm.ps256,
        spki: _algorithm('1.2.840.113549.1.1.1', parameters: _null()),
      ),
      (
        name: 'EC',
        algorithm: SigningAlgorithm.es256,
        spki: _algorithm(
          '1.2.840.10045.2.1',
          parameters: _oid('1.2.840.10045.3.1.7'),
        ),
      ),
      (
        name: 'Ed25519',
        algorithm: SigningAlgorithm.ed25519,
        spki: _algorithm('1.3.101.112'),
      ),
    ]) {
      test('parses generated ${fixture.name} DER fixture', () {
        final der = _certificate(spkiAlgorithm: fixture.spki);
        final certificate = X509Certificate.parse(der);

        expect(certificate.der, der);
        expect(certificate.tbsCertificateDer.first, 0x30);
        expect(certificate.serialNumber, BigInt.from(42));
        expect(certificate.issuer.attributes.single.value, 'Test Issuer');
        expect(certificate.subject.attributes.single.value, 'Test Subject');
        expect(certificate.notBefore, DateTime.utc(2025));
        expect(certificate.notAfter, DateTime.utc(2030));
        expect(certificate.subjectPublicKey, [1, 2, 3, 4]);
        expect(certificate.signatureAlgorithm.oid, '1.2.840.113549.1.1.11');
        expect(certificate.signature, [9, 8, 7]);
        expect(certificate.basicConstraints?.isCa, isFalse);
        expect(certificate.keyUsage, contains(X509KeyUsage.digitalSignature));
        expect(certificate.extendedKeyUsage, [
          ExtendedKeyUsageOids.documentSigning,
        ]);
        expect(certificate.subjectKeyIdentifier, [1, 2, 3]);
        expect(certificate.authorityKeyIdentifier, [4, 5, 6]);
        expect(certificate.ocspUrls.single.toString(), 'https://ocsp.test/');
        expect(
          certificate.extensions.any(
            (extension) => extension.oid == '1.2.3.4.5',
          ),
          isTrue,
        );
        expect(
          validateC2paSignerCertificate(
            certificate,
            algorithm: fixture.algorithm,
            atTime: DateTime.utc(2027),
          ),
          isEmpty,
        );
      });
    }

    test('rejects BER ambiguity, trailing data, and malformed lengths', () {
      final valid = _certificate();
      expect(() => X509Certificate.parse([...valid, 0]), throwsFormatException);
      expect(
        () => X509Certificate.parse([0x30, 0x80, ...valid.skip(2), 0, 0]),
        throwsFormatException,
      );
      expect(
        () => X509Certificate.parse([0x30, 0x81, 0x01, 0]),
        throwsFormatException,
      );
      expect(
        () => X509Certificate.parse([0x30, 0x82, 0, 1, 0]),
        throwsFormatException,
      );
    });

    test('rejects malformed OIDs, times, and extension values', () {
      expect(
        () => X509Certificate.parse(
          _certificate(signatureOid: _tlv(0x06, [0x80])),
        ),
        throwsFormatException,
      );
      expect(
        () => X509Certificate.parse(_certificate(notBefore: '251332000000Z')),
        throwsFormatException,
      );
      expect(
        () => X509Certificate.parse(
          _certificate(
            extraExtensions: [
              _extension(
                '2.5.29.19',
                value: _sequence([_boolean(true), _integer(0)]),
              ),
            ],
            includeBasicConstraints: false,
          ),
        ),
        returnsNormally,
      );
      expect(
        () => X509Certificate.parse(
          _certificate(
            extraExtensions: [
              _extension('2.5.29.19', value: [0x30, 0x80]),
            ],
            includeBasicConstraints: false,
          ),
        ),
        throwsFormatException,
      );
    });

    test('rejects duplicate extensions', () {
      expect(
        () => X509Certificate.parse(
          _certificate(
            extraExtensions: [
              _extension('2.5.29.14', value: _octet([9])),
            ],
          ),
        ),
        throwsFormatException,
      );
    });

    test('rejects mismatched inner and outer signature algorithms', () {
      final certificate = _certificate();
      final tbsStart = _headerLength(certificate);
      final tbsEnd = _encodedValueLength(certificate, tbsStart);
      final mismatched = _sequence([
        certificate.sublist(tbsStart, tbsEnd),
        _sequence([_oid('1.2.840.113549.1.1.12'), _null()]),
        _bitString([9, 8, 7]),
      ]);
      expect(() => X509Certificate.parse(mismatched), throwsFormatException);
    });

    test('rejects or exposes unknown critical extensions', () {
      final der = _certificate(
        extraExtensions: [
          _extension('1.2.3.99', critical: true, value: _null()),
        ],
      );
      expect(() => X509Certificate.parse(der), throwsFormatException);

      final parsed = X509Certificate.parse(
        der,
        allowUnknownCriticalExtensions: true,
      );
      expect(parsed.criticalUnknownExtensions.single.oid, '1.2.3.99');
      expect(
        validateC2paSignerCertificate(
          parsed,
          algorithm: SigningAlgorithm.ps256,
          atTime: DateTime.utc(2027),
        ).map((issue) => issue.code),
        contains(CertificateProfileIssueCode.unsupportedCriticalExtension),
      );
    });
  });

  group('certificate profiles', () {
    test('matches every supported signing key family', () {
      final cases = <SigningAlgorithm, List<int>>{
        SigningAlgorithm.es256: _algorithm(
          '1.2.840.10045.2.1',
          parameters: _oid('1.2.840.10045.3.1.7'),
        ),
        SigningAlgorithm.es384: _algorithm(
          '1.2.840.10045.2.1',
          parameters: _oid('1.3.132.0.34'),
        ),
        SigningAlgorithm.es512: _algorithm(
          '1.2.840.10045.2.1',
          parameters: _oid('1.3.132.0.35'),
        ),
        SigningAlgorithm.ps256: _algorithm(
          '1.2.840.113549.1.1.1',
          parameters: _null(),
        ),
        SigningAlgorithm.ps384: _algorithm(
          '1.2.840.113549.1.1.1',
          parameters: _null(),
        ),
        SigningAlgorithm.ps512: _algorithm(
          '1.2.840.113549.1.1.1',
          parameters: _null(),
        ),
        SigningAlgorithm.ed25519: _algorithm('1.3.101.112'),
      };
      for (final entry in cases.entries) {
        final issues = validateC2paSignerCertificate(
          X509Certificate.parse(_certificate(spkiAlgorithm: entry.value)),
          algorithm: entry.key,
          atTime: DateTime.utc(2027),
        );
        expect(
          issues.map((issue) => issue.code),
          isNot(contains(CertificateProfileIssueCode.keyAlgorithmMismatch)),
          reason: entry.key.name,
        );
      }
    });

    test('accepts a strict TSA profile', () {
      final certificate = X509Certificate.parse(
        _certificate(
          extendedKeyUsages: [ExtendedKeyUsageOids.timeStamping],
          ekuCritical: true,
        ),
      );
      expect(
        validateTsaCertificate(
          certificate,
          algorithm: SigningAlgorithm.ps256,
          atTime: DateTime.utc(2027),
        ),
        isEmpty,
      );
    });

    test('honors RSA-PSS key parameter restrictions', () {
      final sha256 = _algorithm('2.16.840.1.101.3.4.2.1', parameters: _null());
      final pssParameters = _sequence([
        _tlv(0xa0, sha256),
        _tlv(0xa1, _algorithm('1.2.840.113549.1.1.8', parameters: sha256)),
        _tlv(0xa2, _integer(32)),
      ]);
      final certificate = X509Certificate.parse(
        _certificate(
          spkiAlgorithm: _algorithm(
            '1.2.840.113549.1.1.10',
            parameters: pssParameters,
          ),
        ),
      );

      final ps256Issues = validateC2paSignerCertificate(
        certificate,
        algorithm: SigningAlgorithm.ps256,
        atTime: DateTime.utc(2027),
      );
      expect(
        ps256Issues.map((issue) => issue.code),
        isNot(contains(CertificateProfileIssueCode.keyAlgorithmMismatch)),
      );
      final ps384Issues = validateC2paSignerCertificate(
        certificate,
        algorithm: SigningAlgorithm.ps384,
        atTime: DateTime.utc(2027),
      );
      expect(
        ps384Issues.map((issue) => issue.code),
        contains(CertificateProfileIssueCode.keyAlgorithmMismatch),
      );
    });

    test('reports validity, CA, usage, EKU, and key mismatch issues', () {
      final certificate = X509Certificate.parse(
        _certificate(
          spkiAlgorithm: _algorithm(
            '1.2.840.10045.2.1',
            parameters: _oid('1.3.132.0.34'),
          ),
          isCa: true,
          digitalSignature: false,
          extendedKeyUsages: [ExtendedKeyUsageOids.timeStamping],
        ),
      );
      final issues = validateC2paSignerCertificate(
        certificate,
        algorithm: SigningAlgorithm.es256,
        atTime: DateTime.utc(2031),
      ).map((issue) => issue.code);

      expect(
        issues,
        containsAll([
          CertificateProfileIssueCode.expired,
          CertificateProfileIssueCode.caCertificate,
          CertificateProfileIssueCode.missingDigitalSignature,
          CertificateProfileIssueCode.disallowedExtendedKeyUsage,
          CertificateProfileIssueCode.keyAlgorithmMismatch,
        ]),
      );
    });

    test('reports missing extensions and invalid TSA EKU profile', () {
      final missing = X509Certificate.parse(
        _certificate(
          includeBasicConstraints: false,
          includeKeyUsage: false,
          includeExtendedKeyUsage: false,
        ),
      );
      final missingIssues = validateC2paSignerCertificate(
        missing,
        algorithm: SigningAlgorithm.ps256,
        atTime: DateTime.utc(2024),
      ).map((issue) => issue.code);
      expect(
        missingIssues,
        containsAll([
          CertificateProfileIssueCode.notYetValid,
          CertificateProfileIssueCode.missingBasicConstraints,
          CertificateProfileIssueCode.missingKeyUsage,
          CertificateProfileIssueCode.missingExtendedKeyUsage,
        ]),
      );

      final tsa = X509Certificate.parse(_certificate());
      final tsaIssues = validateTsaCertificate(
        tsa,
        algorithm: SigningAlgorithm.ps256,
        atTime: DateTime.utc(2027),
      ).map((issue) => issue.code);
      expect(
        tsaIssues,
        containsAll([
          CertificateProfileIssueCode.disallowedExtendedKeyUsage,
          CertificateProfileIssueCode.extendedKeyUsageNotCritical,
        ]),
      );
    });
  });
}

Uint8List _certificate({
  List<int>? spkiAlgorithm,
  List<int>? signatureOid,
  String notBefore = '250101000000Z',
  String notAfter = '300101000000Z',
  bool isCa = false,
  bool digitalSignature = true,
  bool includeBasicConstraints = true,
  bool includeKeyUsage = true,
  bool includeExtendedKeyUsage = true,
  bool ekuCritical = false,
  List<String> extendedKeyUsages = const [ExtendedKeyUsageOids.documentSigning],
  List<List<int>> extraExtensions = const [],
}) {
  final signatureAlgorithm = _sequence([
    signatureOid ?? _oid('1.2.840.113549.1.1.11'),
    _null(),
  ]);
  final extensions = <List<int>>[
    if (includeBasicConstraints)
      _extension(
        '2.5.29.19',
        critical: true,
        value: _sequence([if (isCa) _boolean(true)]),
      ),
    if (includeKeyUsage)
      _extension(
        '2.5.29.15',
        critical: true,
        value: _bitString(
          digitalSignature ? [0x80] : [0x20],
          unusedBits: digitalSignature ? 7 : 5,
        ),
      ),
    if (includeExtendedKeyUsage)
      _extension(
        '2.5.29.37',
        critical: ekuCritical,
        value: _sequence(extendedKeyUsages.map(_oid).toList()),
      ),
    _extension('2.5.29.14', value: _octet([1, 2, 3])),
    _extension(
      '2.5.29.35',
      value: _sequence([
        _tlv(0x80, [4, 5, 6]),
      ]),
    ),
    _extension(
      '1.3.6.1.5.5.7.1.1',
      value: _sequence([
        _sequence([
          _oid('1.3.6.1.5.5.7.48.1'),
          _tlv(0x86, ascii.encode('https://ocsp.test/')),
        ]),
      ]),
    ),
    _extension('1.2.3.4.5', value: _null()),
    ...extraExtensions,
  ];
  final tbs = _sequence([
    _tlv(0xa0, _integer(2)),
    _integer(42),
    signatureAlgorithm,
    _name('Test Issuer'),
    _sequence([
      _tlv(0x17, ascii.encode(notBefore)),
      _tlv(0x17, ascii.encode(notAfter)),
    ]),
    _name('Test Subject'),
    _sequence([
      spkiAlgorithm ?? _algorithm('1.2.840.113549.1.1.1', parameters: _null()),
      _bitString([1, 2, 3, 4]),
    ]),
    _tlv(0xa3, _sequence(extensions)),
  ]);
  return Uint8List.fromList(
    _sequence([
      tbs,
      signatureAlgorithm,
      _bitString([9, 8, 7]),
    ]),
  );
}

List<int> _name(String commonName) => _sequence([
  _set([
    _sequence([_oid('2.5.4.3'), _tlv(0x0c, utf8.encode(commonName))]),
  ]),
]);

List<int> _algorithm(String oid, {List<int>? parameters}) =>
    _sequence([_oid(oid), ?parameters]);

List<int> _extension(
  String oid, {
  bool critical = false,
  required List<int> value,
}) => _sequence([_oid(oid), if (critical) _boolean(true), _octet(value)]);

List<int> _sequence(List<List<int>> values) =>
    _tlv(0x30, values.expand((value) => value).toList());

List<int> _set(List<List<int>> values) =>
    _tlv(0x31, values.expand((value) => value).toList());

List<int> _integer(int value) {
  final bytes = <int>[];
  var remaining = value;
  do {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  } while (remaining != 0);
  if (bytes.first & 0x80 != 0) {
    bytes.insert(0, 0);
  }
  return _tlv(0x02, bytes);
}

List<int> _boolean(bool value) => _tlv(0x01, [value ? 0xff : 0]);

List<int> _null() => _tlv(0x05, []);

List<int> _octet(List<int> value) => _tlv(0x04, value);

List<int> _bitString(List<int> value, {int unusedBits = 0}) =>
    _tlv(0x03, [unusedBits, ...value]);

List<int> _oid(String oid) {
  final arcs = oid.split('.').map(int.parse).toList();
  final subidentifiers = <int>[arcs[0] * 40 + arcs[1], ...arcs.skip(2)];
  final bytes = <int>[];
  for (final value in subidentifiers) {
    final encoded = <int>[value & 0x7f];
    var remaining = value >> 7;
    while (remaining != 0) {
      encoded.insert(0, 0x80 | (remaining & 0x7f));
      remaining >>= 7;
    }
    bytes.addAll(encoded);
  }
  return _tlv(0x06, bytes);
}

List<int> _tlv(int tag, List<int> content) => [
  tag,
  ..._length(content.length),
  ...content,
];

List<int> _length(int length) {
  if (length < 0x80) {
    return [length];
  }
  final bytes = <int>[];
  var remaining = length;
  while (remaining != 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

int _headerLength(List<int> der) {
  final firstLength = der[1];
  return firstLength < 0x80 ? 2 : 2 + (firstLength & 0x7f);
}

int _encodedValueLength(List<int> der, int offset) {
  final firstLength = der[offset + 1];
  if (firstLength < 0x80) {
    return offset + 2 + firstLength;
  }
  final count = firstLength & 0x7f;
  var length = 0;
  for (var index = 0; index < count; index++) {
    length = length << 8 | der[offset + 2 + index];
  }
  return offset + 2 + count + length;
}

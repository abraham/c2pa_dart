@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:test/test.dart';

void main() {
  late crypto.Ed25519 ed25519;
  late crypto.SimpleKeyPair issuerKey;
  late crypto.SimpleKeyPair targetKey;
  late crypto.SimpleKeyPair indirectKey;
  late X509Certificate issuer;
  late X509Certificate target;
  late X509Certificate indirectSigner;

  setUpAll(() async {
    ed25519 = crypto.Ed25519();
    issuerKey = await _key(ed25519, 1);
    targetKey = await _key(ed25519, 33);
    indirectKey = await _key(ed25519, 65);
    issuer = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'Issuer',
        issuer: 'Issuer',
        subjectKey: issuerKey,
        issuerKey: issuerKey,
        serial: 1,
        isCa: true,
      ),
    );
    target = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'Target',
        issuer: 'Issuer',
        subjectKey: targetKey,
        issuerKey: issuerKey,
        serial: 42,
      ),
    );
    indirectSigner = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'CRL Signer',
        issuer: 'Issuer',
        subjectKey: indirectKey,
        issuerKey: issuerKey,
        serial: 7,
        isCa: true,
      ),
    );
  });

  TrustPolicy policy() => TrustPolicy(
    trustAnchors: [issuer.der],
    evaluationTime: DateTime.utc(2027, 1, 2, 12),
  );

  test('parses and verifies a good stapled CRL', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
    );
    final parsed = X509Crl.parse(fixture.der);
    expect(parsed.version, 2);
    expect(parsed.tbsCertListDer, fixture.tbs);
    expect(parsed.thisUpdate, DateTime.utc(2027, 1, 2, 10));
    expect(parsed.nextUpdate, DateTime.utc(2027, 1, 3, 10));
    expect(parsed.crlNumber, BigInt.from(10));
    expect(parsed.authorityKeyIdentifier, issuer.subjectKeyIdentifier);

    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.good);
    expect(result.issues, isEmpty);
  });

  test('finds revoked entries by issuer and serial', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      entries: [
        _EntrySpec(
          serial: target.serialNumber,
          reason: CrlRevocationReason.keyCompromise,
          invalidityDate: '20261231000000Z',
        ),
      ],
    );
    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.revoked);
    expect(result.entry?.reason, CrlRevocationReason.keyCompromise);
    expect(result.entry?.invalidityDate, DateTime.utc(2026, 12, 31));
    expect(result.entry?.effectiveIssuer.der, issuer.subject.der);
  });

  test('reports stale and future CRLs distinctly', () async {
    final stale = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      thisUpdate: '20261230000000Z',
      nextUpdate: '20270101000000Z',
    );
    final staleResult = await verifyCrl(
      stale.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(staleResult.status, CrlStatus.stale);
    expect(staleResult.issues.single.code, CrlIssueCode.staleCrl);

    final future = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      thisUpdate: '20270103100000Z',
      nextUpdate: '20270104100000Z',
    );
    final futureResult = await verifyCrl(
      future.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(futureResult.status, CrlStatus.stale);
    expect(futureResult.issues.single.code, CrlIssueCode.futureCrl);
  });

  test('rejects a bad CertificateList signature', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
    );
    final tampered = Uint8List.fromList(fixture.der);
    tampered[fixture.signatureOffset] ^= 1;
    final result = await verifyCrl(
      tampered,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.malformed);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CrlIssueCode.invalidSignature),
    );
  });

  test('rejects a CRL bound to the wrong issuer', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      issuerName: 'Other Issuer',
    );
    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.malformed);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CrlIssueCode.wrongIssuer),
    );
  });

  test('parses delta indicators and requires a base CRL', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      crlNumber: 11,
      deltaBaseNumber: 10,
    );
    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.crl?.deltaCrlIndicator, BigInt.from(10));
    expect(result.status, CrlStatus.unknown);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CrlIssueCode.deltaBaseCrlRequired),
    );
  });

  test('supports indirect CRL certificateIssuer entries', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: indirectKey,
      signer: indirectSigner,
      indirect: true,
      entries: [
        _EntrySpec(
          serial: target.serialNumber,
          reason: CrlRevocationReason.superseded,
          certificateIssuer: issuer.subject,
        ),
      ],
    );
    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      crlSigner: indirectSigner,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.revoked);
    expect(result.entry?.effectiveIssuer.der, issuer.subject.der);
  });

  test('enforces issuing distribution point scope', () async {
    final fixture = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      onlyContainsCaCertificates: true,
    );
    final result = await verifyCrl(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, CrlStatus.unknown);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CrlIssueCode.targetOutOfScope),
    );
  });

  test('strictly rejects malformed and invalid-version CRLs', () async {
    expect(() => X509Crl.parse([0x30, 0x81, 0]), throwsFormatException);
    final v1WithExtensions = await _crl(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      includeVersion: false,
    );
    expect(() => X509Crl.parse(v1WithExtensions.der), throwsFormatException);
  });

  test('combines OCSP and CRL evidence with deterministic precedence', () {
    final goodOcsp = OcspVerificationResult(
      status: OcspResultStatus.good,
      issues: const [],
    );
    final revokedOcsp = OcspVerificationResult(
      status: OcspResultStatus.revoked,
      issues: const [],
    );
    final unknownOcsp = OcspVerificationResult(
      status: OcspResultStatus.unknown,
      issues: const [],
    );
    final goodCrl = CrlVerificationResult(
      status: CrlStatus.good,
      issues: const [],
    );
    final revokedCrl = CrlVerificationResult(
      status: CrlStatus.revoked,
      issues: const [],
    );
    final staleCrl = CrlVerificationResult(
      status: CrlStatus.stale,
      issues: const [],
    );

    expect(
      evaluateRevocationEvidence(ocsp: goodOcsp, crl: revokedCrl).status,
      RevocationEvidenceStatus.conflict,
    );
    expect(
      evaluateRevocationEvidence(ocsp: revokedOcsp, crl: goodCrl).status,
      RevocationEvidenceStatus.conflict,
    );
    expect(
      evaluateRevocationEvidence(ocsp: unknownOcsp, crl: revokedCrl).status,
      RevocationEvidenceStatus.revoked,
    );
    expect(
      evaluateRevocationEvidence(ocsp: unknownOcsp, crl: staleCrl).status,
      RevocationEvidenceStatus.stale,
    );
    expect(
      evaluateRevocationEvidence().status,
      RevocationEvidenceStatus.unknown,
    );
  });
}

final class _EntrySpec {
  const _EntrySpec({
    required this.serial,
    this.reason,
    this.invalidityDate,
    this.certificateIssuer,
  });

  final BigInt serial;
  final CrlRevocationReason? reason;
  final String? invalidityDate;
  final X509DistinguishedName? certificateIssuer;
}

final class _CrlFixture {
  const _CrlFixture(this.der, this.tbs, this.signatureOffset);
  final Uint8List der;
  final Uint8List tbs;
  final int signatureOffset;
}

Future<_CrlFixture> _crl({
  required crypto.Ed25519 ed25519,
  required crypto.SimpleKeyPair signerKey,
  required X509Certificate signer,
  List<_EntrySpec> entries = const [],
  String? issuerName,
  String thisUpdate = '20270102100000Z',
  String? nextUpdate = '20270103100000Z',
  int crlNumber = 10,
  int? deltaBaseNumber,
  bool indirect = false,
  bool onlyContainsCaCertificates = false,
  bool includeVersion = true,
}) async {
  final algorithm = _sequence([_oid('1.3.101.112')]);
  final encodedEntries = <List<int>>[];
  for (final entry in entries) {
    final extensions = <List<int>>[
      if (entry.reason != null)
        _extension('2.5.29.21', _tlv(0x0a, [entry.reason!.value])),
      if (entry.invalidityDate != null)
        _extension(
          '2.5.29.24',
          _tlv(0x18, ascii.encode(entry.invalidityDate!)),
        ),
      if (entry.certificateIssuer != null)
        _extension(
          '2.5.29.29',
          _sequence([_tlv(0xa4, entry.certificateIssuer!.der)]),
          critical: true,
        ),
    ];
    encodedEntries.add(
      _sequence([
        _integer(entry.serial),
        _tlv(0x17, ascii.encode('270101000000Z')),
        if (extensions.isNotEmpty) _sequence(extensions),
      ]),
    );
  }
  final crlExtensions = <List<int>>[
    _extension(
      '2.5.29.35',
      _sequence([
        if (signer.subjectKeyIdentifier != null)
          _tlv(0x80, signer.subjectKeyIdentifier!),
      ]),
    ),
    _extension('2.5.29.20', _integer(BigInt.from(crlNumber))),
    if (deltaBaseNumber != null)
      _extension(
        '2.5.29.27',
        _integer(BigInt.from(deltaBaseNumber)),
        critical: true,
      ),
    if (indirect || onlyContainsCaCertificates)
      _extension(
        '2.5.29.28',
        _sequence([
          if (onlyContainsCaCertificates) _tlv(0x82, [0xff]),
          if (indirect) _tlv(0x84, [0xff]),
        ]),
        critical: true,
      ),
  ];
  final tbs = Uint8List.fromList(
    _sequence([
      if (includeVersion) _integer(BigInt.one),
      algorithm,
      _name(issuerName ?? signer.subject.attributes.single.value),
      _tlv(0x17, ascii.encode(thisUpdate.substring(2))),
      if (nextUpdate != null) _tlv(0x17, ascii.encode(nextUpdate.substring(2))),
      if (encodedEntries.isNotEmpty) _sequence(encodedEntries),
      _tlv(0xa0, _sequence(crlExtensions)),
    ]),
  );
  final signature = (await ed25519.sign(tbs, keyPair: signerKey)).bytes;
  final der = Uint8List.fromList(
    _sequence([tbs, algorithm, _bitString(signature)]),
  );
  return _CrlFixture(der, tbs, _indexOf(der, signature));
}

Future<crypto.SimpleKeyPair> _key(crypto.Ed25519 algorithm, int start) =>
    algorithm.newKeyPairFromSeed(
      List<int>.generate(32, (index) => start + index),
    );

Future<Uint8List> _certificate({
  required crypto.Ed25519 ed25519,
  required String subject,
  required String issuer,
  required crypto.SimpleKeyPair subjectKey,
  required crypto.SimpleKeyPair issuerKey,
  required int serial,
  bool isCa = false,
}) async {
  final algorithm = _sequence([_oid('1.3.101.112')]);
  final publicKey = await subjectKey.extractPublicKey();
  final keyUsage = isCa
      ? _bitString([0x06], unusedBits: 1)
      : _bitString([0x80], unusedBits: 7);
  final identifier = List<int>.generate(4, (index) => serial + index);
  final extensions = [
    _extension(
      '2.5.29.19',
      _sequence([
        if (isCa) _tlv(0x01, [0xff]),
        if (isCa) _integer(BigInt.from(2)),
      ]),
      critical: true,
    ),
    _extension('2.5.29.15', keyUsage, critical: true),
    if (!isCa)
      _extension(
        '2.5.29.37',
        _sequence([_oid(ExtendedKeyUsageOids.documentSigning)]),
      ),
    _extension('2.5.29.14', _octet(identifier)),
  ];
  final tbs = _sequence([
    _tlv(0xa0, _integer(BigInt.from(2))),
    _integer(BigInt.from(serial)),
    algorithm,
    _name(issuer),
    _sequence([
      _tlv(0x17, ascii.encode('250101000000Z')),
      _tlv(0x17, ascii.encode('300101000000Z')),
    ]),
    _name(subject),
    _sequence([algorithm, _bitString(publicKey.bytes)]),
    _tlv(0xa3, _sequence(extensions)),
  ]);
  final signature = (await ed25519.sign(tbs, keyPair: issuerKey)).bytes;
  return Uint8List.fromList(_sequence([tbs, algorithm, _bitString(signature)]));
}

List<int> _extension(String oid, List<int> value, {bool critical = false}) =>
    _sequence([
      _oid(oid),
      if (critical) _tlv(0x01, [0xff]),
      _octet(value),
    ]);

List<int> _name(String value) => _sequence([
  _set([
    _sequence([_oid('2.5.4.3'), _tlv(0x0c, utf8.encode(value))]),
  ]),
]);

List<int> _sequence(List<List<int>> values) =>
    _tlv(0x30, values.expand((value) => value).toList());

List<int> _set(List<List<int>> values) =>
    _tlv(0x31, values.expand((value) => value).toList());

List<int> _octet(List<int> value) => _tlv(0x04, value);

List<int> _bitString(List<int> value, {int unusedBits = 0}) =>
    _tlv(0x03, [unusedBits, ...value]);

List<int> _integer(BigInt value) {
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
  final arcs = oid.split('.').map(int.parse).toList();
  final values = <int>[arcs[0] * 40 + arcs[1], ...arcs.skip(2)];
  final output = <int>[];
  for (final original in values) {
    var value = original;
    final encoded = <int>[value & 0x7f];
    value >>= 7;
    while (value != 0) {
      encoded.insert(0, 0x80 | value & 0x7f);
      value >>= 7;
    }
    output.addAll(encoded);
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

int _indexOf(List<int> haystack, List<int> needle) {
  for (var index = 0; index <= haystack.length - needle.length; index++) {
    var equal = true;
    for (var offset = 0; offset < needle.length; offset++) {
      if (haystack[index + offset] != needle[offset]) {
        equal = false;
        break;
      }
    }
    if (equal) return index;
  }
  throw StateError('Needle not found');
}

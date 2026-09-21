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
  late crypto.SimpleKeyPair responderKey;
  late X509Certificate issuer;
  late X509Certificate target;
  late X509Certificate responder;

  setUpAll(() async {
    ed25519 = crypto.Ed25519();
    issuerKey = await _key(ed25519, 1);
    targetKey = await _key(ed25519, 33);
    responderKey = await _key(ed25519, 65);
    issuer = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'Issuer',
        issuer: 'Issuer',
        subjectKey: issuerKey,
        issuerKey: issuerKey,
        serial: 1,
        isCa: true,
        includeKeyUsage: false,
      ),
      allowUnknownCriticalExtensions: true,
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
      allowUnknownCriticalExtensions: true,
    );
    responder = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'Responder',
        issuer: 'Issuer',
        subjectKey: responderKey,
        issuerKey: issuerKey,
        serial: 7,
        eku: ExtendedKeyUsageOids.ocspSigning,
        ekuCritical: true,
      ),
      allowUnknownCriticalExtensions: true,
    );
  });

  TrustPolicy policy() => TrustPolicy(
    trustAnchors: [issuer.der],
    evaluationTime: DateTime.utc(2027, 1, 2, 12),
  );

  test('verifies a directly-issued stapled good response', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      nonce: [1, 2, 3],
    );
    final parsed = OcspResponse.parse(fixture.der);
    expect(parsed.responseStatus, OcspResponseStatus.successful);
    expect(parsed.producedAt, DateTime.utc(2027, 1, 2, 11));
    expect(parsed.nonce, [1, 2, 3]);
    expect(parsed.responses.single.certId.serialNumber, BigInt.from(42));
    expect(parsed.responses.single.thisUpdate, DateTime.utc(2027, 1, 2, 10));
    expect(parsed.responses.single.nextUpdate, DateTime.utc(2027, 1, 3, 10));
    expect(parsed.tbsResponseDataDer, fixture.tbs);

    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
      expectedNonce: [1, 2, 3],
    );
    expect(result.status, OcspResultStatus.good);
    expect(result.issues, isEmpty);
  });

  test('accepts interoperable SHA-1 CertID responses', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      useSha1CertId: true,
    );
    final parsed = OcspResponse.parse(fixture.der);
    expect(
      parsed.responses.single.certId.hashAlgorithm,
      OcspCertIdHashAlgorithm.sha1,
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.good);
  });

  test('authorizes an included delegated OCSP responder', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: responderKey,
      signer: responder,
      target: target,
      issuer: issuer,
      includedCertificates: [responder.der],
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.good);
    expect(result.responderCertificate?.serialNumber, BigInt.from(7));
    expect(result.pathResult?.isTrusted, isTrue);
  });

  test('rejects a delegated responder without OCSP signing EKU', () async {
    final unauthorized = X509Certificate.parse(
      await _certificate(
        ed25519: ed25519,
        subject: 'Unauthorized Responder',
        issuer: 'Issuer',
        subjectKey: responderKey,
        issuerKey: issuerKey,
        serial: 8,
      ),
      allowUnknownCriticalExtensions: true,
    );
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: responderKey,
      signer: unauthorized,
      target: target,
      issuer: issuer,
      includedCertificates: [unauthorized.der],
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.malformed);
    expect(
      result.issues.map((issue) => issue.code),
      contains(OcspIssueCode.unauthorizedResponder),
    );
  });

  test('returns unknown for a response bound to another certificate', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      serialOverride: BigInt.from(43),
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.unknown);
    expect(
      result.issues.map((issue) => issue.code),
      contains(OcspIssueCode.targetCertificateMismatch),
    );
  });

  test('returns unknown for stale evidence', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      thisUpdate: '20261230000000Z',
      nextUpdate: '20270101000000Z',
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.unknown);
    expect(
      result.issues.map((issue) => issue.code),
      contains(OcspIssueCode.staleResponse),
    );
  });

  test('reports revoked status, time, and reason', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      status: OcspCertStatus.revoked,
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.revoked);
    expect(result.singleResponse?.revocationTime, DateTime.utc(2027, 1, 1));
    expect(
      result.singleResponse?.revocationReason,
      OcspRevocationReason.keyCompromise,
    );
  });

  test('evaluates revocation status at a historical signing time', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      status: OcspCertStatus.revoked,
      thisUpdate: '20261230000000Z',
      revocationTime: '20270101000000Z',
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
      evaluationTime: DateTime.utc(2026, 12, 31),
    );
    expect(result.status, OcspResultStatus.good);
  });

  test('reports responder unknown status distinctly', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
      status: OcspCertStatus.unknown,
    );
    final result = await verifyOcspResponse(
      fixture.der,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.unknown);
  });

  test('rejects a bad responder signature', () async {
    final fixture = await _response(
      ed25519: ed25519,
      signerKey: issuerKey,
      signer: issuer,
      target: target,
      issuer: issuer,
    );
    final tampered = Uint8List.fromList(fixture.der);
    tampered[fixture.signatureOffset] ^= 1;
    final result = await verifyOcspResponse(
      tampered,
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.malformed);
    expect(
      result.issues.map((issue) => issue.code),
      contains(OcspIssueCode.invalidSignature),
    );
  });

  test('reports malformed DER distinctly', () async {
    final result = await verifyOcspResponse(
      [0x30, 0x81, 0x00],
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(result.status, OcspResultStatus.malformed);
    expect(result.issues.single.code, OcspIssueCode.malformedResponse);
  });

  test('models unsuccessful and inaccessible fetches', () async {
    final unsuccessful = await verifyOcspResponse(
      _sequence([
        _tlv(0x0a, [3]),
      ]),
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
    );
    expect(unsuccessful.status, OcspResultStatus.inaccessible);

    final fetched = await fetchAndVerifyOcsp(
      endpoint: Uri.parse('https://ocsp.example.test'),
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
      transport: (_, _) async => throw StateError('offline'),
    );
    expect(fetched.status, OcspResultStatus.inaccessible);
    expect(fetched.issues.single.code, OcspIssueCode.responseUnavailable);
  });

  test('creates the expected deterministic OCSP request vector', () async {
    final request = await createOcspRequest(
      certificate: target,
      issuer: issuer,
      nonce: [1, 2, 3, 4],
    );
    expect(
      _hex(request),
      '30773075305a30583056300d06096086480165030402010500042098fc412e'
      'a3d208ce67da0af863c293fae85e10a5e913577969b1821326d18727042065'
      'b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b'
      '802012aa2173015301306092b06010505073001020406040401020304',
    );
  });

  test('enforces response size limits before parsing', () async {
    final result = await fetchAndVerifyOcsp(
      endpoint: Uri.parse('https://ocsp.example.test'),
      certificate: target,
      issuer: issuer,
      trustPolicy: policy(),
      maxResponseBytes: 2,
      transport: (_, _) async => [0x30, 0x01, 0x00],
    );
    expect(result.status, OcspResultStatus.inaccessible);
    expect(result.issues.single.code, OcspIssueCode.responseTooLarge);
  });
}

final class _ResponseFixture {
  const _ResponseFixture(this.der, this.tbs, this.signatureOffset);
  final Uint8List der;
  final Uint8List tbs;
  final int signatureOffset;
}

Future<_ResponseFixture> _response({
  required crypto.Ed25519 ed25519,
  required crypto.SimpleKeyPair signerKey,
  required X509Certificate signer,
  required X509Certificate target,
  required X509Certificate issuer,
  OcspCertStatus status = OcspCertStatus.good,
  BigInt? serialOverride,
  String thisUpdate = '20270102100000Z',
  String? nextUpdate = '20270103100000Z',
  String revocationTime = '20270101000000Z',
  List<int>? nonce,
  List<List<int>> includedCertificates = const [],
  bool useSha1CertId = false,
}) async {
  final issuerNameHash = useSha1CertId
      ? (await crypto.Sha1().hash(issuer.subject.der)).bytes
      : await HashAlgorithm.sha256.digest(issuer.subject.der);
  final issuerKeyHash = useSha1CertId
      ? (await crypto.Sha1().hash(issuer.subjectPublicKey)).bytes
      : await HashAlgorithm.sha256.digest(issuer.subjectPublicKey);
  final certId = _sequence([
    _algorithm(useSha1CertId ? '1.3.14.3.2.26' : '2.16.840.1.101.3.4.2.1'),
    _octet(issuerNameHash),
    _octet(issuerKeyHash),
    _integer(serialOverride ?? target.serialNumber),
  ]);
  final certStatus = switch (status) {
    OcspCertStatus.good => _tlv(0x80, const []),
    OcspCertStatus.unknown => _tlv(0x82, const []),
    OcspCertStatus.revoked => _tlv(0xa1, [
      ..._tlv(0x18, ascii.encode(revocationTime)),
      ..._tlv(0xa0, _tlv(0x0a, [1])),
    ]),
  };
  final single = _sequence([
    certId,
    certStatus,
    _tlv(0x18, ascii.encode(thisUpdate)),
    if (nextUpdate != null) _tlv(0xa0, _tlv(0x18, ascii.encode(nextUpdate))),
  ]);
  final responderHash = (await crypto.Sha1().hash(signer.subjectPublicKey))
      .bytes;
  final tbs = Uint8List.fromList(
    _sequence([
      _tlv(0x82, responderHash),
      _tlv(0x18, ascii.encode('20270102110000Z')),
      _sequence([single]),
      if (nonce != null)
        _tlv(0xa1, _sequence([_extension(OcspOids.nonce, _octet(nonce))])),
    ]),
  );
  final signature = (await ed25519.sign(tbs, keyPair: signerKey)).bytes;
  final basic = _sequence([
    tbs,
    _sequence([_oid('1.3.101.112')]),
    _bitString(signature),
    if (includedCertificates.isNotEmpty)
      _tlv(0xa0, _sequence(includedCertificates)),
  ]);
  final response = Uint8List.fromList(
    _sequence([
      _tlv(0x0a, [0]),
      _tlv(0xa0, _sequence([_oid(OcspOids.basicResponse), _octet(basic)])),
    ]),
  );
  return _ResponseFixture(response, tbs, _indexOf(response, signature));
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
  bool includeKeyUsage = true,
  String? eku,
  bool ekuCritical = false,
}) async {
  final algorithm = _sequence([_oid('1.3.101.112')]);
  final publicKey = await subjectKey.extractPublicKey();
  final extensions = <List<int>>[
    _extension(
      '2.5.29.19',
      _sequence([
        if (isCa) _tlv(0x01, [0xff]),
      ]),
      critical: true,
    ),
    if (includeKeyUsage)
      _extension(
        '2.5.29.15',
        _bitString(isCa ? [0x04] : [0x80], unusedBits: isCa ? 2 : 7),
        critical: true,
      ),
    if (eku != null)
      _extension('2.5.29.37', _sequence([_oid(eku)]), critical: ekuCritical),
    _extension(
      '2.5.29.14',
      _octet(List<int>.generate(4, (index) => serial + index)),
    ),
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

List<int> _algorithm(String oid) =>
    _sequence([_oid(oid), _tlv(0x05, const [])]);

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
  final lengthBytes = <int>[];
  var length = content.length;
  while (length != 0) {
    lengthBytes.insert(0, length & 0xff);
    length >>= 8;
  }
  return [tag, 0x80 | lengthBytes.length, ...lengthBytes, ...content];
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
    if (equal) {
      return index;
    }
  }
  throw StateError('Needle not found');
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

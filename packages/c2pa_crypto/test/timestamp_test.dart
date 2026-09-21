@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:test/test.dart';

void main() {
  final signedBytes = utf8.encode('C2PA claim bytes');
  late crypto.Ed25519 ed25519;
  late crypto.SimpleKeyPair keyPair;
  late Uint8List certificate;
  late List<int> certificateHash;

  setUpAll(() async {
    ed25519 = crypto.Ed25519();
    keyPair = await ed25519.newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 11),
    );
    certificate = await _tsaCertificate(ed25519, keyPair);
    certificateHash = await HashAlgorithm.sha256.digest(certificate);
  });

  Future<_TokenFixture> fixture({
    List<int>? imprintSource,
    bool includeContentType = true,
    bool includeMessageDigest = true,
    String genTime = '20270102030405Z',
    BigInt? nonce,
  }) => _timestampToken(
    ed25519: ed25519,
    keyPair: keyPair,
    certificate: certificate,
    signedBytes: imprintSource ?? signedBytes,
    includeContentType: includeContentType,
    includeMessageDigest: includeMessageDigest,
    genTime: genTime,
    nonce: nonce ?? BigInt.from(1234),
  );

  TrustPolicy policy({bool trusted = true}) => TrustPolicy(
    trustAnchors: const [],
    allowedEndEntitySha256Hashes: trusted ? [certificateHash] : const [],
    evaluationTime: DateTime.utc(2027),
  );

  test('parses and verifies a generated RFC 3161 token', () async {
    final generated = await fixture();
    final token = CmsTimestampToken.parse(generated.der);

    expect(token.timestampInfo.policyOid, '1.2.3.4.5');
    expect(token.timestampInfo.messageImprintAlgorithm, HashAlgorithm.sha256);
    expect(token.timestampInfo.genTime, DateTime.utc(2027, 1, 2, 3, 4, 5));
    expect(token.timestampInfo.nonce, BigInt.from(1234));
    expect(token.signerInfo.contentType, CmsOids.tstInfo);
    expect(token.signerInfo.signingTime, DateTime.utc(2027, 1, 2, 3, 4, 5));
    expect(token.signerInfo.signatureAlgorithm.oid, '1.3.101.112');
    expect(token.certificates, hasLength(1));
    expect(token.signerInfo.signedAttributesDer, generated.signedAttrs);
    expect(token.signerInfo.signedAttributesDer.first, 0xa0);
    expect(token.signerInfo.signedAttributesSignatureInput.first, 0x31);

    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
      expectedNonce: BigInt.from(1234),
    );
    expect(result.status, TimestampStatus.valid);
    expect(result.issues, isEmpty);
    expect(result.pathResult?.directlyAllowedEndEntity, isTrue);
  });

  test('rejects a tampered CMS signature', () async {
    final generated = await fixture();
    final tampered = Uint8List.fromList(generated.der);
    tampered[generated.signatureOffset] ^= 1;
    final result = await verifyTimestampToken(
      tampered,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(result.status, TimestampStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.invalidCmsSignature),
    );
  });

  test('rejects the wrong timestamp message imprint', () async {
    final generated = await fixture(imprintSource: utf8.encode('other claim'));
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.messageImprintMismatch),
    );
  });

  test('reports an untrusted TSA certificate', () async {
    final generated = await fixture();
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(trusted: false),
    );
    expect(result.status, TimestampStatus.untrusted);
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.untrustedCertificatePath),
    );
  });

  test('validates TSA certificate lifetime at genTime', () async {
    final generated = await fixture(genTime: '20310102030405Z');
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(result.status, TimestampStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.tsaCertificateProfile),
    );
  });

  test('returns a malformed result for truncated DER', () async {
    final generated = await fixture();
    final result = await verifyTimestampToken(
      generated.der.sublist(0, generated.der.length - 1),
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(result.status, TimestampStatus.malformed);
    expect(result.issues.single.code, TimestampIssueCode.malformedToken);
  });

  test('reports a missing messageDigest signed attribute', () async {
    final generated = await fixture(includeMessageDigest: false);
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(result.status, TimestampStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.missingMessageDigestAttribute),
    );
  });

  test('reports a missing contentType signed attribute', () async {
    final generated = await fixture(includeContentType: false);
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(result.status, TimestampStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.missingContentTypeAttribute),
    );
  });

  test('reports a nonce mismatch', () async {
    final generated = await fixture();
    final result = await verifyTimestampToken(
      generated.der,
      signedBytes: signedBytes,
      trustPolicy: policy(),
      expectedNonce: BigInt.from(999),
    );
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.nonceMismatch),
    );
  });

  test('rejects a signed-attribute digest mismatch', () async {
    final generated = await fixture();
    final tampered = Uint8List.fromList(generated.der);
    tampered[generated.messageDigestOffset] ^= 1;
    final result = await verifyTimestampToken(
      tampered,
      signedBytes: signedBytes,
      trustPolicy: policy(),
    );
    expect(
      result.issues.map((issue) => issue.code),
      contains(TimestampIssueCode.messageDigestMismatch),
    );
  });

  test('creates deterministic RFC 3161 requests and uses transport', () async {
    final first = await createTimestampRequest(
      signedBytes: signedBytes,
      policyOid: '1.2.3.4.5',
      nonce: BigInt.from(99),
    );
    final second = await createTimestampRequest(
      signedBytes: signedBytes,
      policyOid: '1.2.3.4.5',
      nonce: BigInt.from(99),
    );
    expect(first, second);
    expect(first.first, 0x30);

    List<int>? transported;
    final response = await requestTimestamp(
      signedBytes: signedBytes,
      nonce: BigInt.from(99),
      transport: (request) async {
        transported = request;
        return [0x30, 0x00];
      },
    );
    expect(transported, isNotNull);
    expect(response, [0x30, 0x00]);
  });

  test('strictly rejects trailing token data', () async {
    final generated = await fixture();
    expect(
      () => CmsTimestampToken.parse([...generated.der, 0]),
      throwsFormatException,
    );
  });
}

final class _TokenFixture {
  const _TokenFixture({
    required this.der,
    required this.signedAttrs,
    required this.signatureOffset,
    required this.messageDigestOffset,
  });

  final Uint8List der;
  final Uint8List signedAttrs;
  final int signatureOffset;
  final int messageDigestOffset;
}

Future<_TokenFixture> _timestampToken({
  required crypto.Ed25519 ed25519,
  required crypto.SimpleKeyPair keyPair,
  required List<int> certificate,
  required List<int> signedBytes,
  required bool includeContentType,
  required bool includeMessageDigest,
  required String genTime,
  required BigInt? nonce,
}) async {
  final imprint = await HashAlgorithm.sha256.digest(signedBytes);
  final tstInfo = _sequence([
    _integer(BigInt.one),
    _oid('1.2.3.4.5'),
    _sequence([_algorithm('2.16.840.1.101.3.4.2.1'), _octet(imprint)]),
    _integer(BigInt.from(77)),
    _tlv(0x18, ascii.encode(genTime)),
    if (nonce != null) _integer(nonce),
  ]);
  final contentDigest = await HashAlgorithm.sha256.digest(tstInfo);
  final attributes = <List<int>>[
    if (includeContentType)
      _attribute(CmsOids.contentType, _oid(CmsOids.tstInfo)),
    if (includeMessageDigest)
      _attribute(CmsOids.messageDigest, _octet(contentDigest)),
    _attribute(
      CmsOids.signingTime,
      _tlv(0x18, ascii.encode('20270102030405Z')),
    ),
  ]..sort(_compare);
  final signedAttrsSet = _set(attributes);
  final signedAttrs = Uint8List.fromList(signedAttrsSet)..[0] = 0xa0;
  final signature = (await ed25519.sign(
    signedAttrsSet,
    keyPair: keyPair,
  )).bytes;
  final signerInfo = _sequence([
    _integer(BigInt.from(3)),
    _tlv(0x80, [1, 2, 3, 4]),
    _algorithm('2.16.840.1.101.3.4.2.1'),
    signedAttrs,
    _sequence([_oid('1.3.101.112')]),
    _octet(signature),
  ]);
  final signedData = _sequence([
    _integer(BigInt.from(3)),
    _set([_algorithm('2.16.840.1.101.3.4.2.1')]),
    _sequence([_oid(CmsOids.tstInfo), _tlv(0xa0, _octet(tstInfo))]),
    _tlv(0xa0, certificate),
    _set([signerInfo]),
  ]);
  final token = Uint8List.fromList(
    _sequence([_oid(CmsOids.signedData), _tlv(0xa0, signedData)]),
  );
  final signatureOffset = _indexOf(token, signature);
  final messageDigestOffset = includeMessageDigest
      ? _indexOf(token, contentDigest, start: _indexOf(token, signedAttrs))
      : -1;
  return _TokenFixture(
    der: token,
    signedAttrs: signedAttrs,
    signatureOffset: signatureOffset,
    messageDigestOffset: messageDigestOffset,
  );
}

Future<Uint8List> _tsaCertificate(
  crypto.Ed25519 ed25519,
  crypto.SimpleKeyPair keyPair,
) async {
  final publicKey = await keyPair.extractPublicKey();
  final algorithm = _sequence([_oid('1.3.101.112')]);
  final spki = _sequence([algorithm, _bitString(publicKey.bytes)]);
  final name = _name('Test TSA');
  final extensions = [
    _extension('2.5.29.19', critical: true, value: _sequence(const [])),
    _extension(
      '2.5.29.15',
      critical: true,
      value: _bitString([0x80], unusedBits: 7),
    ),
    _extension(
      '2.5.29.37',
      critical: true,
      value: _sequence([_oid(ExtendedKeyUsageOids.timeStamping)]),
    ),
    _extension('2.5.29.14', value: _octet([1, 2, 3, 4])),
  ];
  final tbs = _sequence([
    _tlv(0xa0, _integer(BigInt.from(2))),
    _integer(BigInt.from(42)),
    algorithm,
    name,
    _sequence([
      _tlv(0x17, ascii.encode('250101000000Z')),
      _tlv(0x17, ascii.encode('300101000000Z')),
    ]),
    name,
    spki,
    _tlv(0xa3, _sequence(extensions)),
  ]);
  final signature = (await ed25519.sign(tbs, keyPair: keyPair)).bytes;
  return Uint8List.fromList(_sequence([tbs, algorithm, _bitString(signature)]));
}

List<int> _attribute(String oid, List<int> value) => _sequence([
  _oid(oid),
  _set([value]),
]);

List<int> _algorithm(String oid) =>
    _sequence([_oid(oid), _tlv(0x05, const [])]);

List<int> _extension(
  String oid, {
  bool critical = false,
  required List<int> value,
}) => _sequence([
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

List<int> _octet(List<int> value) => _tlv(0x04, value);

List<int> _bitString(List<int> value, {int unusedBits = 0}) =>
    _tlv(0x03, [unusedBits, ...value]);

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
  final length = content.length;
  if (length < 128) {
    return [tag, length, ...content];
  }
  final bytes = <int>[];
  var remaining = length;
  while (remaining != 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return [tag, 0x80 | bytes.length, ...bytes, ...content];
}

int _compare(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    if (left[index] != right[index]) {
      return left[index] - right[index];
    }
  }
  return left.length - right.length;
}

int _indexOf(List<int> haystack, List<int> needle, {int start = 0}) {
  for (var index = start; index <= haystack.length - needle.length; index++) {
    var matches = true;
    for (var offset = 0; offset < needle.length; offset++) {
      if (haystack[index + offset] != needle[offset]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return index;
    }
  }
  throw StateError('Needle not found');
}

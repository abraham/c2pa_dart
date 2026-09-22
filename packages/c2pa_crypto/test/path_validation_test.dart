@TestOn('vm || browser')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_crypto/src/der_writer.dart';
import 'package:c2pa_crypto/src/key_encoding.dart' as keyenc;
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

void main() {
  late _Key rootAKey;
  late _Key rootBKey;
  late _Key intermediateKey;
  late _Key leafKey;

  setUpAll(() async {
    rootAKey = await _generateKey(1);
    rootBKey = await _generateKey(2);
    intermediateKey = await _generateKey(3);
    leafKey = await _generateKey(4);
  });

  test('validates a root, intermediate, and leaf path', () async {
    final chain = await _chain(rootAKey, intermediateKey, leafKey);
    final result = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        evaluationTime: DateTime.utc(2027),
      ),
    );

    expect(result.status, CertificatePathStatus.trusted);
    expect(result.path, hasLength(3));
    expect(result.path[1].subject.attributes.single.value, 'Intermediate');
    expect(result.directlyAllowedEndEntity, isFalse);
  });

  test('selects the trusted branch of a cross-signed path', () async {
    final rootA = await _certificate(
      subject: 'Root A',
      issuer: 'Root A',
      subjectKey: rootAKey,
      issuerKey: rootAKey,
      serial: 1,
      isCa: true,
      pathLength: 2,
    );
    final rootB = await _certificate(
      subject: 'Root B',
      issuer: 'Root B',
      subjectKey: rootBKey,
      issuerKey: rootBKey,
      serial: 2,
      isCa: true,
      pathLength: 2,
    );
    final intermediateA = await _certificate(
      subject: 'Cross Intermediate',
      issuer: 'Root A',
      subjectKey: intermediateKey,
      issuerKey: rootAKey,
      serial: 3,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootAKey.identifier,
    );
    final intermediateB = await _certificate(
      subject: 'Cross Intermediate',
      issuer: 'Root B',
      subjectKey: intermediateKey,
      issuerKey: rootBKey,
      serial: 4,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootBKey.identifier,
    );
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'Cross Intermediate',
      subjectKey: leafKey,
      issuerKey: intermediateKey,
      serial: 5,
      authorityKeyIdentifier: intermediateKey.identifier,
    );

    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [rootA],
        intermediates: [intermediateB, intermediateA, rootB],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
    expect(result.path.last.subject.attributes.single.value, 'Root A');
  });

  test('detects ambiguous cross-signed paths', () async {
    final rootA = await _certificate(
      subject: 'Root A',
      issuer: 'Root A',
      subjectKey: rootAKey,
      issuerKey: rootAKey,
      serial: 10,
      isCa: true,
      pathLength: 2,
    );
    final rootB = await _certificate(
      subject: 'Root B',
      issuer: 'Root B',
      subjectKey: rootBKey,
      issuerKey: rootBKey,
      serial: 11,
      isCa: true,
      pathLength: 2,
    );
    final intermediateA = await _certificate(
      subject: 'Cross Intermediate',
      issuer: 'Root A',
      subjectKey: intermediateKey,
      issuerKey: rootAKey,
      serial: 12,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootAKey.identifier,
    );
    final intermediateB = await _certificate(
      subject: 'Cross Intermediate',
      issuer: 'Root B',
      subjectKey: intermediateKey,
      issuerKey: rootBKey,
      serial: 13,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootBKey.identifier,
    );
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'Cross Intermediate',
      subjectKey: leafKey,
      issuerKey: intermediateKey,
      serial: 14,
      authorityKeyIdentifier: intermediateKey.identifier,
    );

    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [rootA, rootB],
        intermediates: [intermediateA, intermediateB],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.ambiguous);
    expect(result.issues.single.code, CertificatePathIssueCode.ambiguousPath);
  });

  test('reports expired and historical-time outcomes', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      notAfter: '280101000000Z',
    );
    final current = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        evaluationTime: DateTime.utc(2029),
      ),
    );
    expect(current.status, CertificatePathStatus.invalid);

    final historical = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(historical.status, CertificatePathStatus.trusted);
  });

  test('reports wrong leaf EKU', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      leafEkus: [ExtendedKeyUsageOids.timeStamping],
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(result.issues.single.code, CertificatePathIssueCode.leafProfile);
  });

  test('reports a bad certificate signature', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      corruptLeafSignature: true,
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.badCertificateSignature),
    );
  });

  test('verifies ECDSA DER certificate signatures', () async {
    final issuer = await generateEcdsaKeyPair(SigningAlgorithm.es256);
    final issuerSpki = keyenc.encodeEcdsaPublicKeySpki(
      issuer.publicKey,
      keyenc.prime256v1Oid,
    );
    Future<List<int>> sign(List<int> tbs) async => ecdsaP1363ToDer(
      _signEcdsaRaw(issuer.privateKey, pc.SHA256Digest(), tbs, 32),
      componentLength: 32,
    );
    final root = await _customCertificate(
      subject: 'EC Root',
      issuer: 'EC Root',
      subjectSpki: issuerSpki,
      subjectIdentifier: [20],
      serial: 50,
      isCa: true,
      signatureAlgorithm: _sequence([_oid('1.2.840.10045.4.3.2')]),
      sign: sign,
    );
    final leaf = await _customCertificate(
      subject: 'Leaf',
      issuer: 'EC Root',
      subjectSpki: leafKey.spki,
      subjectIdentifier: leafKey.identifier,
      authorityKeyIdentifier: [20],
      serial: 51,
      signatureAlgorithm: _sequence([_oid('1.2.840.10045.4.3.2')]),
      sign: sign,
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [root],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
  });

  test('verifies RSA-PSS certificate signatures', () async {
    final issuer = await generateRsaPssKeyPair(SigningAlgorithm.ps256);
    final signatureAlgorithm = _rsaPssSha256Algorithm();
    Future<List<int>> sign(List<int> tbs) async => _signRsaPss(
      issuer.privateKey,
      pc.SHA256Digest(),
      pc.SHA256Digest(),
      32,
      tbs,
    );
    final root = await _customCertificate(
      subject: 'PSS Root',
      issuer: 'PSS Root',
      subjectSpki: keyenc.encodeRsaPublicKeySpki(issuer.publicKey),
      subjectIdentifier: [22],
      serial: 55,
      isCa: true,
      signatureAlgorithm: signatureAlgorithm,
      sign: sign,
    );
    final leaf = await _customCertificate(
      subject: 'Leaf',
      issuer: 'PSS Root',
      subjectSpki: leafKey.spki,
      subjectIdentifier: leafKey.identifier,
      authorityKeyIdentifier: [22],
      serial: 56,
      signatureAlgorithm: signatureAlgorithm,
      sign: sign,
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [root],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
  });

  test('verifies Ed25519 certificate signatures', () async {
    final implementation = cryptography.Ed25519();
    final issuer = await implementation.newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 1),
    );
    final publicKey = await issuer.extractPublicKey();
    final issuerSpki = _sequence([
      _sequence([_oid('1.3.101.112')]),
      _bitString(publicKey.bytes),
    ]);
    Future<List<int>> sign(List<int> tbs) async =>
        (await implementation.sign(tbs, keyPair: issuer)).bytes;

    final root = await _customCertificate(
      subject: 'Ed Root',
      issuer: 'Ed Root',
      subjectSpki: issuerSpki,
      subjectIdentifier: [21],
      serial: 60,
      isCa: true,
      signatureAlgorithm: _sequence([_oid('1.3.101.112')]),
      sign: sign,
    );
    final leaf = await _customCertificate(
      subject: 'Leaf',
      issuer: 'Ed Root',
      subjectSpki: leafKey.spki,
      subjectIdentifier: leafKey.identifier,
      authorityKeyIdentifier: [21],
      serial: 61,
      signatureAlgorithm: _sequence([_oid('1.3.101.112')]),
      sign: sign,
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [root],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
  });

  test('rejects non-CA intermediates', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateIsCa: false,
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.issuerNotCa),
    );
  });

  test('enforces pathLenConstraint', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      rootPathLength: 0,
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.pathLengthExceeded),
    );
  });

  test('accepts permitted DNS, IP, email, and URI names', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _nameConstraints(
          permitted: [
            _tlv(0x82, ascii.encode('.example.com')),
            _tlv(0x81, ascii.encode('example.com')),
            _tlv(0x86, ascii.encode('.example.com')),
            _tlv(0x87, [10, 0, 0, 0, 255, 0, 0, 0]),
          ],
        ),
      ],
      leafExtraExtensions: [
        _subjectAlternativeNames([
          _tlv(0x82, ascii.encode('asset.example.com')),
          _tlv(0x81, ascii.encode('signer@example.com')),
          _tlv(0x86, ascii.encode('https://service.example.com/time')),
          _tlv(0x87, [10, 20, 30, 40]),
        ]),
      ],
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.trusted);
    final parsedIntermediate = result.path[1];
    expect(parsedIntermediate.nameConstraints?.permitted, hasLength(4));
    final parsedLeaf = result.path.first;
    expect(
      parsedLeaf.subjectAlternativeNames.map((name) => name.type),
      containsAll(X509GeneralNameType.values),
    );
  });

  test('rejects excluded and non-permitted names in mixed SANs', () async {
    final excluded = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _nameConstraints(
          excluded: [_tlv(0x82, ascii.encode('.blocked.example.com'))],
        ),
      ],
      leafExtraExtensions: [
        _subjectAlternativeNames([
          _tlv(0x82, ascii.encode('asset.blocked.example.com')),
          _tlv(0x81, ascii.encode('safe@example.com')),
        ]),
      ],
    );
    final excludedResult = await _validate(excluded);
    expect(
      excludedResult.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.nameConstraintExcluded),
    );

    final outside = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _nameConstraints(
          permitted: [
            _tlv(0x87, [10, 0, 0, 0, 255, 0, 0, 0]),
          ],
        ),
      ],
      leafExtraExtensions: [
        _subjectAlternativeNames([
          _tlv(0x82, ascii.encode('asset.example.com')),
          _tlv(0x87, [192, 0, 2, 1]),
        ]),
      ],
    );
    final outsideResult = await _validate(outside);
    expect(
      outsideResult.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.nameConstraintNotPermitted),
    );
  });

  test('does not count a self-issued rollover against pathLen', () async {
    final root = await _certificate(
      subject: 'Root',
      issuer: 'Root',
      subjectKey: rootAKey,
      issuerKey: rootAKey,
      serial: 200,
      isCa: true,
      pathLength: 0,
    );
    final rollover = await _certificate(
      subject: 'Root',
      issuer: 'Root',
      subjectKey: intermediateKey,
      issuerKey: rootAKey,
      serial: 201,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootAKey.identifier,
    );
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'Root',
      subjectKey: leafKey,
      issuerKey: intermediateKey,
      serial: 202,
      authorityKeyIdentifier: intermediateKey.identifier,
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [root],
        intermediates: [rollover],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
    expect(result.path, hasLength(3));
  });

  test('enforces anyPolicy inhibition', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _certificatePolicies(['1.2.3.4']),
        _extension('2.5.29.54', critical: true, value: _integer(0)),
      ],
      leafExtraExtensions: [
        _certificatePolicies(['2.5.29.32.0']),
      ],
    );
    final result = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        requiredCertificatePolicyOids: const {'1.2.3.4'},
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.anyPolicyInhibited),
    );
  });

  test('applies certificate policy mappings', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _certificatePolicies(['1.2.3.4']),
        _policyMappings([('1.2.3.4', '1.2.3.5')]),
      ],
      leafExtraExtensions: [
        _certificatePolicies(['1.2.3.5']),
      ],
    );
    final result = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        requiredCertificatePolicyOids: const {'1.2.3.4'},
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
  });

  test('enforces inhibitPolicyMapping across intermediates', () async {
    final root = await _certificate(
      subject: 'Root',
      issuer: 'Root',
      subjectKey: rootAKey,
      issuerKey: rootAKey,
      serial: 210,
      isCa: true,
      pathLength: 2,
    );
    final upper = await _certificate(
      subject: 'Upper',
      issuer: 'Root',
      subjectKey: rootBKey,
      issuerKey: rootAKey,
      serial: 211,
      isCa: true,
      pathLength: 1,
      authorityKeyIdentifier: rootAKey.identifier,
      extraExtensions: [
        _certificatePolicies(['1.2.3.4']),
        _policyConstraints(inhibitPolicyMapping: 0),
      ],
    );
    final lower = await _certificate(
      subject: 'Lower',
      issuer: 'Upper',
      subjectKey: intermediateKey,
      issuerKey: rootBKey,
      serial: 212,
      isCa: true,
      pathLength: 0,
      authorityKeyIdentifier: rootBKey.identifier,
      extraExtensions: [
        _certificatePolicies(['1.2.3.4']),
        _policyMappings([('1.2.3.4', '1.2.3.5')]),
      ],
    );
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'Lower',
      subjectKey: leafKey,
      issuerKey: intermediateKey,
      serial: 213,
      authorityKeyIdentifier: intermediateKey.identifier,
      extraExtensions: [
        _certificatePolicies(['1.2.3.5']),
      ],
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [root],
        intermediates: [upper, lower],
        requiredCertificatePolicyOids: const {'1.2.3.4'},
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.policyMappingInhibited),
    );
  });

  test('enforces requireExplicitPolicy on subsequent certificates', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _policyConstraints(requireExplicitPolicy: 0),
      ],
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.explicitPolicyRequired),
    );
  });

  test('rejects malformed name and policy extension encodings', () async {
    final malformedConstraints = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _extension(
          '2.5.29.30',
          critical: true,
          value: _sequence([
            _tlv(
              0xa0,
              _sequence([
                _tlv(0x82, ascii.encode('.example.com')),
                _tlv(0x80, [0]),
              ]),
            ),
          ]),
        ),
      ],
    );
    final constraintsResult = await _validate(malformedConstraints);
    expect(
      constraintsResult.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.malformedCertificate),
    );

    final malformedMapping = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _policyMappings([('2.5.29.32.0', '1.2.3.5')]),
      ],
    );
    final mappingResult = await _validate(malformedMapping);
    expect(
      mappingResult.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.malformedCertificate),
    );
  });

  test('returns an untrusted result without a matching anchor', () async {
    final chain = await _chain(rootAKey, intermediateKey, leafKey);
    final result = await validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: const [],
        intermediates: [chain.intermediate],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.untrusted);
  });

  test('supports direct end-entity SHA-256 allow-list trust', () async {
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'Missing Issuer',
      subjectKey: leafKey,
      issuerKey: rootAKey,
      serial: 30,
    );
    final hash = await HashAlgorithm.sha256.digest(leaf);
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: const [],
        allowedEndEntitySha256Hashes: [hash],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.trusted);
    expect(result.directlyAllowedEndEntity, isTrue);
    expect(result.path, hasLength(1));
  });

  test('reports critical unsupported validation features', () async {
    final chain = await _chain(
      rootAKey,
      intermediateKey,
      leafKey,
      intermediateExtraExtensions: [
        _extension('1.2.3.4.999', critical: true, value: _sequence([])),
      ],
    );
    final result = await _validate(chain);
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.unsupportedCriticalExtension),
    );
  });

  test('detects issuer loops', () async {
    final a = await _certificate(
      subject: 'CA A',
      issuer: 'CA B',
      subjectKey: rootAKey,
      issuerKey: rootBKey,
      serial: 40,
      isCa: true,
      pathLength: 3,
      authorityKeyIdentifier: rootBKey.identifier,
    );
    final b = await _certificate(
      subject: 'CA B',
      issuer: 'CA A',
      subjectKey: rootBKey,
      issuerKey: rootAKey,
      serial: 41,
      isCa: true,
      pathLength: 3,
      authorityKeyIdentifier: rootAKey.identifier,
    );
    final leaf = await _certificate(
      subject: 'Leaf',
      issuer: 'CA A',
      subjectKey: leafKey,
      issuerKey: rootAKey,
      serial: 42,
      authorityKeyIdentifier: rootAKey.identifier,
    );
    final result = await validateCertificatePath(
      leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: const [],
        intermediates: [a, b],
        evaluationTime: DateTime.utc(2027),
      ),
    );
    expect(result.status, CertificatePathStatus.invalid);
    expect(
      result.issues.map((issue) => issue.code),
      contains(CertificatePathIssueCode.loopDetected),
    );
  });

  test('accepts an RSA signer at the minimum modulus size', () async {
    final der = await _certificate(
      subject: 'Leaf',
      issuer: 'Root A',
      subjectKey: leafKey,
      issuerKey: rootAKey,
      serial: 90,
    );
    final issues = validateC2paSignerCertificate(
      X509Certificate.parse(der),
      algorithm: SigningAlgorithm.ps256,
      atTime: DateTime.utc(2027),
    );

    expect(issues, isEmpty);
  });

  test('rejects an RSA signer below the minimum modulus size', () async {
    final weakKey = await _generateKey(9, modulusBits: 1024);
    final der = await _certificate(
      subject: 'Weak Leaf',
      issuer: 'Root A',
      subjectKey: weakKey,
      issuerKey: rootAKey,
      serial: 91,
    );
    final issues = validateC2paSignerCertificate(
      X509Certificate.parse(der),
      algorithm: SigningAlgorithm.ps256,
      atTime: DateTime.utc(2027),
    );

    expect(
      issues.map((issue) => issue.code),
      contains(CertificateProfileIssueCode.rsaModulusTooSmall),
    );
    expect(
      issues
          .singleWhere(
            (issue) =>
                issue.code == CertificateProfileIssueCode.rsaModulusTooSmall,
          )
          .message,
      contains('1024 bits'),
    );
  });

  test('ignores the RSA modulus floor for an ECDSA signer', () async {
    final ecPair = await generateEcdsaKeyPair(SigningAlgorithm.es256);
    final der = await _customCertificate(
      subject: 'EC Leaf',
      issuer: 'Root A',
      subjectSpki: keyenc.encodeEcdsaPublicKeySpki(
        ecPair.publicKey,
        keyenc.prime256v1Oid,
      ),
      subjectIdentifier: const [9, 9, 9],
      serial: 92,
      signatureAlgorithm: _sequence([_oid('1.2.840.113549.1.1.11'), _null()]),
      sign: (tbs) async => _signPkcs1Sha256(rootAKey.privateKey, tbs),
    );
    final issues = validateC2paSignerCertificate(
      X509Certificate.parse(der),
      algorithm: SigningAlgorithm.es256,
      atTime: DateTime.utc(2027),
    );

    expect(
      issues.map((issue) => issue.code),
      isNot(contains(CertificateProfileIssueCode.rsaModulusTooSmall)),
    );
  });
}

Future<CertificatePathValidationResult> _validate(_Chain chain) =>
    validateCertificatePath(
      chain.leaf,
      algorithm: SigningAlgorithm.ps256,
      policy: TrustPolicy(
        trustAnchors: [chain.root],
        intermediates: [chain.intermediate],
        evaluationTime: DateTime.utc(2027),
      ),
    );

Future<_Chain> _chain(
  _Key rootKey,
  _Key intermediateKey,
  _Key leafKey, {
  String notAfter = '300101000000Z',
  List<String> leafEkus = const [ExtendedKeyUsageOids.documentSigning],
  bool corruptLeafSignature = false,
  bool intermediateIsCa = true,
  int? rootPathLength = 1,
  List<List<int>> intermediateExtraExtensions = const [],
  List<List<int>> leafExtraExtensions = const [],
}) async {
  final root = await _certificate(
    subject: 'Root',
    issuer: 'Root',
    subjectKey: rootKey,
    issuerKey: rootKey,
    serial: 100,
    isCa: true,
    pathLength: rootPathLength,
    notAfter: notAfter,
  );
  final intermediate = await _certificate(
    subject: 'Intermediate',
    issuer: 'Root',
    subjectKey: intermediateKey,
    issuerKey: rootKey,
    serial: 101,
    isCa: intermediateIsCa,
    pathLength: intermediateIsCa ? 0 : null,
    authorityKeyIdentifier: rootKey.identifier,
    notAfter: notAfter,
    extraExtensions: intermediateExtraExtensions,
  );
  final leaf = await _certificate(
    subject: 'Leaf',
    issuer: 'Intermediate',
    subjectKey: leafKey,
    issuerKey: intermediateKey,
    serial: 102,
    authorityKeyIdentifier: intermediateKey.identifier,
    extendedKeyUsages: leafEkus,
    corruptSignature: corruptLeafSignature,
    notAfter: notAfter,
    extraExtensions: leafExtraExtensions,
  );
  return (root: root, intermediate: intermediate, leaf: leaf);
}

typedef _Chain = ({Uint8List root, Uint8List intermediate, Uint8List leaf});

final class _Key {
  const _Key(this.privateKey, this.spki, this.identifier);

  final pc.RSAPrivateKey privateKey;
  final Uint8List spki;
  final Uint8List identifier;
}

Future<_Key> _generateKey(int identifier, {int modulusBits = 2048}) async {
  final pair = await generateRsaPssKeyPair(
    SigningAlgorithm.ps256,
    modulusLength: modulusBits,
  );
  return _Key(
    pair.privateKey,
    keyenc.encodeRsaPublicKeySpki(pair.publicKey),
    Uint8List.fromList([identifier, identifier, identifier]),
  );
}

Future<Uint8List> _certificate({
  required String subject,
  required String issuer,
  required _Key subjectKey,
  required _Key issuerKey,
  required int serial,
  bool isCa = false,
  int? pathLength,
  List<int>? authorityKeyIdentifier,
  List<String> extendedKeyUsages = const [ExtendedKeyUsageOids.documentSigning],
  List<List<int>> extraExtensions = const [],
  bool corruptSignature = false,
  String notAfter = '300101000000Z',
}) async {
  final signatureAlgorithm = _sequence([
    _oid('1.2.840.113549.1.1.11'),
    _null(),
  ]);
  final extensions = <List<int>>[
    _extension(
      '2.5.29.19',
      critical: true,
      value: _sequence([
        if (isCa) _boolean(true),
        if (pathLength != null) _integer(pathLength),
      ]),
    ),
    _extension(
      '2.5.29.15',
      critical: true,
      value: isCa
          ? _bitString([0x04], unusedBits: 2)
          : _bitString([0x80], unusedBits: 7),
    ),
    if (!isCa)
      _extension(
        '2.5.29.37',
        value: _sequence(extendedKeyUsages.map(_oid).toList()),
      ),
    _extension('2.5.29.14', value: _octet(subjectKey.identifier)),
    if (authorityKeyIdentifier != null)
      _extension(
        '2.5.29.35',
        value: _sequence([_tlv(0x80, authorityKeyIdentifier)]),
      ),
    ...extraExtensions,
  ];
  final tbs = _sequence([
    _tlv(0xa0, _integer(2)),
    _integer(serial),
    signatureAlgorithm,
    _name(issuer),
    _sequence([
      _tlv(0x17, ascii.encode('250101000000Z')),
      _tlv(0x17, ascii.encode(notAfter)),
    ]),
    _name(subject),
    subjectKey.spki,
    _tlv(0xa3, _sequence(extensions)),
  ]);
  final signature = _signPkcs1Sha256(issuerKey.privateKey, tbs);
  if (corruptSignature) {
    signature[0] ^= 1;
  }
  return Uint8List.fromList(
    _sequence([tbs, signatureAlgorithm, _bitString(signature)]),
  );
}

Future<Uint8List> _customCertificate({
  required String subject,
  required String issuer,
  required List<int> subjectSpki,
  required List<int> subjectIdentifier,
  required int serial,
  required List<int> signatureAlgorithm,
  required Future<List<int>> Function(List<int>) sign,
  bool isCa = false,
  List<int>? authorityKeyIdentifier,
}) async {
  final extensions = <List<int>>[
    _extension(
      '2.5.29.19',
      critical: true,
      value: _sequence([if (isCa) _boolean(true), if (isCa) _integer(1)]),
    ),
    _extension(
      '2.5.29.15',
      critical: true,
      value: isCa
          ? _bitString([0x04], unusedBits: 2)
          : _bitString([0x80], unusedBits: 7),
    ),
    if (!isCa)
      _extension(
        '2.5.29.37',
        value: _sequence([_oid(ExtendedKeyUsageOids.documentSigning)]),
      ),
    _extension('2.5.29.14', value: _octet(subjectIdentifier)),
    if (authorityKeyIdentifier != null)
      _extension(
        '2.5.29.35',
        value: _sequence([_tlv(0x80, authorityKeyIdentifier)]),
      ),
  ];
  final tbs = _sequence([
    _tlv(0xa0, _integer(2)),
    _integer(serial),
    signatureAlgorithm,
    _name(issuer),
    _sequence([
      _tlv(0x17, ascii.encode('250101000000Z')),
      _tlv(0x17, ascii.encode('300101000000Z')),
    ]),
    _name(subject),
    subjectSpki,
    _tlv(0xa3, _sequence(extensions)),
  ]);
  return Uint8List.fromList(
    _sequence([tbs, signatureAlgorithm, _bitString(await sign(tbs))]),
  );
}

List<int> _name(String commonName) => _sequence([
  _set([
    _sequence([_oid('2.5.4.3'), _tlv(0x0c, utf8.encode(commonName))]),
  ]),
]);

List<int> _rsaPssSha256Algorithm() {
  final hash = _sequence([_oid('2.16.840.1.101.3.4.2.1'), _null()]);
  return _sequence([
    _oid('1.2.840.113549.1.1.10'),
    _sequence([
      _tlv(0xa0, hash),
      _tlv(0xa1, _sequence([_oid('1.2.840.113549.1.1.8'), hash])),
      _tlv(0xa2, _integer(32)),
    ]),
  ]);
}

List<int> _extension(
  String oid, {
  bool critical = false,
  required List<int> value,
}) => _sequence([_oid(oid), if (critical) _boolean(true), _octet(value)]);

List<int> _subjectAlternativeNames(List<List<int>> names) =>
    _extension('2.5.29.17', value: _sequence(names));

List<int> _nameConstraints({
  List<List<int>> permitted = const [],
  List<List<int>> excluded = const [],
}) => _extension(
  '2.5.29.30',
  critical: true,
  value: _sequence([
    if (permitted.isNotEmpty)
      _tlv(
        0xa0,
        permitted
            .map((name) => _sequence([name]))
            .expand((item) => item)
            .toList(),
      ),
    if (excluded.isNotEmpty)
      _tlv(
        0xa1,
        excluded
            .map((name) => _sequence([name]))
            .expand((item) => item)
            .toList(),
      ),
  ]),
);

List<int> _certificatePolicies(List<String> policies) => _extension(
  '2.5.29.32',
  critical: true,
  value: _sequence(
    policies.map((policy) => _sequence([_oid(policy)])).toList(),
  ),
);

List<int> _policyMappings(List<(String, String)> mappings) => _extension(
  '2.5.29.33',
  critical: true,
  value: _sequence(
    mappings
        .map((mapping) => _sequence([_oid(mapping.$1), _oid(mapping.$2)]))
        .toList(),
  ),
);

List<int> _policyConstraints({
  int? requireExplicitPolicy,
  int? inhibitPolicyMapping,
}) => _extension(
  '2.5.29.36',
  critical: true,
  value: _sequence([
    if (requireExplicitPolicy != null)
      _tlv(0x80, _integerContent(requireExplicitPolicy)),
    if (inhibitPolicyMapping != null)
      _tlv(0x81, _integerContent(inhibitPolicyMapping)),
  ]),
);

List<int> _sequence(List<List<int>> values) =>
    _tlv(0x30, values.expand((value) => value).toList());

List<int> _set(List<List<int>> values) =>
    _tlv(0x31, values.expand((value) => value).toList());

List<int> _integer(int value) {
  return _tlv(0x02, _integerContent(value));
}

List<int> _integerContent(int value) {
  final bytes = <int>[];
  var remaining = value;
  do {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  } while (remaining != 0);
  if (bytes.first & 0x80 != 0) {
    bytes.insert(0, 0);
  }
  return bytes;
}

List<int> _boolean(bool value) => _tlv(0x01, [value ? 0xff : 0]);

List<int> _null() => _tlv(0x05, []);

List<int> _octet(List<int> value) => _tlv(0x04, value);

List<int> _bitString(List<int> value, {int unusedBits = 0}) =>
    _tlv(0x03, [unusedBits, ...value]);

List<int> _oid(String oid) {
  final arcs = oid.split('.').map(int.parse).toList();
  final values = <int>[arcs[0] * 40 + arcs[1], ...arcs.skip(2)];
  final bytes = <int>[];
  for (final value in values) {
    final encoded = <int>[value & 0x7f];
    var remaining = value >> 7;
    while (remaining != 0) {
      encoded.insert(0, 0x80 | remaining & 0x7f);
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

/// Signs [data] with RSASSA-PKCS1-v1.5 using SHA-256, as a pure-Dart
/// replacement for webcrypto's `RsassaPkcs1V15PrivateKey.signBytes`.
Uint8List _signPkcs1Sha256(pc.RSAPrivateKey key, List<int> data) {
  final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
    ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(key));
  return signer.generateSignature(Uint8List.fromList(data)).bytes;
}

/// Signs [data] with RSASSA-PSS using [contentDigest]/[mgfDigest] and
/// [saltLength], as a pure-Dart replacement for webcrypto's
/// `RsaPssPrivateKey.signBytes`.
Uint8List _signRsaPss(
  pc.RSAPrivateKey key,
  pc.Digest contentDigest,
  pc.Digest mgfDigest,
  int saltLength,
  List<int> data,
) {
  final signer = pc.PSSSigner(pc.RSAEngine(), contentDigest, mgfDigest)
    ..init(
      true,
      pc.ParametersWithSaltConfiguration(
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(key),
        _testSecureRandom(),
        saltLength,
      ),
    );
  return signer.generateSignature(Uint8List.fromList(data)).bytes;
}

/// Produces a fixed-width big-endian P1363 ECDSA signature over [data], as a
/// pure-Dart replacement for webcrypto's `EcdsaPrivateKey.signBytes`.
Uint8List _signEcdsaRaw(
  pc.ECPrivateKey key,
  pc.Digest digest,
  List<int> data,
  int componentLength,
) {
  final signer = pc.ECDSASigner(digest)
    ..init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.ECPrivateKey>(key),
        _testSecureRandom(),
      ),
    );
  final signature =
      signer.generateSignature(Uint8List.fromList(data)) as pc.ECSignature;
  return Uint8List.fromList([
    ...derFixedWidthUnsigned(signature.r, componentLength),
    ...derFixedWidthUnsigned(signature.s, componentLength),
  ]);
}

pc.SecureRandom _testSecureRandom() {
  final random = pc.FortunaRandom();
  random.seed(
    pc.KeyParameter(Uint8List.fromList(List<int>.generate(32, (i) => i + 1))),
  );
  return random;
}

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'byte_compare.dart';
import 'der_reader.dart';
import 'der_writer.dart';

/// `rsaEncryption` (PKCS#1) OID octets.
const List<int> rsaEncryptionOid = [
  0x2a,
  0x86,
  0x48,
  0x86,
  0xf7,
  0x0d,
  0x01,
  0x01,
  0x01,
];

/// `id-RSASSA-PSS` OID octets.
const List<int> rsaPssOid = [
  0x2a,
  0x86,
  0x48,
  0x86,
  0xf7,
  0x0d,
  0x01,
  0x01,
  0x0a,
];

/// `id-ecPublicKey` OID octets.
const List<int> ecPublicKeyOid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// `prime256v1` (P-256) named curve OID octets.
const List<int> prime256v1Oid = [
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x03,
  0x01,
  0x07,
];

/// `secp384r1` (P-384) named curve OID octets.
const List<int> secp384r1Oid = [0x2b, 0x81, 0x04, 0x00, 0x22];

/// `secp521r1` (P-521) named curve OID octets.
const List<int> secp521r1Oid = [0x2b, 0x81, 0x04, 0x00, 0x23];

/// `id-sha256` OID octets.
const List<int> sha256HashOid = [
  0x60,
  0x86,
  0x48,
  0x01,
  0x65,
  0x03,
  0x04,
  0x02,
  0x01,
];

/// `id-sha384` OID octets.
const List<int> sha384HashOid = [
  0x60,
  0x86,
  0x48,
  0x01,
  0x65,
  0x03,
  0x04,
  0x02,
  0x02,
];

/// `id-sha512` OID octets.
const List<int> sha512HashOid = [
  0x60,
  0x86,
  0x48,
  0x01,
  0x65,
  0x03,
  0x04,
  0x02,
  0x03,
];

/// Resolves the PointyCastle domain parameters for a named curve [oid].
///
/// Throws [FormatException] when [oid] is not a supported NIST curve.
pc.ECDomainParameters domainParametersForCurveOid(List<int> oid) {
  if (bytesEqual(oid, prime256v1Oid)) {
    return pc.ECCurve_secp256r1();
  }
  if (bytesEqual(oid, secp384r1Oid)) {
    return pc.ECCurve_secp384r1();
  }
  if (bytesEqual(oid, secp521r1Oid)) {
    return pc.ECCurve_secp521r1();
  }
  throw const FormatException('Unsupported named curve OID');
}

/// The named curve OID octets for [domain], or `null` when unrecognized.
List<int>? curveOidForDomainParameters(pc.ECDomainParameters domain) {
  switch (domain.domainName) {
    case 'secp256r1':
      return prime256v1Oid;
    case 'secp384r1':
      return secp384r1Oid;
    case 'secp521r1':
      return secp521r1Oid;
    default:
      return null;
  }
}

/// Parses a `SubjectPublicKeyInfo` for an RSA key, accepting either the
/// `rsaEncryption` or `id-RSASSA-PSS` algorithm identifier.
///
/// When the key uses `id-RSASSA-PSS`, its embedded parameters must name
/// [expectedHashOid] for both the digest and MGF1 hash, matching COSE/CMS
/// requirements that a PSS-restricted key not be reused with another hash.
/// Returns `null` when [spki] does not carry an RSA algorithm identifier.
///
/// Throws [FormatException] for malformed input or a PSS parameter mismatch.
({BigInt modulus, BigInt exponent})? parseRsaPublicKeySpki(
  List<int> spki, {
  List<int>? expectedHashOid,
}) {
  final outer = DerReader(Uint8List.fromList(spki));
  final sequence = outer.read(0x30).reader();
  outer.requireEnd();

  final algorithm = sequence.read(0x30).reader();
  final oid = algorithm.read(0x06).content;
  if (bytesEqual(oid, rsaEncryptionOid)) {
    final parameters = algorithm.read(0x05);
    if (parameters.content.isNotEmpty) {
      throw const FormatException('rsaEncryption parameters must be NULL');
    }
    algorithm.requireEnd();
  } else if (bytesEqual(oid, rsaPssOid)) {
    if (expectedHashOid != null) {
      _validateRsaPssSpkiParameters(algorithm, expectedHashOid);
    }
  } else {
    return null;
  }

  final bitString = sequence.read(0x03).content;
  sequence.requireEnd();
  if (bitString.isEmpty || bitString.first != 0) {
    throw const FormatException(
      'RSA SubjectPublicKey BIT STRING must have zero unused bits',
    );
  }
  final rsa = DerReader(Uint8List.fromList(bitString.sublist(1)));
  final publicKey = rsa.read(0x30).reader();
  rsa.requireEnd();
  final modulus = _positiveInteger(publicKey.read(0x02).content, 'modulus');
  final exponent = _positiveInteger(publicKey.read(0x02).content, 'exponent');
  publicKey.requireEnd();
  return (
    modulus: bigIntFromUnsignedBytes(modulus),
    exponent: bigIntFromUnsignedBytes(exponent),
  );
}

void _validateRsaPssSpkiParameters(
  DerReader algorithm,
  List<int> expectedHashOid,
) {
  final parameters = algorithm.read(0x30).reader();
  algorithm.requireEnd();

  const mgf1Oid = <int>[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

  final hashWrapper = parameters.read(0xa0).reader();
  final hash = hashWrapper.read(0x30).reader();
  hashWrapper.requireEnd();
  _requireAlgorithmIdentifier(hash, expectedHashOid, 'RSA-PSS hash');

  final maskWrapper = parameters.read(0xa1).reader();
  final mask = maskWrapper.read(0x30).reader();
  maskWrapper.requireEnd();
  if (!bytesEqual(mask.read(0x06).content, mgf1Oid)) {
    throw const FormatException('RSA-PSS mask algorithm must be MGF1');
  }
  final maskHash = mask.read(0x30).reader();
  _requireAlgorithmIdentifier(maskHash, expectedHashOid, 'RSA-PSS MGF1 hash');
  mask.requireEnd();

  final saltWrapper = parameters.read(0xa2).reader();
  saltWrapper.read(0x02);
  saltWrapper.requireEnd();

  if (parameters.peekTag() == 0xa3) {
    final trailer = parameters.read(0xa3).reader();
    trailer.read(0x02);
    trailer.requireEnd();
  }
  parameters.requireEnd();
}

void _requireAlgorithmIdentifier(
  DerReader algorithm,
  List<int> expectedOid,
  String name,
) {
  if (!bytesEqual(algorithm.read(0x06).content, expectedOid)) {
    throw FormatException('$name does not match the requested algorithm');
  }
  final nullParameters = algorithm.read(0x05);
  if (nullParameters.content.isNotEmpty) {
    throw FormatException('$name parameters must be NULL');
  }
  algorithm.requireEnd();
}

Uint8List _positiveInteger(Uint8List bytes, String name) {
  if (bytes.isEmpty || bytes.first >= 0x80) {
    throw FormatException('RSA $name must be a positive DER INTEGER');
  }
  if (bytes.length > 1 && bytes.first == 0 && bytes[1] < 0x80) {
    throw FormatException('RSA $name has redundant sign padding');
  }
  final value = bytes.length > 1 && bytes.first == 0 ? bytes.sublist(1) : bytes;
  if (value.every((byte) => byte == 0)) {
    throw FormatException('RSA $name must be non-zero');
  }
  return Uint8List.fromList(value);
}

/// Parses a `SubjectPublicKeyInfo` for an EC key.
///
/// Returns `null` when [spki] does not carry the `id-ecPublicKey` algorithm
/// identifier. Throws [FormatException] for malformed input.
({List<int> curveOid, Uint8List point})? parseEcPublicKeySpki(List<int> spki) {
  final outer = DerReader(Uint8List.fromList(spki));
  final sequence = outer.read(0x30).reader();
  outer.requireEnd();

  final algorithm = sequence.read(0x30).reader();
  final oid = algorithm.read(0x06).content;
  if (!bytesEqual(oid, ecPublicKeyOid)) {
    return null;
  }
  final curveOid = algorithm.read(0x06).content;
  algorithm.requireEnd();

  final bitString = sequence.read(0x03).content;
  sequence.requireEnd();
  if (bitString.isEmpty || bitString.first != 0) {
    throw const FormatException(
      'EC SubjectPublicKey BIT STRING must have zero unused bits',
    );
  }
  return (curveOid: curveOid, point: Uint8List.fromList(bitString.sublist(1)));
}

/// Encodes an RSA public key as a `rsaEncryption` SPKI.
Uint8List encodeRsaPublicKeySpki(pc.RSAPublicKey key) {
  final rsaPublicKey = derSequence([
    derInteger(key.modulus!),
    derInteger(key.publicExponent!),
  ]);
  return derSequence([
    derSequence([derOid(rsaEncryptionOid), derNull()]),
    derBitString(rsaPublicKey),
  ]);
}

/// Encodes an RSA private key as a `rsaEncryption` PKCS#8 `PrivateKeyInfo`.
Uint8List encodeRsaPrivateKeyPkcs8(pc.RSAPrivateKey key) {
  final n = key.modulus!;
  final e = key.publicExponent!;
  final d = key.privateExponent!;
  final p = key.p!;
  final q = key.q!;
  final dP = d % (p - BigInt.one);
  final dQ = d % (q - BigInt.one);
  final qInv = q.modInverse(p);
  final rsaPrivateKey = derSequence([
    derInteger(BigInt.zero),
    derInteger(n),
    derInteger(e),
    derInteger(d),
    derInteger(p),
    derInteger(q),
    derInteger(dP),
    derInteger(dQ),
    derInteger(qInv),
  ]);
  return derSequence([
    derInteger(BigInt.zero),
    derSequence([derOid(rsaEncryptionOid), derNull()]),
    derOctetString(rsaPrivateKey),
  ]);
}

/// Decodes an RSA `PrivateKeyInfo` (PKCS#8), accepting `rsaEncryption` or
/// `id-RSASSA-PSS` algorithm identifiers.
///
/// Throws [FormatException] for malformed input.
pc.RSAPrivateKey decodeRsaPrivateKeyPkcs8(List<int> pkcs8) {
  final outer = DerReader(Uint8List.fromList(pkcs8)).read(0x30).reader();
  outer.read(0x02); // version
  final algorithm = outer.read(0x30).reader();
  final oid = algorithm.read(0x06).content;
  if (!bytesEqual(oid, rsaEncryptionOid) && !bytesEqual(oid, rsaPssOid)) {
    throw const FormatException('Not an RSA private key');
  }
  final privateKeyOctets = outer.read(0x04).content;

  final rsaSequence = DerReader(privateKeyOctets).read(0x30).reader();
  rsaSequence.read(0x02); // version
  final modulus = bigIntFromUnsignedBytes(
    _positiveInteger(rsaSequence.read(0x02).content, 'modulus'),
  );
  rsaSequence.read(0x02); // publicExponent (recomputed from p, q, d)
  final privateExponent = bigIntFromUnsignedBytes(
    _positiveInteger(rsaSequence.read(0x02).content, 'privateExponent'),
  );
  final p = bigIntFromUnsignedBytes(
    _positiveInteger(rsaSequence.read(0x02).content, 'prime1'),
  );
  final q = bigIntFromUnsignedBytes(
    _positiveInteger(rsaSequence.read(0x02).content, 'prime2'),
  );
  return pc.RSAPrivateKey(modulus, privateExponent, p, q);
}

/// Encodes an EC public key as an `id-ecPublicKey` SPKI for [curveOid].
Uint8List encodeEcdsaPublicKeySpki(pc.ECPublicKey key, List<int> curveOid) {
  final point = key.Q!.getEncoded(false);
  return derSequence([
    derSequence([derOid(ecPublicKeyOid), derOid(curveOid)]),
    derBitString(point),
  ]);
}

/// Encodes an EC private key as an RFC 5915 `ECPrivateKey` wrapped in a
/// PKCS#8 `PrivateKeyInfo` for [curveOid].
Uint8List encodeEcdsaPrivateKeyPkcs8(
  pc.ECPrivateKey key,
  List<int> curveOid,
  int fieldLength,
) {
  final domain = key.parameters!;
  final d = key.d!;
  final publicPoint = (domain.G * d)!;
  final ecPrivateKey = derSequence([
    derInteger(BigInt.one),
    derOctetString(derFixedWidthUnsigned(d, fieldLength)),
    derTlv(0xa1, derBitString(publicPoint.getEncoded(false))),
  ]);
  return derSequence([
    derInteger(BigInt.zero),
    derSequence([derOid(ecPublicKeyOid), derOid(curveOid)]),
    derOctetString(ecPrivateKey),
  ]);
}

/// Decodes an EC `PrivateKeyInfo` (PKCS#8) using [domain] as the expected
/// curve.
///
/// Throws [FormatException] for malformed input or an algorithm mismatch.
pc.ECPrivateKey decodeEcPrivateKeyPkcs8(
  List<int> pkcs8,
  pc.ECDomainParameters domain,
) {
  final outer = DerReader(Uint8List.fromList(pkcs8)).read(0x30).reader();
  outer.read(0x02); // version
  final algorithm = outer.read(0x30).reader();
  final oid = algorithm.read(0x06).content;
  if (!bytesEqual(oid, ecPublicKeyOid)) {
    throw const FormatException('Not an EC private key');
  }
  final privateKeyOctets = outer.read(0x04).content;

  final ecSequence = DerReader(privateKeyOctets).read(0x30).reader();
  ecSequence.read(0x02); // version, must be 1
  final dBytes = ecSequence.read(0x04).content;
  if (dBytes.isEmpty) {
    throw const FormatException('EC private key value is empty');
  }
  return pc.ECPrivateKey(bigIntFromUnsignedBytes(dBytes), domain);
}

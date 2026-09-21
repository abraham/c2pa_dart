import 'hash_algorithm.dart';

/// Signing algorithms supported by the C2PA cryptographic foundation.
enum SigningAlgorithm {
  /// ECDSA using P-256 and SHA-256; COSE algorithm identifier `-7`.
  es256(
    coseId: -7,
    hashAlgorithm: HashAlgorithm.sha256,
    p1363ComponentLength: 32,
  ),

  /// ECDSA using P-384 and SHA-384; COSE algorithm identifier `-35`.
  es384(
    coseId: -35,
    hashAlgorithm: HashAlgorithm.sha384,
    p1363ComponentLength: 48,
  ),

  /// ECDSA using P-521 and SHA-512; COSE algorithm identifier `-36`.
  es512(
    coseId: -36,
    hashAlgorithm: HashAlgorithm.sha512,
    p1363ComponentLength: 66,
  ),

  /// RSA-PSS using SHA-256 and digest-sized salt; COSE identifier `-37`.
  ps256(coseId: -37, hashAlgorithm: HashAlgorithm.sha256),

  /// RSA-PSS using SHA-384 and digest-sized salt; COSE identifier `-38`.
  ps384(coseId: -38, hashAlgorithm: HashAlgorithm.sha384),

  /// RSA-PSS using SHA-512 and digest-sized salt; COSE identifier `-39`.
  ps512(coseId: -39, hashAlgorithm: HashAlgorithm.sha512),

  /// Ed25519 with hashing intrinsic to the algorithm; COSE identifier `-8`.
  ed25519(coseId: -8);

  const SigningAlgorithm({
    required this.coseId,
    this.hashAlgorithm,
    this.p1363ComponentLength,
  });

  /// The algorithm identifier registered by COSE.
  final int coseId;

  /// The digest used by this algorithm, or `null` when hashing is intrinsic.
  final HashAlgorithm? hashAlgorithm;

  /// The fixed width of each ECDSA P1363 integer, or `null` when inapplicable.
  final int? p1363ComponentLength;

  /// The fixed-width P1363 signature size, or `null` when inapplicable.
  int? get p1363SignatureLength =>
      p1363ComponentLength == null ? null : p1363ComponentLength! * 2;

  /// Resolves an exact COSE algorithm identifier.
  ///
  /// Throws [ArgumentError] when [coseId] is not supported.
  static SigningAlgorithm fromCoseId(int coseId) {
    for (final algorithm in values) {
      if (algorithm.coseId == coseId) {
        return algorithm;
      }
    }
    throw ArgumentError.value(coseId, 'coseId', 'Unsupported COSE algorithm');
  }
}

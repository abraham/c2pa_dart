import 'hash_algorithm.dart';

/// Signing algorithms supported by the C2PA cryptographic foundation.
enum SigningAlgorithm {
  es256(
    coseId: -7,
    hashAlgorithm: HashAlgorithm.sha256,
    p1363ComponentLength: 32,
  ),
  es384(
    coseId: -35,
    hashAlgorithm: HashAlgorithm.sha384,
    p1363ComponentLength: 48,
  ),
  es512(
    coseId: -36,
    hashAlgorithm: HashAlgorithm.sha512,
    p1363ComponentLength: 66,
  ),
  ps256(coseId: -37, hashAlgorithm: HashAlgorithm.sha256),
  ps384(coseId: -38, hashAlgorithm: HashAlgorithm.sha384),
  ps512(coseId: -39, hashAlgorithm: HashAlgorithm.sha512),
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

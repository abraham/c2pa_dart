import 'package:cryptography/cryptography.dart' as crypto;

/// Hash algorithms used by C2PA signing algorithms.
enum HashAlgorithm {
  /// SHA-256, COSE hash component for ES256 and PS256, with 32-byte output.
  sha256('SHA-256', 32),

  /// SHA-384, COSE hash component for ES384 and PS384, with 48-byte output.
  sha384('SHA-384', 48),

  /// SHA-512, COSE hash component for ES512 and PS512, with 64-byte output.
  sha512('SHA-512', 64);

  const HashAlgorithm(this.name, this.digestLength);

  /// The conventional algorithm name.
  final String name;

  /// The digest length in bytes.
  final int digestLength;

  /// Computes a digest of [data].
  Future<List<int>> digest(List<int> data) async {
    final hash = switch (this) {
      sha256 => crypto.Sha256(),
      sha384 => crypto.Sha384(),
      sha512 => crypto.Sha512(),
    };
    return (await hash.hash(data)).bytes;
  }
}

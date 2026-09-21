import 'package:c2pa_crypto/c2pa_crypto.dart';

Future<void> main() async {
  final digest = await HashAlgorithm.sha256.digest([1, 2, 3]);
  assert(digest.length == HashAlgorithm.sha256.digestLength);
}

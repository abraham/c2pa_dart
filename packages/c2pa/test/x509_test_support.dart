import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';

final class TestCertificateChain {
  TestCertificateChain({
    required this.root,
    required this.intermediate,
    required this.leaf,
    required this.wrongEkuLeaf,
    required this.leafPrivateKey,
  });

  final Uint8List root;
  final Uint8List intermediate;
  final Uint8List leaf;
  final Uint8List wrongEkuLeaf;
  final Uint8List leafPrivateKey;

  Uint8List get leafSpki => X509Certificate.parse(leaf).subjectPublicKeyInfoDer;
}

Future<TestCertificateChain> loadTestCertificateChain() async {
  final libraryUri = await Isolate.resolvePackageUri(
    Uri.parse('package:c2pa/c2pa.dart'),
  );
  if (libraryUri == null) {
    throw StateError('Could not resolve the c2pa package root');
  }
  final packageRoot = File.fromUri(libraryUri).parent.parent;
  Future<Uint8List> read(String name) =>
      File('${packageRoot.path}/test/fixtures/x509/$name').readAsBytes();

  return TestCertificateChain(
    root: await read('root.der'),
    intermediate: await read('intermediate.der'),
    leaf: await read('leaf.der'),
    wrongEkuLeaf: await read('wrong_eku_leaf.der'),
    leafPrivateKey: await read('leaf.pk8'),
  );
}

Future<C2paSigner> createNativeTestSigner(TestCertificateChain chain) async {
  final key = await importRsaPssPrivateKeyPkcs8(
    SigningAlgorithm.ps256,
    chain.leafPrivateKey,
  );
  return _NativeTestSigner(RsaPssSigningBackend(SigningAlgorithm.ps256, key));
}

final class _NativeTestSigner implements C2paSigner {
  const _NativeTestSigner(this.backend);

  final CoseSigningBackend backend;

  @override
  String get algorithm => 'ps256';

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      Uint8List.fromList(await backend.sign(SigningAlgorithm.ps256, data));
}

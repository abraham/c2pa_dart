import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';

import '../conformance.dart';
import 'golden_json.dart';

Future<ConformanceFixtureIndex> loadConformanceFixtureIndex(String path) async {
  final json = await loadGoldenJsonObject(path);
  return ConformanceFixtureIndex.fromJson(json);
}

Future<ConformanceFixtureIndex> loadConformanceFixtureManifest(String path) =>
    loadConformanceFixtureIndex(path);

/// Loads a fixture relative to its index and verifies declared size and SHA-256.
Future<Uint8List> loadConformanceFixtureAsset(
  String indexPath,
  ConformanceFixture fixture,
) async {
  final indexUri = await _resolvePackagePath(indexPath);
  final assetUri = indexUri.resolve(fixture.asset);
  final bytes = await File.fromUri(assetUri).readAsBytes();

  final expectedSize = fixture.metadata['size'];
  if (expectedSize != null && expectedSize != bytes.length) {
    throw FormatException(
      'Fixture "${fixture.id}" has size ${bytes.length}, expected '
      '$expectedSize.',
    );
  }

  final expectedHash = fixture.metadata['sha256'];
  if (expectedHash != null) {
    final actualHash = _hex(await HashAlgorithm.sha256.digest(bytes));
    if (expectedHash != actualHash) {
      throw FormatException(
        'Fixture "${fixture.id}" has SHA-256 $actualHash, expected '
        '$expectedHash.',
      );
    }
  }
  return bytes;
}

Future<Uri> _resolvePackagePath(String path) async {
  final pathUri = Uri.file(path);
  if (pathUri.isAbsolute) {
    return pathUri;
  }
  final libraryUri = await Isolate.resolvePackageUri(
    Uri.parse('package:c2pa_testkit/c2pa_testkit_vm.dart'),
  );
  if (libraryUri == null) {
    throw StateError('Unable to resolve the c2pa_testkit package root.');
  }
  return libraryUri.resolve('../').resolveUri(pathUri);
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

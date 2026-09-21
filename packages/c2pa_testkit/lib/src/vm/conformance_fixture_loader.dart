import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:c2pa_crypto/c2pa_crypto.dart';

import '../conformance.dart';
import 'golden_json.dart';

/// Loads a VM-only conformance fixture index from [path].
///
/// Relative paths are resolved through the `c2pa_testkit` package; this uses
/// `dart:io` and isolate package resolution, so it is not web-safe.
Future<ConformanceFixtureIndex> loadConformanceFixtureIndex(String path) async {
  final json = await loadGoldenJsonObject(path);
  return ConformanceFixtureIndex.fromJson(json);
}

/// Loads a VM-only fixture manifest alias from [path].
///
/// This exists for tests that use manifest terminology and delegates to
/// [loadConformanceFixtureIndex].
Future<ConformanceFixtureIndex> loadConformanceFixtureManifest(String path) =>
    loadConformanceFixtureIndex(path);

/// Loads a fixture relative to its index and verifies declared size and SHA-256.
///
/// This VM-only helper reads bytes with `dart:io`. It throws
/// [FormatException] when `metadata.size` or `metadata.sha256` is declared
/// and does not match the bytes on disk.
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

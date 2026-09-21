import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

/// Loads and decodes a JSON golden from [path] in VM tests.
///
/// Relative paths are resolved from the `c2pa_testkit` package root rather
/// than the process working directory.
Future<Object?> loadGoldenJson(String path) async {
  final pathUri = Uri.file(path);
  final file = pathUri.isAbsolute
      ? File.fromUri(pathUri)
      : File.fromUri((await _packageRoot()).resolveUri(pathUri));
  return jsonDecode(await file.readAsString());
}

/// Loads a JSON-object golden from [path] in VM tests.
Future<Map<String, Object?>> loadGoldenJsonObject(String path) async {
  final value = await loadGoldenJson(path);
  if (value is! Map<String, Object?>) {
    throw FormatException('Expected a JSON object in "$path".');
  }
  return value;
}

/// Loads fixture bytes relative to the package root in VM tests.
Future<Uint8List> loadFixtureBytes(String path) async =>
    File.fromUri(await _resolvePackagePath(path)).readAsBytes();

/// Loads fixture text relative to the package root in VM tests.
Future<String> loadFixtureString(String path) async =>
    File.fromUri(await _resolvePackagePath(path)).readAsString();

Future<Uri> _packageRoot() async {
  final libraryUri = await Isolate.resolvePackageUri(
    Uri.parse('package:c2pa_testkit/c2pa_testkit_vm.dart'),
  );
  if (libraryUri == null) {
    throw StateError('Unable to resolve the c2pa_testkit package root.');
  }
  return libraryUri.resolve('../');
}

Future<Uri> _resolvePackagePath(String path) async {
  final pathUri = Uri.file(path);
  return pathUri.isAbsolute
      ? pathUri
      : (await _packageRoot()).resolveUri(pathUri);
}

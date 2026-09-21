@TestOn('vm')
library;

import 'dart:io';
import 'dart:isolate';

import 'package:test/test.dart';

void main() {
  test('main barrel compiles for the browser', () async {
    final library = await Isolate.resolvePackageUri(
      Uri.parse('package:c2pa_testkit/c2pa_testkit.dart'),
    );
    final root = library!.resolve('../');
    final source = File.fromUri(
      root.resolve('test/support/web_compile_smoke.dart'),
    );
    final outputDirectory = Directory.fromUri(
      root.resolve('.dart_tool/browser-compile-$pid/'),
    );
    final output = File.fromUri(outputDirectory.uri.resolve('smoke.js'));

    await outputDirectory.create(recursive: true);
    try {
      final result = await Process.run(Platform.resolvedExecutable, [
        'compile',
        'js',
        source.path,
        '-o',
        output.path,
      ], workingDirectory: root.toFilePath());

      expect(result.exitCode, 0, reason: '${result.stdout}\n${result.stderr}');
      expect(await output.exists(), isTrue);
    } finally {
      if (await outputDirectory.exists()) {
        await outputDirectory.delete(recursive: true);
      }
    }
  }, timeout: const Timeout(Duration(minutes: 2)));
}

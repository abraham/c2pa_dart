import 'dart:io';
import 'dart:isolate';

import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  late Directory scratchDirectory;
  late String scriptPath;

  setUpAll(() async {
    final library = await Isolate.resolvePackageUri(
      Uri.parse('package:c2pa_testkit/c2pa_testkit_vm.dart'),
    );
    final packageRoot = library!.resolve('../');
    scriptPath = File.fromUri(
      packageRoot.resolve('test/support/fake_oracle.dart'),
    ).path;
    scratchDirectory = Directory.fromUri(
      packageRoot.resolve('.dart_tool/c2pa_testkit_oracle_tests/'),
    );
    if (await scratchDirectory.exists()) {
      await scratchDirectory.delete(recursive: true);
    }
  });

  tearDownAll(() async {
    if (await scratchDirectory.exists()) {
      await scratchDirectory.delete(recursive: true);
    }
  });

  C2paRsOracle oracle(
    String mode, {
    Duration timeout = const Duration(seconds: 5),
    int maxOutputBytes = 1024,
  }) {
    return C2paRsOracle(
      command: C2paRsOracleCommand(
        executable: Platform.resolvedExecutable,
        arguments: [
          scriptPath,
          '--asset',
          '{asset}',
          '--json',
          '{json}',
          '--crjson',
          '{crjson}',
          '--mode',
          mode,
        ],
        pinnedVersion: 'fake-c2pa-rs-1.2.3',
      ),
      scratchDirectory: scratchDirectory,
      timeout: timeout,
      maxOutputBytes: maxOutputBytes,
    );
  }

  test(
    'captures JSON, crJSON, diagnostics, version, and exit status',
    () async {
      final result = await oracle('success')
          .inspect(FixtureAsset(name: 'asset', bytes: [1, 2, 3]));

      expect(result.commandVersion, 'fake-c2pa-rs-1.2.3');
      expect(result.exitCode, 0);
      expect(result.json, {
        'active_manifest': 'urn:manifest:active',
        'assetLength': 3,
      });
      expect(result.crJson, {
        'manifests': ['urn:manifest:active'],
      });
      expect(result.jsonText, contains('"assetLength":3'));
      expect(result.crJsonText, contains('"manifests"'));
      expect(result.stderr, endsWith('fake oracle diagnostic'));
      expect(await scratchDirectory.list().toList(), isEmpty);
    },
  );

  test('retains nonzero exit status when a report was emitted', () async {
    final result = await oracle('nonzero')
        .inspect(FixtureAsset(name: 'asset', bytes: [1]));
    expect(result.exitCode, 7);
    expect(result.json, isA<Map<String, Object?>>());
  });

  test('terminates timed out commands and cleans invocation files', () async {
    await expectLater(
      oracle(
        'timeout',
        timeout: const Duration(milliseconds: 100),
      ).inspect(FixtureAsset(name: 'asset', bytes: [])),
      throwsA(isA<C2paRsOracleTimeoutException>()),
    );
    expect(await scratchDirectory.list().toList(), isEmpty);
  });

  test('rejects malformed and oversized reports', () async {
    await expectLater(
      oracle('malformed').inspect(FixtureAsset(name: 'asset', bytes: [])),
      throwsA(isA<C2paRsOracleFormatException>()),
    );
    await expectLater(
      oracle(
        'oversized-report',
        maxOutputBytes: 256,
      ).inspect(FixtureAsset(name: 'asset', bytes: [])),
      throwsA(isA<C2paRsOracleOutputException>()),
    );
  });

  test('limits combined stdout and stderr output', () async {
    await expectLater(
      oracle(
        'oversized-output',
        maxOutputBytes: 256,
      ).inspect(FixtureAsset(name: 'asset', bytes: [])),
      throwsA(isA<C2paRsOracleOutputException>()),
    );
  });

  test('limits combined report files', () async {
    await expectLater(
      oracle(
        'combined-reports',
        maxOutputBytes: 256,
      ).inspect(FixtureAsset(name: 'asset', bytes: [])),
      throwsA(isA<C2paRsOracleOutputException>()),
    );
  });

  test('uses stdout when the command has no JSON output placeholder', () async {
    final stdoutOracle = C2paRsOracle(
      command: C2paRsOracleCommand(
        executable: Platform.resolvedExecutable,
        arguments: [scriptPath, '--mode', 'stdout-json'],
        pinnedVersion: 'fake-c2pa-rs-1.2.3',
      ),
      scratchDirectory: scratchDirectory,
    );

    final result = await stdoutOracle.inspect(
      FixtureAsset(name: 'asset.jpg', bytes: [1]),
    );
    expect(result.json, {'source': 'stdout'});
    expect(result.crJson, isNull);
  });

  test('requires explicit absolute scratch storage and pinned command', () {
    expect(
      () => C2paRsOracle(
        command: C2paRsOracleCommand(
          executable: 'tool',
          arguments: const [],
          pinnedVersion: '1',
        ),
        scratchDirectory: Directory('relative'),
      ),
      throwsArgumentError,
    );
    expect(
      () => C2paRsOracleCommand(
        executable: 'tool',
        arguments: const [],
        pinnedVersion: '',
      ),
      throwsArgumentError,
    );
  });
}

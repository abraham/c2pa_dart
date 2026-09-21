import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2patool_dart/c2patool_dart.dart';
import 'package:test/test.dart';

void main() {
  late Directory scratch;

  setUp(() async {
    scratch = Directory('.dart_tool/c2patool-test');
    if (await scratch.exists()) await scratch.delete(recursive: true);
    await scratch.create(recursive: true);
  });

  tearDown(() async {
    if (await scratch.exists()) await scratch.delete(recursive: true);
  });

  test('help, version, and usage exits are deterministic', () async {
    final help = await C2paCli().run(['--help']);
    final commandHelp = await C2paCli().run(['sign', '--help']);
    final version = await C2paCli().run(['--version']);
    final noCommand = await C2paCli().run([]);
    final usage = await C2paCli().run(['inspect']);

    expect(help.exitCode, CliExitCode.success);
    expect(help.stdout, contains('fragment-sign'));
    expect(help.stderr, isEmpty);
    expect(commandHelp.exitCode, CliExitCode.success);
    expect(commandHelp.stdout, contains('--signer-command'));
    expect(version.stdout, 'c2patool_dart $c2patoolVersion\n');
    expect(noCommand.exitCode, CliExitCode.usage);
    expect(noCommand.stdout, isEmpty);
    expect(noCommand.stderr, startsWith('Usage error: A command is required'));
    expect(usage.exitCode, CliExitCode.usage);
    expect(usage.stdout, isEmpty);
    expect(usage.stderr, startsWith('Usage error:'));
  });

  test('inspect emits parseable SDK, detailed, and crJSON', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    await asset.writeAsBytes(await _manifest());

    for (final format in ['sdk', 'detailed', 'crjson']) {
      final result = await C2paCli().run([
        'inspect',
        '--format',
        format,
        asset.path,
      ]);
      expect(result.exitCode, CliExitCode.success);
      expect(jsonDecode(result.stdout), isA<Map<String, Object?>>());
      expect(result.stderr, isEmpty);
    }
  });

  test('validate uses the validation exit code for an invalid claim', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    await asset.writeAsBytes(await _manifest());

    final result = await C2paCli().run(['validate', asset.path]);

    expect(result.exitCode, CliExitCode.validation);
    expect(result.stderr, 'C2PA validation failed.\n');
    expect(jsonDecode(result.stdout), isA<Map<String, Object?>>());
  });

  test('extract writes the manifest and resources with safe names', () async {
    final source = C2paBuilder(
      definition: ManifestDefinition(
        label: 'urn:example:resources',
        intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
        generatorInfo: ClaimGeneratorInfo(name: 'cli-test'),
        format: 'application/c2pa',
        instanceId: 'xmp:iid:resources',
        resources: [
          ManifestResource(
            label: 'safe-resource',
            format: 'text/plain',
            bytes: Uint8List.fromList(utf8.encode('resource')),
            name: '../unsafe/name',
          ),
        ],
      ),
      context: C2paContext(
        signer: CallbackC2paSigner(
          algorithm: 'es256',
          callback: (_) async => Uint8List(64),
        ),
      ),
      signingAlgorithm: 'es256',
      x5chain: [
        Uint8List.fromList([1]),
      ],
    );
    final asset = File('${scratch.path}/asset.c2pa');
    await asset.writeAsBytes(await source.build());
    final manifest = '${scratch.path}/extracted.c2pa';
    final resources = '${scratch.path}/resources';

    final result = await C2paCli().run([
      'extract',
      '--manifest-output',
      manifest,
      '--resources',
      resources,
      asset.path,
    ]);

    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
    expect(await File(manifest).readAsBytes(), await asset.readAsBytes());
    final files = (await Directory(
      resources,
    ).list().toList()).whereType<File>().toList();
    expect(files, hasLength(1));
    expect(files.single.path, isNot(contains('..')));
    expect(await files.single.readAsString(), 'resource');
  });

  test('malformed assets and definitions have stable nonzero exits', () async {
    final malformed = File('${scratch.path}/malformed.jpg');
    await malformed.writeAsBytes([1, 2, 3]);
    final definition = File('${scratch.path}/manifest.json');
    await definition.writeAsString('{');
    final cert = File('${scratch.path}/cert.der');
    await cert.writeAsBytes([1]);
    final output = '${scratch.path}/archive.c2pa';

    final inspect = await C2paCli().run(['inspect', malformed.path]);
    final archive = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--output',
      output,
    ]);

    expect(inspect.exitCode, CliExitCode.validation);
    expect(archive.exitCode, CliExitCode.validation);
    expect(await File(output).exists(), isFalse);
  });

  test('definition resources cannot escape their directory', () async {
    final definition = File('${scratch.path}/manifest.json');
    await definition.writeAsString(
      jsonEncode({
        ..._definition(),
        'resources': [
          {'label': 'bad', 'format': 'text/plain', 'path': '../secret'},
        ],
      }),
    );
    final cert = File('${scratch.path}/cert.der');
    await cert.writeAsBytes([1]);

    final result = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--output',
      '${scratch.path}/archive.c2pa',
    ]);

    expect(result.exitCode, CliExitCode.validation);
    expect(result.stderr, contains('Unsafe resource path'));
  });

  test('definition resources reject symlink escapes', () async {
    final outside = File('${scratch.path}/outside.bin');
    final definitionDirectory = Directory('${scratch.path}/definition')
      ..createSync();
    final resource = Link('${definitionDirectory.path}/resource.bin');
    await outside.writeAsBytes([1, 2, 3]);
    await resource.create(outside.absolute.path);
    final result = await _archiveDefinition(scratch, {
      ..._definition(),
      'resources': [
        {
          'label': 'escaped',
          'format': 'application/octet-stream',
          'path': 'resource.bin',
        },
      ],
    }, definitionDirectory: definitionDirectory);

    expect(result.exitCode, CliExitCode.io);
    expect(result.stderr, contains('Unsafe path in C2PA working archive'));
  });

  test('ingredient manifests reject symlink escapes', () async {
    final outside = File('${scratch.path}/outside.c2pa');
    final definitionDirectory = Directory('${scratch.path}/definition')
      ..createSync();
    await outside.writeAsBytes(await _manifest());
    await Link('${definitionDirectory.path}/ingredient.c2pa')
        .create(outside.absolute.path);
    final result = await _archiveDefinition(scratch, {
      ..._definition(),
      'ingredients': [
        {
          'id': 'xmp:iid:ingredient',
          'manifest': 'ingredient.c2pa',
          'assertion': {
            'relationship': 'componentOf',
            'dc:title': 'ingredient',
            'dc:format': 'application/c2pa',
            'instanceID': 'xmp:iid:ingredient',
          },
        },
      ],
    }, definitionDirectory: definitionDirectory);

    expect(result.exitCode, CliExitCode.io);
    expect(result.stderr, contains('Unsafe path in C2PA working archive'));
  });

  test('archive resources reject symlink escapes', () async {
    final archiveDirectory = Directory('${scratch.path}/archive')..createSync();
    final project = Directory('${archiveDirectory.path}/project')..createSync();
    final outside = File('${scratch.path}/outside.bin');
    await outside.writeAsBytes([4, 5, 6]);
    await Link('${project.path}/resource.bin').create(outside.absolute.path);
    final archive = File('${archiveDirectory.path}/working.c2pa');
    await archive.writeAsBytes(_archiveWithExternalResource('resource.bin'));
    final signer = await _signerScript(scratch);

    final result = await C2paCli().run([
      'archive-load',
      '--archive',
      archive.path,
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--output',
      '${scratch.path}/output.c2pa',
    ]);

    expect(result.exitCode, CliExitCode.io);
    expect(result.stderr, contains('Unsafe path in C2PA working archive'));
  });

  test('missing inputs still reject an escaping symlink ancestor', () async {
    final outside = Directory('${scratch.path}/outside')..createSync();
    final definitionDirectory = Directory('${scratch.path}/definition')
      ..createSync();
    await Link('${definitionDirectory.path}/nested')
        .create(outside.absolute.path);
    final result = await _archiveDefinition(scratch, {
      ..._definition(),
      'resources': [
        {
          'label': 'missing',
          'format': 'application/octet-stream',
          'path': 'nested/missing.bin',
        },
      ],
    }, definitionDirectory: definitionDirectory);

    expect(result.exitCode, CliExitCode.io);
    expect(result.stderr, contains('Unsafe path in C2PA working archive'));
  });

  test('contained inputs reject broken links, loops, and non-files', () async {
    final definitionDirectory = Directory('${scratch.path}/definition')
      ..createSync();
    await Link('${definitionDirectory.path}/broken.bin').create('missing.bin');
    await Link('${definitionDirectory.path}/loop.bin').create('loop.bin');
    await Directory('${definitionDirectory.path}/directory.bin').create();

    for (final (path, message) in [
      ('broken.bin', 'broken link or symlink loop'),
      ('loop.bin', 'broken link or symlink loop'),
      ('directory.bin', 'not a regular file'),
    ]) {
      final result = await _archiveDefinition(
        scratch,
        {
          ..._definition(),
          'resources': [
            {'label': path, 'format': 'application/octet-stream', 'path': path},
          ],
        },
        definitionDirectory: definitionDirectory,
        outputName: '$path-archive.c2pa',
      );
      expect(result.exitCode, CliExitCode.io, reason: result.stderr);
      expect(result.stderr, contains(message));
    }
  });

  test('opened FileByteSource detects growth before use', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    await asset.writeAsBytes(await _manifest());
    var changed = false;
    final result = await C2paCli(
      onInputOpened: (path) async {
        if (!changed && path == asset.path) {
          changed = true;
          await asset.writeAsBytes([0], mode: FileMode.append);
        }
      },
    ).run(['inspect', asset.path]);

    expect(changed, isTrue);
    expect(result.exitCode, CliExitCode.io);
    expect(result.stderr, contains('changed'));
  });

  test('opened FileByteSource is immune to pathname substitution', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    final opened = File('${scratch.path}/opened.c2pa');
    final replacement = File('${scratch.path}/replacement.c2pa');
    final bytes = await _manifest();
    await asset.writeAsBytes(bytes);
    await replacement.writeAsBytes(List<int>.filled(bytes.length + 1, 0));
    var replaced = false;
    final result = await C2paCli(
      onInputOpened: (path) async {
        if (!replaced && path == asset.path) {
          replaced = true;
          await asset.rename(opened.path);
          await replacement.rename(asset.path);
        }
      },
    ).run(['inspect', '--max-input-bytes', '${bytes.length}', asset.path]);

    expect(replaced, isTrue);
    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
  });

  test('bounded reads are immune to pathname substitution', () async {
    final definition = File('${scratch.path}/manifest.json');
    final opened = File('${scratch.path}/opened.json');
    final replacement = File('${scratch.path}/replacement.json');
    final cert = File('${scratch.path}/cert.der');
    await definition.writeAsString(jsonEncode(_definition()));
    await replacement.writeAsBytes(const []);
    await replacement.openWrite().close();
    final replacementHandle = await replacement.open(mode: FileMode.write);
    await replacementHandle.truncate(16 * 1024 * 1024 + 1);
    await replacementHandle.close();
    await cert.writeAsBytes([1]);
    var replaced = false;
    final result =
        await C2paCli(
          onInputOpened: (path) async {
            if (!replaced && path == definition.path) {
              replaced = true;
              await definition.rename(opened.path);
              await replacement.rename(definition.path);
            }
          },
        ).run([
          'archive-save',
          '--manifest',
          definition.path,
          '--cert',
          cert.path,
          '--output',
          '${scratch.path}/archive.c2pa',
        ]);

    expect(replaced, isTrue);
    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
  });

  test('bounded file limits cover every CLI input category', () async {
    final definition = File('${scratch.path}/manifest.json');
    final cert = File('${scratch.path}/cert.der');
    final asset = File('${scratch.path}/asset.c2pa');
    await definition.writeAsString(jsonEncode(_definition()));
    await cert.writeAsBytes([1]);
    await asset.writeAsBytes(await _manifest());

    Future<File> sparse(String name, int length) async {
      final file = File('${scratch.path}/$name');
      final handle = await file.open(mode: FileMode.write);
      await handle.truncate(length);
      await handle.close();
      return file;
    }

    final oversizedManifest = await sparse('manifest.c2pa', 2);
    final manifestResult = await C2paCli().run([
      'replace',
      '--manifest',
      oversizedManifest.path,
      '--max-manifest-bytes',
      '1',
      '--output',
      '${scratch.path}/replaced.c2pa',
      asset.path,
    ]);

    final oversizedArchive = await sparse('archive.c2pa', 64 * 1024 * 1024 + 1);
    final archiveResult = await C2paCli().run([
      'archive-load',
      '--archive',
      oversizedArchive.path,
      '--signer-command',
      Platform.resolvedExecutable,
      '--output',
      '${scratch.path}/archive-output.c2pa',
    ]);

    final oversizedCert = await sparse('large-cert.der', 4 * 1024 * 1024 + 1);
    final certResult = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      oversizedCert.path,
      '--output',
      '${scratch.path}/cert-archive.c2pa',
    ]);

    final oversizedTrust = await sparse('large-trust.pem', 4 * 1024 * 1024 + 1);
    final trustResult = await C2paCli().run([
      'inspect',
      '--trust-anchor',
      oversizedTrust.path,
      asset.path,
    ]);

    final oversizedDefinition = await sparse(
      'large-definition.json',
      16 * 1024 * 1024 + 1,
    );
    final definitionResult = await C2paCli().run([
      'archive-save',
      '--manifest',
      oversizedDefinition.path,
      '--cert',
      cert.path,
      '--output',
      '${scratch.path}/definition-archive.c2pa',
    ]);

    final oversizedResource = await sparse(
      'large-resource.bin',
      50 * 1024 * 1024 + 1,
    );
    final resourceDefinition = File('${scratch.path}/resource-definition.json');
    await resourceDefinition.writeAsString(
      jsonEncode({
        ..._definition(),
        'resources': [
          {
            'label': 'large',
            'format': 'application/octet-stream',
            'path': oversizedResource.uri.pathSegments.last,
          },
        ],
      }),
    );
    final resourceResult = await C2paCli().run([
      'archive-save',
      '--manifest',
      resourceDefinition.path,
      '--cert',
      cert.path,
      '--output',
      '${scratch.path}/resource-archive.c2pa',
    ]);

    for (final result in [
      manifestResult,
      archiveResult,
      certResult,
      trustResult,
      definitionResult,
      resourceResult,
    ]) {
      expect(result.exitCode, CliExitCode.io, reason: result.stderr);
      expect(result.stderr, contains('exceeds'));
    }
  });

  test('archive save/load round-trips into a readable manifest', () async {
    final definition = File('${scratch.path}/manifest.json');
    await definition.writeAsString(jsonEncode(_definition()));
    final cert = File('${scratch.path}/cert.der');
    await cert.writeAsBytes([1]);
    final archive = '${scratch.path}/working.c2pa';
    final output = '${scratch.path}/output.c2pa';
    final signer = await _signerScript(scratch);

    final saved = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--algorithm',
      'es256',
      '--output',
      archive,
    ]);
    final loaded = await C2paCli().run([
      'archive-load',
      '--archive',
      archive,
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--algorithm',
      'es256',
      '--output',
      output,
    ]);

    expect(saved.exitCode, CliExitCode.success, reason: saved.stderr);
    expect(loaded.exitCode, CliExitCode.success, reason: loaded.stderr);
    final inspected = await C2paCli().run(['inspect', output]);
    expect(inspected.exitCode, CliExitCode.success);
    expect(
      (jsonDecode(inspected.stdout) as Map<String, Object?>)['active_manifest'],
      'urn:example:cli',
    );
  });

  test('archive-load uses the archived algorithm when omitted', () async {
    for (final algorithm in ['es384', 'ed25519', 'ps256']) {
      final archive = await _createArchive(scratch, algorithm);
      final output = '${scratch.path}/$algorithm-output.c2pa';
      final algorithmLog = File('${scratch.path}/$algorithm-algorithm');
      final signer = await _signerScript(
        scratch,
        name: '$algorithm-signer.dart',
        algorithmLog: algorithmLog,
      );

      final result = await C2paCli().run([
        'archive-load',
        '--archive',
        archive,
        '--signer-command',
        Platform.resolvedExecutable,
        '--signer-arg',
        signer.path,
        '--output',
        output,
      ]);

      expect(result.exitCode, CliExitCode.success, reason: result.stderr);
      expect(await algorithmLog.readAsString(), algorithm);
      expect(await File(output).length(), greaterThan(0));
    }
  });

  test('sign uses the archived algorithm when omitted', () async {
    final archive = await _createArchive(scratch, 'es384');
    final output = '${scratch.path}/signed.c2pa';
    final algorithmLog = File('${scratch.path}/sign-algorithm');
    final signer = await _signerScript(
      scratch,
      name: 'sign-archive-signer.dart',
      algorithmLog: algorithmLog,
    );

    final result = await C2paCli().run([
      'sign',
      '--archive',
      archive,
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--output',
      output,
    ]);

    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
    expect(await algorithmLog.readAsString(), 'es384');
    expect(await File(output).length(), greaterThan(0));
  });

  test('an explicit matching archive algorithm is accepted', () async {
    final archive = await _createArchive(scratch, 'es384');
    final output = '${scratch.path}/matching.c2pa';
    final algorithmLog = File('${scratch.path}/matching-algorithm');
    final signer = await _signerScript(
      scratch,
      name: 'matching-signer.dart',
      algorithmLog: algorithmLog,
    );

    final result = await C2paCli().run([
      'archive-load',
      '--archive',
      archive,
      '--algorithm',
      'ES-384',
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--output',
      output,
    ]);

    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
    expect(await algorithmLog.readAsString(), 'es384');
    expect(await File(output).length(), greaterThan(0));
  });

  test(
    'archive algorithm mismatch fails before signer invocation or output',
    () async {
      final archive = await _createArchive(scratch, 'ed25519');
      for (final command in ['sign', 'archive-load']) {
        final output = File('${scratch.path}/$command-mismatch.c2pa');
        final marker = File('${scratch.path}/$command-signer-invoked');
        final signer = await _signerScript(
          scratch,
          name: '$command-mismatch-signer.dart',
          marker: marker,
        );

        final result = await C2paCli().run([
          command,
          '--archive',
          archive,
          '--algorithm',
          'ps256',
          '--signer-command',
          Platform.resolvedExecutable,
          '--signer-arg',
          signer.path,
          '--output',
          output.path,
        ]);

        expect(result.exitCode, CliExitCode.usage);
        expect(
          result.stderr,
          contains(
            '--algorithm ps256 does not match archive signing algorithm '
            'ed25519',
          ),
        );
        expect(await marker.exists(), isFalse);
        expect(await output.exists(), isFalse);
      }
    },
  );

  test('network access requires an explicit host allowlist', () async {
    final result = await C2paCli().run([
      'inspect',
      '--allow-network',
      'missing.jpg',
    ]);

    expect(result.exitCode, CliExitCode.usage);
    expect(result.stderr, contains('--allow-host'));
  });

  test('explicit sidecar takes precedence over an embedded manifest', () async {
    final embedded = await _manifest(label: 'urn:example:embedded');
    final explicit = await _manifest(label: 'urn:example:explicit');
    final source = Uint8List.fromList(
      utf8.encode('<svg xmlns="http://www.w3.org/2000/svg"/>'),
    );
    final embeddedSink = MemoryByteSink();
    await const SvgAssetHandler().embedManifest(
      MemoryByteSource(source),
      embedded,
      embeddedSink,
    );
    final asset = File('${scratch.path}/asset.unknown');
    final sidecar = File('${scratch.path}/explicit.c2pa');
    await asset.writeAsBytes(embeddedSink.toBytes());
    await sidecar.writeAsBytes(explicit);

    final result = await C2paCli().run([
      'inspect',
      '--manifest',
      sidecar.path,
      '--mime-type',
      'image/svg+xml',
      asset.path,
    ]);

    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
    expect(
      (jsonDecode(result.stdout) as Map<String, Object?>)['active_manifest'],
      'urn:example:explicit',
    );
  });

  test('outputs do not clobber without force and never alias inputs', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    final output = File('${scratch.path}/report.json');
    await asset.writeAsBytes(await _manifest());
    await output.writeAsString('keep');

    final refused = await C2paCli().run([
      'inspect',
      '--output',
      output.path,
      asset.path,
    ]);
    expect(refused.exitCode, CliExitCode.usage);
    expect(await output.readAsString(), 'keep');

    final forced = await C2paCli().run([
      'inspect',
      '--force',
      '--output',
      output.path,
      asset.path,
    ]);
    final aliased = await C2paCli().run([
      'inspect',
      '--force',
      '--output',
      asset.path,
      asset.path,
    ]);

    expect(forced.exitCode, CliExitCode.success, reason: forced.stderr);
    expect(await output.readAsString(), isNot('keep'));
    expect(aliased.exitCode, CliExitCode.usage);
    expect(aliased.stderr, contains('must be different'));
  });

  test(
    'sign validates remote output dependencies before signer setup',
    () async {
      final result = await C2paCli().run([
        'sign',
        '--manifest',
        'missing.json',
        '--input',
        'missing.svg',
        '--output',
        '${scratch.path}/manifest.c2pa',
        '--remote-url',
        'https://example.test/manifest.c2pa',
      ]);

      expect(result.exitCode, CliExitCode.usage);
      expect(result.stderr, contains('--asset-output'));
      expect(await File('${scratch.path}/manifest.c2pa').exists(), isFalse);
    },
  );

  test('sign preserves archive sidecar configuration by default', () async {
    final definition = File('${scratch.path}/manifest.json');
    final cert = File('${scratch.path}/cert.der');
    final input = File('${scratch.path}/input.svg');
    final archive = '${scratch.path}/remote-archive.c2pa';
    final manifestOutput = '${scratch.path}/signed.c2pa';
    final assetOutput = '${scratch.path}/signed.svg';
    final marker = File('${scratch.path}/signer-invoked');
    final signer = await _signerScript(scratch, marker: marker);
    await definition.writeAsString(jsonEncode(_definition()));
    await cert.writeAsBytes([1]);
    await input.writeAsString('<svg xmlns="http://www.w3.org/2000/svg"/>');

    final saved = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--no-embed',
      '--remote-url',
      'https://example.test/manifest.c2pa',
      '--output',
      archive,
    ]);
    final signed = await C2paCli().run([
      'sign',
      '--archive',
      archive,
      '--input',
      input.path,
      '--output',
      manifestOutput,
      '--asset-output',
      assetOutput,
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--mime-type',
      'image/svg+xml',
    ]);

    expect(saved.exitCode, CliExitCode.success, reason: saved.stderr);
    expect(signed.exitCode, CliExitCode.success, reason: signed.stderr);
    expect(await marker.exists(), isTrue);
    expect(await File(manifestOutput).length(), greaterThan(0));
    expect(
      await File(assetOutput).readAsString(),
      contains('https://example.test/manifest.c2pa'),
    );
  });

  test(
    'sign can explicitly override archived no-embed configuration',
    () async {
      final definition = File('${scratch.path}/manifest.json');
      final cert = File('${scratch.path}/cert.der');
      final input = File('${scratch.path}/input.svg');
      final archive = '${scratch.path}/sidecar-archive.c2pa';
      final output = '${scratch.path}/embedded.svg';
      final signer = await _signerScript(scratch);
      await definition.writeAsString(jsonEncode(_definition()));
      await cert.writeAsBytes([1]);
      await input.writeAsString('<svg xmlns="http://www.w3.org/2000/svg"/>');

      final saved = await C2paCli().run([
        'archive-save',
        '--manifest',
        definition.path,
        '--cert',
        cert.path,
        '--no-embed',
        '--output',
        archive,
      ]);
      final signed = await C2paCli().run([
        'sign',
        '--archive',
        archive,
        '--embed',
        '--input',
        input.path,
        '--output',
        output,
        '--signer-command',
        Platform.resolvedExecutable,
        '--signer-arg',
        signer.path,
        '--reserve-size',
        '64',
        '--mime-type',
        'image/svg+xml',
      ]);

      expect(saved.exitCode, CliExitCode.success, reason: saved.stderr);
      expect(signed.exitCode, CliExitCode.success, reason: signed.stderr);
      expect(await File(output).readAsString(), contains('c2pa:manifest'));
    },
  );

  test('sign preflights every destination before invoking signer', () async {
    final definition = File('${scratch.path}/manifest.json');
    final cert = File('${scratch.path}/cert.der');
    final input = File('${scratch.path}/input.svg');
    final output = File('${scratch.path}/signed.c2pa');
    final marker = File('${scratch.path}/signer-invoked');
    final signer = await _signerScript(scratch, marker: marker);
    await definition.writeAsString(jsonEncode(_definition()));
    await cert.writeAsBytes([1]);
    await input.writeAsString('<svg xmlns="http://www.w3.org/2000/svg"/>');

    final result = await C2paCli().run([
      'sign',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--no-embed',
      '--remote-url',
      'https://example.test/manifest.c2pa',
      '--input',
      input.path,
      '--output',
      output.path,
      '--asset-output',
      '${scratch.path}/missing/asset.svg',
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--mime-type',
      'image/svg+xml',
    ]);

    expect(result.exitCode, CliExitCode.usage);
    expect(result.stderr, contains('does not exist or is not a directory'));
    expect(await marker.exists(), isFalse);
    expect(await output.exists(), isFalse);
    expect(await File('${scratch.path}/missing/asset.svg').exists(), isFalse);
  });

  test('trust lists are explicit local PEM files', () async {
    final asset = File('${scratch.path}/asset.c2pa');
    final malformedPem = File('${scratch.path}/trust.pem');
    await asset.writeAsBytes(await _manifest());
    await malformedPem.writeAsString('not a PEM certificate');
    final help = await C2paCli().run(['inspect', '--help']);
    final remote = await C2paCli().run([
      'inspect',
      '--trust-list-file',
      'https://example.test/trust.pem',
      'missing.c2pa',
    ]);
    final parsed = await C2paCli().run([
      'inspect',
      '--trust-list-file',
      malformedPem.path,
      asset.path,
    ]);

    expect(help.stdout, contains('--trust-list-file'));
    expect(help.stdout, isNot(contains('--trust-list ')));
    expect(remote.exitCode, CliExitCode.io);
    expect(parsed.exitCode, CliExitCode.validation);
    expect(parsed.stderr, contains('PEM'));
  });

  test('definition ingredients are parsed through public models', () async {
    final definition = File('${scratch.path}/manifest.json');
    await definition.writeAsString(
      jsonEncode({
        ..._definition(),
        'ingredients': [
          {
            'id': 'xmp:iid:ingredient',
            'version': 3,
            'assertion': {
              'relationship': 'componentOf',
              'dc:title': 'component.svg',
              'dc:format': 'image/svg+xml',
              'instanceID': 'xmp:iid:ingredient',
            },
          },
        ],
      }),
    );
    final cert = File('${scratch.path}/cert.der');
    await cert.writeAsBytes([1]);
    final archive = '${scratch.path}/ingredients.c2pa';

    final result = await C2paCli().run([
      'archive-save',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--output',
      archive,
    ]);

    expect(result.exitCode, CliExitCode.success, reason: result.stderr);
    expect(await File(archive).length(), greaterThan(0));
  });

  test('replace, remote, and remove preserve safe output workflow', () async {
    final source = File('${scratch.path}/source.svg');
    final replaced = File('${scratch.path}/replaced.svg');
    final remote = File('${scratch.path}/remote.svg');
    final removed = File('${scratch.path}/removed.svg');
    final manifest = File('${scratch.path}/manifest.c2pa');
    final sourceBytes = utf8.encode(
      '<svg xmlns="http://www.w3.org/2000/svg"/>',
    );
    final manifestBytes = await _manifest();
    final embeddedSink = MemoryByteSink();
    await const SvgAssetHandler().embedManifest(
      MemoryByteSource(sourceBytes),
      manifestBytes,
      embeddedSink,
    );
    await source.writeAsBytes(embeddedSink.toBytes());
    await manifest.writeAsBytes(
      await _manifest(label: 'urn:example:replacement'),
    );

    final replaceResult = await C2paCli().run([
      'replace',
      '--manifest',
      manifest.path,
      '--output',
      replaced.path,
      source.path,
    ]);
    final remoteResult = await C2paCli().run([
      'remote',
      '--url',
      'https://example.test/manifest.c2pa',
      '--output',
      remote.path,
      replaced.path,
    ]);
    final removeResult = await C2paCli().run([
      'remove',
      '--output',
      removed.path,
      replaced.path,
    ]);

    expect(
      replaceResult.exitCode,
      CliExitCode.success,
      reason: replaceResult.stderr,
    );
    expect(
      remoteResult.exitCode,
      CliExitCode.success,
      reason: remoteResult.stderr,
    );
    expect(
      removeResult.exitCode,
      CliExitCode.success,
      reason: removeResult.stderr,
    );
    await expectLater(
      const SvgAssetHandler().extractManifest(
        MemoryByteSource(await removed.readAsBytes()),
      ),
      throwsA(isA<ManifestNotFoundException>()),
    );
  });

  test('fragment sign and inspect use explicit bounded outputs', () async {
    final definition = File('${scratch.path}/manifest.json');
    final cert = File('${scratch.path}/cert.der');
    final init = File('${scratch.path}/init.mp4');
    final fragment = File('${scratch.path}/fragment.m4s');
    final output = '${scratch.path}/fragments';
    final signer = await _signerScript(scratch);
    await definition.writeAsString(jsonEncode(_definition()));
    await cert.writeAsBytes([1]);
    await init.writeAsBytes(_fragmentedInit());
    await fragment.writeAsBytes(_fragment(1, const [1, 2, 3, 4]));

    final signed = await C2paCli().run([
      'fragment-sign',
      '--manifest',
      definition.path,
      '--cert',
      cert.path,
      '--signer-command',
      Platform.resolvedExecutable,
      '--signer-arg',
      signer.path,
      '--reserve-size',
      '64',
      '--init',
      init.path,
      '--fragment',
      fragment.path,
      '--output-dir',
      output,
      '--mime-type',
      'video/mp4',
      '--merkle-reservation',
      '4096',
      '--fixed-block-size',
      '1024',
    ]);
    expect(signed.exitCode, CliExitCode.success, reason: signed.stderr);

    final inspected = await C2paCli().run([
      'fragment-inspect',
      '--init',
      '$output/init.mp4',
      '--fragment',
      '$output/fragment-0.m4s',
      '--mime-type',
      'video/mp4',
    ]);
    expect(inspected.exitCode, isNot(CliExitCode.usage));
    expect(jsonDecode(inspected.stdout), isA<Map<String, Object?>>());
  });

  test(
    'fragment signing rejects generated output aliases before signing',
    () async {
      final definition = File('${scratch.path}/manifest.json');
      final cert = File('${scratch.path}/cert.der');
      final init = File('${scratch.path}/init.mp4');
      final fragment = File('${scratch.path}/fragment.m4s');
      final marker = File('${scratch.path}/signer-invoked');
      final signer = await _signerScript(scratch, marker: marker);
      await definition.writeAsString(jsonEncode(_definition()));
      await cert.writeAsBytes([1]);
      final originalInit = _fragmentedInit();
      await init.writeAsBytes(originalInit);
      await fragment.writeAsBytes(_fragment(1, const [1, 2, 3, 4]));

      final result = await C2paCli().run([
        'fragment-sign',
        '--manifest',
        definition.path,
        '--cert',
        cert.path,
        '--signer-command',
        Platform.resolvedExecutable,
        '--signer-arg',
        signer.path,
        '--reserve-size',
        '64',
        '--init',
        init.path,
        '--fragment',
        fragment.path,
        '--output-dir',
        scratch.path,
        '--force',
        '--mime-type',
        'video/mp4',
      ]);

      expect(result.exitCode, CliExitCode.usage);
      expect(result.stderr, contains('must be different'));
      expect(await marker.exists(), isFalse);
      expect(await init.readAsBytes(), originalInit);
    },
  );
}

Future<Uint8List> _manifest({String label = 'urn:example:cli'}) {
  return C2paBuilder(
    definition: ManifestDefinition(
      label: label,
      intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
      generatorInfo: ClaimGeneratorInfo(name: 'cli-test', version: '1'),
      format: 'application/c2pa',
      instanceId: 'xmp:iid:cli-test',
    ),
    context: C2paContext(
      signer: CallbackC2paSigner(
        algorithm: 'es256',
        callback: (_) async => Uint8List(64),
      ),
    ),
    signingAlgorithm: 'es256',
    x5chain: [
      Uint8List.fromList([1]),
    ],
  ).build();
}

Map<String, Object?> _definition() => {
  'label': 'urn:example:cli',
  'format': 'application/c2pa',
  'instance_id': 'xmp:iid:cli-test',
  'claim_generator_info': {'name': 'cli-test', 'version': '1'},
  'intent': {'type': 'create', 'sourceType': 'digitalCapture'},
  'actions': [
    {'action': 'c2pa.created'},
  ],
};

Future<CliResult> _archiveDefinition(
  Directory scratch,
  Map<String, Object?> definition, {
  Directory? definitionDirectory,
  String outputName = 'archive.c2pa',
}) async {
  final directory = definitionDirectory ?? scratch;
  final definitionFile = File('${directory.path}/manifest.json');
  final cert = File('${scratch.path}/cert.der');
  await definitionFile.writeAsString(jsonEncode(definition));
  await cert.writeAsBytes([1]);
  return C2paCli().run([
    'archive-save',
    '--manifest',
    definitionFile.path,
    '--cert',
    cert.path,
    '--output',
    '${scratch.path}/$outputName',
  ]);
}

Uint8List _archiveWithExternalResource(String path) {
  final builder = C2paBuilder(
    definition: ManifestDefinition(
      label: 'urn:example:external',
      intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
      generatorInfo: ClaimGeneratorInfo(name: 'cli-test'),
      format: 'application/c2pa',
      instanceId: 'xmp:iid:external',
    ),
    context: C2paContext(),
    signingAlgorithm: 'es256',
    x5chain: const [],
  );
  final root = parseJumbf(builder.toArchive());
  final payload = (root.children.single as JumbfJsonNode).payload;
  final document = jsonDecode(utf8.decode(payload)) as Map<String, Object?>;
  final archiveBuilder = document['builder']! as Map<String, Object?>;
  archiveBuilder['basePath'] = 'project';
  archiveBuilder['externalResources'] = [
    {
      'uri': 'self#jumbf=/c2pa/resource',
      'path': path,
      'format': 'application/octet-stream',
    },
  ];
  return JumbfSuperBoxNode(
    description: root.description,
    children: [
      JumbfJsonNode(Uint8List.fromList(utf8.encode(jsonEncode(document)))),
    ],
  ).encode();
}

Future<String> _createArchive(Directory scratch, String algorithm) async {
  final definition = File('${scratch.path}/$algorithm-manifest.json');
  final cert = File('${scratch.path}/$algorithm-cert.der');
  final archive = '${scratch.path}/$algorithm-working.c2pa';
  await definition.writeAsString(jsonEncode(_definition()));
  await cert.writeAsBytes([1]);
  final result = await C2paCli().run([
    'archive-save',
    '--manifest',
    definition.path,
    '--cert',
    cert.path,
    '--algorithm',
    algorithm,
    '--output',
    archive,
  ]);
  expect(result.exitCode, CliExitCode.success, reason: result.stderr);
  return archive;
}

Future<File> _signerScript(
  Directory scratch, {
  File? marker,
  File? algorithmLog,
  String name = 'signer.dart',
}) async {
  final script = File('${scratch.path}/$name');
  await script.writeAsString('''
import 'dart:io';
Future<void> main() async {
  ${marker == null ? '' : 'await File(${jsonEncode(marker.path)}).writeAsString("invoked");'}
  final algorithm = Platform.environment['C2PA_SIGNING_ALGORITHM']!;
  ${algorithmLog == null ? '' : 'await File(${jsonEncode(algorithmLog.path)}).writeAsString(algorithm);'}
  await stdin.fold<List<int>>(<int>[], (a, b) => a..addAll(b));
  final size = switch (algorithm.replaceAll('-', '').replaceAll('_', '').toLowerCase()) {
    'es384' => 96,
    'ps256' || 'ps384' || 'ps512' => 256,
    _ => 64,
  };
  stdout.add(List<int>.filled(size, 0));
}
''');
  return script;
}

List<int> _fragmentedInit() => [
  ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
  ..._isoBox('moov', const []),
];

List<int> _fragment(int sequence, List<int> payload) => [
  ..._isoBox('moof', _isoBox('mfhd', [0, 0, 0, 0, ..._uint32(sequence)])),
  ..._isoBox('mdat', payload),
];

List<int> _isoBox(String type, List<int> payload) => [
  ..._uint32(payload.length + 8),
  ...type.codeUnits,
  ...payload,
];

List<int> _uint32(int value) => [
  (value >> 24) & 0xff,
  (value >> 16) & 0xff,
  (value >> 8) & 0xff,
  value & 0xff,
];

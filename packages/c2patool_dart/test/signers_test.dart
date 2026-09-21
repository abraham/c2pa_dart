import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2patool_dart/src/signers.dart'
    show
        LocalKeyC2paSigner,
        resolveExecutableFromPath,
        SubprocessC2paSigner,
        SubprocessSignerException;
import 'package:test/test.dart';

void main() {
  late Directory scratch;

  setUp(() async {
    scratch = Directory('.dart_tool/c2patool-signer-test');
    if (await scratch.exists()) await scratch.delete(recursive: true);
    await scratch.create(recursive: true);
  });

  tearDown(() async {
    if (await scratch.exists()) await scratch.delete(recursive: true);
  });

  group('subprocess signer', () {
    test('round-trips the raw protocol and algorithm environment', () async {
      final script = await _script(scratch, '''
import 'dart:io';
Future<void> main() async {
  final bytes = await stdin.fold<List<int>>([], (a, b) => a..addAll(b));
  if (Platform.environment['C2PA_SIGNING_ALGORITHM'] != 'es384') {
    stderr.write('missing algorithm');
    exitCode = 2;
    return;
  }
  stdout.add(bytes.reversed.toList());
}
''');
      final signer = SubprocessC2paSigner(
        executable: Platform.resolvedExecutable,
        arguments: [script.path],
        algorithm: 'es384',
      );

      expect(
        await signer.sign(Uint8List.fromList([1, 2, 3])),
        Uint8List.fromList([3, 2, 1]),
      );
    });

    test('reports nonzero exits and bounded diagnostics', () async {
      final script = await _script(scratch, '''
import 'dart:io';
void main() {
  stderr.write('denied');
  exitCode = 9;
}
''');
      final signer = SubprocessC2paSigner(
        executable: Platform.resolvedExecutable,
        arguments: [script.path],
        algorithm: 'ed25519',
      );

      await expectLater(
        signer.sign(Uint8List(1)),
        throwsA(
          isA<SubprocessSignerException>()
              .having((error) => error.message, 'message', contains('code 9'))
              .having((error) => error.message, 'message', contains('denied')),
        ),
      );
    });

    test('rejects an empty malformed response', () async {
      final script = await _script(scratch, 'void main() {}');
      final signer = SubprocessC2paSigner(
        executable: Platform.resolvedExecutable,
        arguments: [script.path],
        algorithm: 'ed25519',
      );

      await expectLater(
        signer.sign(Uint8List(1)),
        throwsA(
          isA<SubprocessSignerException>().having(
            (error) => error.message,
            'message',
            contains('empty signature'),
          ),
        ),
      );
    });

    test('bounds signature and diagnostic output while streaming', () async {
      for (final streamName in ['stdout', 'stderr']) {
        final script = await _script(scratch, '''
import 'dart:io';
void main() {
  $streamName.add(List<int>.filled(1024 * 1024, 1));
}
''');
        final signer = SubprocessC2paSigner(
          executable: Platform.resolvedExecutable,
          arguments: [script.path],
          algorithm: 'ed25519',
          maximumSignatureBytes: 8,
          maximumDiagnosticBytes: 8,
        );

        await expectLater(
          signer.sign(Uint8List(1)),
          throwsA(
            isA<SubprocessSignerException>().having(
              (error) => error.message,
              'message',
              contains('exceeds the 8 byte limit'),
            ),
          ),
        );
      }
    });

    test('times out when the child never drains stdin', () async {
      final script = await _script(scratch, '''
import 'dart:async';
Future<void> main() async {
  await Future<void>.delayed(const Duration(seconds: 10));
}
''');
      final signer = SubprocessC2paSigner(
        executable: Platform.resolvedExecutable,
        arguments: [script.path],
        algorithm: 'ed25519',
        timeout: const Duration(milliseconds: 100),
      );
      final stopwatch = Stopwatch()..start();

      await expectLater(
        signer.sign(Uint8List(16 * 1024 * 1024)),
        throwsA(
          isA<SubprocessSignerException>().having(
            (error) => error.message,
            'message',
            contains('timed out'),
          ),
        ),
      );
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 3)));
    });

    test(
      'escalates termination and repeatedly cleans up ignored timeouts',
      () async {
        if (Platform.isWindows) return;
        final script = await _script(scratch, '''
import 'dart:async';
import 'dart:io';
Future<void> main() async {
  ProcessSignal.sigterm.watch().listen((_) {});
  await Future<void>.delayed(const Duration(seconds: 10));
}
''');
        final stopwatch = Stopwatch()..start();
        for (var index = 0; index < 3; index++) {
          final signer = SubprocessC2paSigner(
            executable: Platform.resolvedExecutable,
            arguments: [script.path],
            algorithm: 'ed25519',
            timeout: const Duration(milliseconds: 150),
          );
          await expectLater(
            signer.sign(Uint8List(1)),
            throwsA(isA<SubprocessSignerException>()),
          );
        }
        expect(stopwatch.elapsed, lessThan(const Duration(seconds: 5)));
      },
    );
  });

  group('local OpenSSL signer', () {
    final openssl = _findExecutable('openssl');
    final algorithms = <String, ({String keyType, String? curve, int width})>{
      'es256': (keyType: 'EC', curve: 'prime256v1', width: 64),
      'es384': (keyType: 'EC', curve: 'secp384r1', width: 96),
      'es512': (keyType: 'EC', curve: 'secp521r1', width: 132),
      'ps256': (keyType: 'RSA', curve: null, width: 512),
      'ps384': (keyType: 'RSA', curve: null, width: 512),
      'ps512': (keyType: 'RSA', curve: null, width: 512),
      'ed25519': (keyType: 'ED25519', curve: null, width: 64),
    };

    for (final entry in algorithms.entries) {
      test(
        '${entry.key} signs and verifies with the expected reservation',
        () async {
          final executable = openssl!;
          final key = File('${scratch.path}/${entry.key}.pem');
          final generated = await _generateKey(
            executable,
            key,
            entry.value.keyType,
            entry.value.curve,
          );
          if (!generated) {
            markTestSkipped(
              'Installed OpenSSL does not support ${entry.value.curve ?? entry.value.keyType}',
            );
            return;
          }
          final signer = LocalKeyC2paSigner(
            keyPath: key.absolute.path,
            algorithm: entry.key,
            opensslExecutable: entry.key == 'es256' ? 'openssl' : executable,
            ed25519TemporaryRoot: entry.key == 'ed25519' ? scratch.path : null,
          );
          expect(signer.reservedSignatureSize, entry.value.width);

          final data = Uint8List.fromList(utf8.encode('C2PA signer test'));
          final signature = await signer.sign(data);
          if (entry.key.startsWith('es')) {
            expect(signature, hasLength(entry.value.width));
          } else if (entry.key == 'ed25519') {
            expect(signature, hasLength(64));
          } else {
            expect(signature, hasLength(256));
          }
          await _verify(executable, scratch, key, entry.key, data, signature);
          if (entry.key == 'ed25519') {
            expect(
              await scratch
                  .list()
                  .where(
                    (entity) => entity.path
                        .split(Platform.pathSeparator)
                        .last
                        .startsWith('.c2pa-ed25519-'),
                  )
                  .isEmpty,
              isTrue,
            );
          }
        },
        skip: openssl == null
            ? 'OpenSSL is not installed on trusted PATH'
            : false,
      );
    }

    test(
      'ed25519 uses exact pkeyutl stdin protocol without temp artifacts',
      () async {
        if (Platform.isWindows) {
          markTestSkipped('Executable Dart script fixture is POSIX-only');
          return;
        }
        final key = File('${scratch.path}/ed25519 key.pem');
        await key.writeAsString('fixture key');
        final executable = await _executableScript(scratch, '''
import 'dart:io';

Future<void> main(List<String> arguments) async {
  final expected = [
    'pkeyutl',
    '-sign',
    '-rawin',
    '-inkey',
    ${jsonEncode(key.absolute.path)},
  ];
  if (arguments.length != expected.length ||
      Iterable<int>.generate(expected.length)
          .any((index) => arguments[index] != expected[index])) {
    stderr.write('unexpected arguments: \$arguments');
    exitCode = 23;
    return;
  }
  final payload = await stdin.fold<List<int>>([], (all, chunk) => all..addAll(chunk));
  stdout.add(payload.reversed.toList());
}
''');
        final before = await _entryNames(scratch);
        final signer = LocalKeyC2paSigner(
          keyPath: key.absolute.path,
          algorithm: 'ed25519',
          opensslExecutable: executable.path,
        );

        final signature = await signer.sign(Uint8List.fromList([1, 2, 3, 4]));

        expect(signature, Uint8List.fromList([4, 3, 2, 1]));
        expect(await _entryNames(scratch), before);
      },
    );

    test('ed25519 preserves bounded timeout and error handling', () async {
      if (Platform.isWindows) {
        markTestSkipped('Executable Dart script fixture is POSIX-only');
        return;
      }
      final key = File('${scratch.path}/key.pem');
      await key.writeAsString('fixture key');
      final errorExecutable = await _executableScript(scratch, '''
import 'dart:io';
void main() {
  stderr.write('ed25519 denied');
  exitCode = 17;
}
''');
      final errorSigner = LocalKeyC2paSigner(
        keyPath: key.absolute.path,
        algorithm: 'ed25519',
        opensslExecutable: errorExecutable.path,
      );
      await expectLater(
        errorSigner.sign(Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<SubprocessSignerException>()
              .having((error) => error.message, 'message', contains('code 17'))
              .having(
                (error) => error.message,
                'message',
                contains('ed25519 denied'),
              ),
        ),
      );

      final timeoutExecutable = await _executableScript(scratch, '''
import 'dart:async';
Future<void> main() async {
  await Future<void>.delayed(const Duration(seconds: 10));
}
''');
      final timeoutSigner = LocalKeyC2paSigner(
        keyPath: key.absolute.path,
        algorithm: 'ed25519',
        opensslExecutable: timeoutExecutable.path,
        timeout: const Duration(milliseconds: 100),
      );
      final stopwatch = Stopwatch()..start();
      await expectLater(
        timeoutSigner.sign(Uint8List(16 * 1024 * 1024)),
        throwsA(
          isA<SubprocessSignerException>().having(
            (error) => error.message,
            'message',
            contains('timed out'),
          ),
        ),
      );
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 3)));
    });

    test(
      'ed25519 rejects a symlink substitution before fallback launch',
      () async {
        if (Platform.isWindows) {
          markTestSkipped('Executable Dart script fixture is POSIX-only');
          return;
        }
        final root = Directory('${scratch.path}/secure-root');
        await root.create();
        final key = File('${scratch.path}/key.pem');
        await key.writeAsString('fixture key');
        final launched = File('${scratch.path}/fallback-launched');
        final executable = await _executableScript(scratch, '''
import 'dart:io';
void main(List<String> arguments) {
  if (!arguments.contains('-in')) {
    stderr.write('unable to determine file size for oneshot operation');
    exitCode = 1;
    return;
  }
  File(${jsonEncode(launched.absolute.path)}).writeAsStringSync('launched');
  stdout.add(List<int>.filled(64, 1));
}
''');
        final replacement = File('${scratch.path}/replacement');
        await replacement.writeAsBytes([9, 9, 9]);
        final substituted = Completer<void>();
        final substituter = () async {
          final deadline = DateTime.now().add(const Duration(seconds: 5));
          while (DateTime.now().isBefore(deadline)) {
            await for (final entity in root.list()) {
              if (entity is! Directory) continue;
              final payload = File('${entity.path}/payload');
              if (await payload.exists()) {
                await payload.delete();
                await Link(payload.path).create(replacement.absolute.path);
                substituted.complete();
                return;
              }
            }
            await Future<void>.delayed(const Duration(milliseconds: 1));
          }
          substituted.completeError(StateError('payload was not created'));
        }();
        final signer = LocalKeyC2paSigner(
          keyPath: key.absolute.path,
          algorithm: 'ed25519',
          opensslExecutable: executable.path,
          ed25519TemporaryRoot: root.path,
        );

        await expectLater(
          signer.sign(Uint8List.fromList([1, 2, 3])),
          throwsA(
            isA<C2paSigningException>().having(
              (error) => error.message,
              'message',
              anyOf(
                contains('integrity verification failed'),
                contains('restrict Ed25519 temporary input permissions'),
              ),
            ),
          ),
        );
        await substituter;
        await substituted.future;
        expect(await launched.exists(), isFalse);
        final directories = (await root.list().toList())
            .whereType<Directory>()
            .toList();
        expect(directories, hasLength(1));
        expect(
          await FileSystemEntity.type(
            '${directories.single.path}/payload',
            followLinks: false,
          ),
          FileSystemEntityType.link,
        );
      },
    );

    test('ed25519 cleanup retains a replaced regular payload', () async {
      if (Platform.isWindows) {
        markTestSkipped('Executable Dart script fixture is POSIX-only');
        return;
      }
      final root = Directory('${scratch.path}/secure-root');
      await root.create();
      final key = File('${scratch.path}/key.pem');
      await key.writeAsString('fixture key');
      final executable = await _executableScript(scratch, r'''
import 'dart:io';
void main(List<String> arguments) {
  if (!arguments.contains('-in')) {
    stderr.write('unable to determine file size for oneshot operation');
    exitCode = 1;
    return;
  }
  final input = File(arguments[arguments.indexOf('-in') + 1]);
  input.writeAsBytesSync([7, 7, 7]);
  stderr.write('fallback failed');
  exitCode = 19;
}
''');
      final signer = LocalKeyC2paSigner(
        keyPath: key.absolute.path,
        algorithm: 'ed25519',
        opensslExecutable: executable.path,
        ed25519TemporaryRoot: root.path,
      );

      await expectLater(
        signer.sign(Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<SubprocessSignerException>().having(
            (error) => error.message,
            'message',
            contains('fallback failed'),
          ),
        ),
      );
      final directories = (await root.list().toList())
          .whereType<Directory>()
          .toList();
      expect(directories, hasLength(1));
      expect(await File('${directories.single.path}/payload').readAsBytes(), [
        7,
        7,
        7,
      ]);
      expect(await File('${directories.single.path}/.owner').exists(), isTrue);
    });

    test(
      'rejects relative executable paths rather than searching the cwd',
      () async {
        final signer = LocalKeyC2paSigner(
          keyPath: 'unused.pem',
          algorithm: 'es256',
          opensslExecutable: './openssl',
        );
        await expectLater(
          signer.sign(Uint8List(1)),
          throwsA(
            isA<C2paSigningException>().having(
              (error) => error.message,
              'message',
              contains('absolute path or a bare name'),
            ),
          ),
        );
      },
    );
  });

  group('Windows executable PATH resolution', () {
    String? resolve(
      String executable, {
      required String path,
      String pathExt = '.EXE;.BAT;.CMD',
      Set<String> existing = const {},
    }) {
      return resolveExecutableFromPath(
        executable: executable,
        path: path,
        isWindows: true,
        pathExt: pathExt,
        pathSeparator: '/',
        isAbsolute: (path) => path.startsWith('/'),
        exists: existing.contains,
      );
    }

    test('checks recognized suffixes as supplied, case-insensitively', () {
      expect(
        resolve(
          'openssl.exe',
          path: '/tools',
          existing: {'/tools/openssl.exe'},
        ),
        '/tools/openssl.exe',
      );
      expect(
        resolve(
          'openssl.ExE',
          path: '/tools',
          pathExt: '.exe;.cmd',
          existing: {'/tools/openssl.ExE'},
        ),
        '/tools/openssl.ExE',
      );
    });

    test('tries safe PATHEXT entries for extensionless names', () {
      expect(
        resolve(
          'openssl',
          path: '/tools',
          pathExt: '.EXE;../BAD;.CMD',
          existing: {'/tools/openssl.CMD'},
        ),
        '/tools/openssl.CMD',
      );
    });

    test('handles quoted paths and excludes empty or relative entries', () {
      expect(
        resolve(
          'openssl',
          path: '"";;relative; "/program files/tools" ',
          existing: {'/program files/tools/openssl.EXE'},
        ),
        '/program files/tools/openssl.EXE',
      );
    });

    test('returns no match when no trusted candidate exists', () {
      expect(resolve('openssl.exe', path: '"";relative;/missing'), isNull);
    });
  });
}

Future<bool> _generateKey(
  String openssl,
  File key,
  String keyType,
  String? curve,
) async {
  final arguments = ['genpkey', '-algorithm', keyType];
  if (curve != null) {
    arguments.addAll(['-pkeyopt', 'ec_paramgen_curve:$curve']);
  } else if (keyType == 'RSA') {
    arguments.addAll(['-pkeyopt', 'rsa_keygen_bits:2048']);
  }
  arguments.addAll(['-out', key.path]);
  final result = await Process.run(openssl, arguments);
  return result.exitCode == 0;
}

Future<void> _verify(
  String openssl,
  Directory scratch,
  File key,
  String algorithm,
  Uint8List data,
  Uint8List signature,
) async {
  final publicKey = File('${scratch.path}/$algorithm-public.pem');
  final dataFile = File('${scratch.path}/$algorithm-data.bin');
  final signatureFile = File('${scratch.path}/$algorithm-signature.bin');
  await dataFile.writeAsBytes(data);
  final normalizedSignature = algorithm.startsWith('es')
      ? ecdsaP1363ToDer(
          signature,
          componentLength: switch (algorithm) {
            'es256' => 32,
            'es384' => 48,
            _ => 66,
          },
        )
      : signature;
  await signatureFile.writeAsBytes(normalizedSignature);
  await _expectOpenSslSuccess(openssl, [
    'pkey',
    '-in',
    key.path,
    '-pubout',
    '-out',
    publicKey.path,
  ]);

  final arguments = switch (algorithm) {
    'ed25519' => [
      'pkeyutl',
      '-verify',
      '-rawin',
      '-pubin',
      '-inkey',
      publicKey.path,
      '-sigfile',
      signatureFile.path,
      '-in',
      dataFile.path,
    ],
    'ps256' || 'ps384' || 'ps512' => [
      'dgst',
      '-sha${algorithm.substring(2)}',
      '-verify',
      publicKey.path,
      '-signature',
      signatureFile.path,
      '-sigopt',
      'rsa_padding_mode:pss',
      '-sigopt',
      'rsa_pss_saltlen:digest',
      dataFile.path,
    ],
    _ => [
      'dgst',
      '-sha${algorithm.substring(2)}',
      '-verify',
      publicKey.path,
      '-signature',
      signatureFile.path,
      dataFile.path,
    ],
  };
  await _expectOpenSslSuccess(openssl, arguments);
}

Future<void> _expectOpenSslSuccess(
  String executable,
  List<String> arguments,
) async {
  final result = await Process.run(executable, arguments);
  expect(
    result.exitCode,
    0,
    reason: 'OpenSSL ${arguments.join(' ')} failed: ${result.stderr}',
  );
}

String? _findExecutable(String name) {
  final path = Platform.environment['PATH'];
  if (path == null) return null;
  for (final directory in path.split(Platform.isWindows ? ';' : ':')) {
    if (directory.isEmpty || !Directory(directory).isAbsolute) continue;
    final extensions = Platform.isWindows ? ['.exe', '.cmd', '.bat'] : [''];
    for (final extension in extensions) {
      final candidate = File(
        '$directory${directory.endsWith(Platform.pathSeparator) ? '' : Platform.pathSeparator}$name$extension',
      );
      if (candidate.existsSync()) return candidate.absolute.path;
    }
  }
  return null;
}

Future<File> _script(Directory scratch, String source) async {
  final file = File(
    '${scratch.path}/script-${DateTime.now().microsecondsSinceEpoch}.dart',
  );
  await file.writeAsString(source);
  return file;
}

Future<File> _executableScript(Directory scratch, String source) async {
  final file = File(
    '${scratch.path}/executable-${DateTime.now().microsecondsSinceEpoch}.dart',
  );
  await file.writeAsString('#!${Platform.resolvedExecutable}\n$source');
  final chmod = await Process.run('chmod', ['700', file.path]);
  expect(chmod.exitCode, 0, reason: '${chmod.stderr}');
  return file.absolute;
}

Future<Set<String>> _entryNames(Directory directory) async {
  return directory.list().map((entry) => entry.uri.pathSegments.last).toSet();
}

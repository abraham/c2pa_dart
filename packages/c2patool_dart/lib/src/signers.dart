import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';

final class SubprocessSignerException extends C2paSigningException {
  const SubprocessSignerException(super.message, {super.cause});
}

/// A signer subprocess using a deliberately small, shell-free protocol.
///
/// The payload is written verbatim to stdin. A successful process writes only
/// the raw signature to stdout. Diagnostics belong on stderr. The algorithm is
/// also available as `C2PA_SIGNING_ALGORITHM`.
final class SubprocessC2paSigner implements C2paReservedSizeSigner {
  SubprocessC2paSigner({
    required this.executable,
    required this.algorithm,
    this.arguments = const [],
    this.timeout = const Duration(seconds: 30),
    this.maximumSignatureBytes = 64 * 1024,
    this.maximumDiagnosticBytes = 64 * 1024,
    this.reservedSignatureSize = 0,
    this.environment = const {},
    this.workingDirectory,
  }) {
    if (executable.isEmpty) {
      throw ArgumentError.value(executable, 'executable');
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(timeout, 'timeout');
    }
    if (maximumSignatureBytes <= 0 || maximumDiagnosticBytes <= 0) {
      throw ArgumentError('Subprocess byte limits must be positive');
    }
  }

  final String executable;
  final List<String> arguments;
  @override
  final String algorithm;
  final Duration timeout;
  final int maximumSignatureBytes;
  final int maximumDiagnosticBytes;
  @override
  final int reservedSignatureSize;
  final Map<String, String> environment;
  final String? workingDirectory;

  @override
  Future<Uint8List> sign(Uint8List data) async {
    Process process;
    try {
      process = await Process.start(
        executable,
        arguments,
        workingDirectory: workingDirectory,
        environment: {...environment, 'C2PA_SIGNING_ALGORITHM': algorithm},
        includeParentEnvironment: true,
        runInShell: false,
      );
    } on Object catch (error) {
      throw SubprocessSignerException(
        'Unable to start signer process',
        cause: error,
      );
    }

    final stdoutRead = _readBounded(
      process.stdout,
      maximumSignatureBytes,
      'signature',
    );
    final stderrRead = _readBounded(
      process.stderr,
      maximumDiagnosticBytes,
      'diagnostic',
    );
    var exited = false;
    final exitCode = process.exitCode.then((code) {
      exited = true;
      return code;
    });
    var succeeded = false;
    try {
      final results = await Future.wait<dynamic>([
        Future<void>.sync(() {
          process.stdin.add(data);
          return process.stdin.close();
        }),
        exitCode,
        stdoutRead.result,
        stderrRead.result,
      ], eagerError: true).timeout(timeout);
      final code = results[1] as int;
      final signature = results[2] as Uint8List;
      final diagnostic = results[3] as Uint8List;
      if (code != 0) {
        throw SubprocessSignerException(
          'Signer process exited with code $code'
          '${diagnostic.isEmpty ? '' : ': ${String.fromCharCodes(diagnostic)}'}',
        );
      }
      if (signature.isEmpty) {
        throw const SubprocessSignerException(
          'Signer process returned an empty signature',
        );
      }
      succeeded = true;
      return signature;
    } on SubprocessSignerException {
      rethrow;
    } on TimeoutException catch (error) {
      throw SubprocessSignerException('Signer process timed out', cause: error);
    } on Object catch (error) {
      throw SubprocessSignerException('Signer process failed', cause: error);
    } finally {
      if (!succeeded && !exited) {
        await _terminate(process, exitCode, () => exited);
      }
      await _boundedCleanup(process.stdin.close);
      await Future.wait<void>([
        _boundedCleanup(stdoutRead.subscription.cancel),
        _boundedCleanup(stderrRead.subscription.cancel),
      ]);
      if (!exited) {
        await _terminate(process, exitCode, () => exited);
      }
    }
  }

  static _BoundedRead _readBounded(
    Stream<List<int>> stream,
    int maximum,
    String name,
  ) {
    final bytes = BytesBuilder(copy: false);
    final result = Completer<Uint8List>();
    // The caller owns and cancels this subscription in its finally block.
    // ignore: cancel_subscriptions
    late final StreamSubscription<List<int>> subscription;
    subscription = stream.listen(
      (chunk) {
        if (result.isCompleted) return;
        if (bytes.length + chunk.length > maximum) {
          result.completeError(
            SubprocessSignerException(
              'Signer $name exceeds the $maximum byte limit',
            ),
          );
          return;
        }
        bytes.add(chunk);
      },
      onError: (Object error, StackTrace stackTrace) {
        if (!result.isCompleted) result.completeError(error, stackTrace);
      },
      onDone: () {
        if (!result.isCompleted) result.complete(bytes.takeBytes());
      },
      cancelOnError: false,
    );
    return _BoundedRead(subscription, result.future);
  }

  static Future<void> _terminate(
    Process process,
    Future<int> exitCode,
    bool Function() hasExited,
  ) async {
    if (hasExited()) return;
    process.kill(ProcessSignal.sigterm);
    try {
      await exitCode.timeout(const Duration(milliseconds: 250));
      return;
    } on TimeoutException {
      if (!hasExited()) {
        process.kill(ProcessSignal.sigkill);
      }
    }
    try {
      await exitCode.timeout(const Duration(milliseconds: 750));
    } on TimeoutException {
      // The OS still owns the process, but cleanup remains strictly bounded.
    }
  }

  static Future<void> _boundedCleanup(Future<void> Function() cleanup) async {
    try {
      await cleanup().timeout(const Duration(milliseconds: 250));
    } on Object {
      // Preserve the operation's result while ensuring cleanup cannot hang it.
    }
  }
}

final class _BoundedRead {
  const _BoundedRead(this.subscription, this.result);

  final StreamSubscription<List<int>> subscription;
  final Future<Uint8List> result;
}

final class _SecureEd25519Input {
  const _SecureEd25519Input({
    required this.directory,
    required this.marker,
    required this.payload,
    required this.markerBytes,
    required this.payloadBytes,
  });

  final Directory directory;
  final File marker;
  final File payload;
  final Uint8List markerBytes;
  final Uint8List payloadBytes;

  Future<void> verify() async {
    if (await FileSystemEntity.type(directory.path, followLinks: false) !=
        FileSystemEntityType.directory) {
      throw const C2paSigningException(
        'Ed25519 temporary directory was replaced',
      );
    }
    final directoryStat = await FileStat.stat(directory.path);
    if (!Platform.isWindows && directoryStat.mode & 0x3f != 0) {
      throw const C2paSigningException(
        'Ed25519 temporary directory is not owner-only',
      );
    }
    if (!await _matchesRegularFile(marker, markerBytes) ||
        !await _matchesRegularFile(payload, payloadBytes)) {
      throw const C2paSigningException(
        'Ed25519 temporary input integrity verification failed',
      );
    }
  }

  Future<void> cleanup() async {
    try {
      if (await FileSystemEntity.type(directory.path, followLinks: false) !=
          FileSystemEntityType.directory) {
        return;
      }
      if (!await _matchesRegularFile(marker, markerBytes)) return;

      final payloadType = await FileSystemEntity.type(
        payload.path,
        followLinks: false,
      );
      if (payloadType != FileSystemEntityType.notFound) {
        if (!await _matchesRegularFile(payload, payloadBytes)) return;
        await payload.delete();
      }

      if (!await _matchesRegularFile(marker, markerBytes)) return;
      await marker.delete();
      if (await FileSystemEntity.type(directory.path, followLinks: false) !=
          FileSystemEntityType.directory) {
        return;
      }
      if (await directory.list(followLinks: false).isEmpty) {
        await directory.delete();
      }
    } on FileSystemException {
      // Cleanup must never delete a path after its ownership checks fail.
    }
  }

  static Future<bool> _matchesRegularFile(File file, Uint8List expected) async {
    if (await FileSystemEntity.type(file.path, followLinks: false) !=
        FileSystemEntityType.file) {
      return false;
    }
    final before = await FileStat.stat(file.path);
    if (!Platform.isWindows && before.mode & 0x3f != 0) return false;
    final actual = await file.readAsBytes();
    if (actual.length != expected.length) return false;
    var difference = 0;
    for (var index = 0; index < actual.length; index++) {
      difference |= actual[index] ^ expected[index];
    }
    if (difference != 0) return false;
    if (await FileSystemEntity.type(file.path, followLinks: false) !=
        FileSystemEntityType.file) {
      return false;
    }
    final after = await FileStat.stat(file.path);
    return before.size == after.size &&
        before.modified == after.modified &&
        before.changed == after.changed &&
        before.mode == after.mode;
  }
}

String? resolveExecutableFromPath({
  required String executable,
  required String? path,
  required bool isWindows,
  required String? pathExt,
  required String pathSeparator,
  required bool Function(String path) isAbsolute,
  required bool Function(String path) exists,
}) {
  if (path == null) return null;
  final extensions = isWindows
      ? _windowsExecutableExtensions(pathExt)
      : const <String>[''];
  final hasRecognizedExtension =
      isWindows &&
      extensions.any(
        (extension) =>
            executable.toLowerCase().endsWith(extension.toLowerCase()),
      );
  final candidateExtensions = hasRecognizedExtension
      ? const <String>['']
      : extensions;
  for (var directory in path.split(isWindows ? ';' : ':')) {
    if (isWindows) {
      directory = directory.trim();
      if (directory.length >= 2 &&
          directory.startsWith('"') &&
          directory.endsWith('"')) {
        directory = directory.substring(1, directory.length - 1);
      }
    }
    if (directory.isEmpty || !isAbsolute(directory)) continue;
    final prefix = directory.endsWith(pathSeparator)
        ? directory
        : '$directory$pathSeparator';
    for (final extension in candidateExtensions) {
      final candidate = '$prefix$executable$extension';
      if (exists(candidate)) return candidate;
    }
  }
  return null;
}

List<String> _windowsExecutableExtensions(String? pathExt) {
  return (pathExt ?? '.EXE;.BAT;.CMD')
      .split(';')
      .map((value) => value.trim())
      .where(
        (value) =>
            value.length > 1 &&
            value.startsWith('.') &&
            !value.substring(1).contains(RegExp(r'[./\\:]')),
      )
      .toList(growable: false);
}

/// Signs with a local PEM/DER private key by invoking OpenSSL without a shell.
///
/// The key is passed to OpenSSL by path and is never loaded into Dart memory.
/// [opensslExecutable] must be an absolute path or a bare executable name. Bare
/// names are resolved only in absolute `PATH` entries; empty and relative
/// entries are ignored so the current directory is never searched implicitly.
final class LocalKeyC2paSigner implements C2paReservedSizeSigner {
  LocalKeyC2paSigner({
    required this.keyPath,
    required this.algorithm,
    this.opensslExecutable = 'openssl',
    this.timeout = const Duration(seconds: 30),
    this.ed25519TemporaryRoot,
    int? reservedSignatureSize,
  }) : reservedSignatureSize =
           reservedSignatureSize ?? _defaultSignatureSize(algorithm);

  final String keyPath;
  @override
  final String algorithm;
  final String opensslExecutable;
  final Duration timeout;
  final String? ed25519TemporaryRoot;
  @override
  final int reservedSignatureSize;

  @override
  Future<Uint8List> sign(Uint8List data) async {
    final normalized = algorithm.toLowerCase().replaceAll(RegExp(r'[-_]'), '');
    final executable = _resolveExecutable(opensslExecutable);
    if (normalized == 'ed25519' || normalized == 'eddsa') {
      return _signEd25519(executable, data);
    }
    final args = switch (normalized) {
      'es256' => ['dgst', '-sha256', '-sign', keyPath],
      'es384' => ['dgst', '-sha384', '-sign', keyPath],
      'es512' => ['dgst', '-sha512', '-sign', keyPath],
      'ps256' => _rsaArgs('sha256'),
      'ps384' => _rsaArgs('sha384'),
      'ps512' => _rsaArgs('sha512'),
      _ => throw C2paSigningException(
        'Unsupported local-key algorithm: $algorithm',
      ),
    };
    final signer = SubprocessC2paSigner(
      executable: executable,
      arguments: args,
      algorithm: algorithm,
      timeout: timeout,
      reservedSignatureSize: reservedSignatureSize,
    );
    final signature = await signer.sign(data);
    if (normalized.startsWith('es')) {
      return Uint8List.fromList(
        ecdsaDerToP1363(
          signature,
          componentLength: switch (normalized) {
            'es256' => 32,
            'es384' => 48,
            _ => 66,
          },
        ),
      );
    }
    return signature;
  }

  Future<Uint8List> _signEd25519(String executable, Uint8List data) async {
    try {
      return await _ed25519Signer(executable).sign(data);
    } on SubprocessSignerException catch (error) {
      if (!error.message.toLowerCase().contains(
        'unable to determine file size for oneshot operation',
      )) {
        rethrow;
      }
    }

    final input = await _createSecureEd25519Input(data);
    try {
      await input.verify();
      return await SubprocessC2paSigner(
        executable: executable,
        arguments: [
          'pkeyutl',
          '-sign',
          '-rawin',
          '-inkey',
          keyPath,
          '-in',
          input.payload.path,
        ],
        algorithm: algorithm,
        timeout: timeout,
        reservedSignatureSize: reservedSignatureSize,
      ).sign(Uint8List(0));
    } finally {
      await input.cleanup();
    }
  }

  SubprocessC2paSigner _ed25519Signer(String executable) {
    return SubprocessC2paSigner(
      executable: executable,
      arguments: ['pkeyutl', '-sign', '-rawin', '-inkey', keyPath],
      algorithm: algorithm,
      timeout: timeout,
      reservedSignatureSize: reservedSignatureSize,
    );
  }

  Future<_SecureEd25519Input> _createSecureEd25519Input(Uint8List data) async {
    final root = Directory(ed25519TemporaryRoot ?? Directory.systemTemp.path)
        .absolute;
    final rootStat = await FileStat.stat(root.path);
    if (rootStat.type != FileSystemEntityType.directory ||
        await FileSystemEntity.isLink(root.path)) {
      throw C2paSigningException(
        'Ed25519 temporary root must be an existing, non-symlink directory',
      );
    }

    final random = Random.secure();
    for (var attempt = 0; attempt < 10; attempt++) {
      final tokenBytes = List<int>.generate(32, (_) => random.nextInt(256));
      final token = tokenBytes
          .map((value) => value.toRadixString(16).padLeft(2, '0'))
          .join();
      final directory = Directory(
        '${root.path}${Platform.pathSeparator}.c2pa-ed25519-$token',
      );
      if (await FileSystemEntity.type(directory.path, followLinks: false) !=
          FileSystemEntityType.notFound) {
        continue;
      }

      final marker = File('${directory.path}${Platform.pathSeparator}.owner');
      final payload = File('${directory.path}${Platform.pathSeparator}payload');
      final markerBytes = Uint8List.fromList(utf8.encode(token));
      final payloadBytes = Uint8List.fromList(data);
      try {
        if (!await _createPrivateDirectory(directory)) continue;
        await _writeExclusive(marker, markerBytes);
        await _writeExclusive(payload, payloadBytes);
        final input = _SecureEd25519Input(
          directory: directory,
          marker: marker,
          payload: payload,
          markerBytes: markerBytes,
          payloadBytes: payloadBytes,
        );
        await input.verify();
        return input;
      } on Object {
        await _SecureEd25519Input(
          directory: directory,
          marker: marker,
          payload: payload,
          markerBytes: markerBytes,
          payloadBytes: payloadBytes,
        ).cleanup();
        rethrow;
      }
    }
    throw const C2paSigningException(
      'Unable to create a private Ed25519 input directory',
    );
  }

  static Future<bool> _createPrivateDirectory(Directory directory) async {
    if (!Platform.isWindows) {
      final mkdir = File('/bin/mkdir').existsSync()
          ? '/bin/mkdir'
          : '/usr/bin/mkdir';
      if (File(mkdir).existsSync()) {
        final result = await Process.run(mkdir, ['-m', '700', directory.path]);
        return result.exitCode == 0;
      }
    }
    if (await FileSystemEntity.type(directory.path, followLinks: false) !=
        FileSystemEntityType.notFound) {
      return false;
    }
    await directory.create();
    await _makeOwnerOnly(directory.path, directory: true);
    return true;
  }

  static Future<void> _writeExclusive(File file, Uint8List contents) async {
    await file.create(exclusive: true);
    final output = await file.open(mode: FileMode.writeOnly);
    try {
      await output.writeFrom(contents);
      await output.flush();
    } finally {
      await output.close();
    }
    await _makeOwnerOnly(file.path, directory: false);
  }

  static Future<void> _makeOwnerOnly(
    String path, {
    required bool directory,
  }) async {
    if (Platform.isWindows) return;
    final chmod = File('/bin/chmod').existsSync()
        ? '/bin/chmod'
        : '/usr/bin/chmod';
    if (!File(chmod).existsSync()) return;
    final result = await Process.run(chmod, [directory ? '700' : '600', path]);
    if (result.exitCode != 0) {
      throw C2paSigningException(
        'Unable to restrict Ed25519 temporary input permissions',
      );
    }
  }

  List<String> _rsaArgs(String digest) => [
    'dgst',
    '-$digest',
    '-sign',
    keyPath,
    '-sigopt',
    'rsa_padding_mode:pss',
    '-sigopt',
    'rsa_pss_saltlen:digest',
  ];

  static int _defaultSignatureSize(String algorithm) {
    return switch (algorithm.toLowerCase().replaceAll(RegExp(r'[-_]'), '')) {
      'ed25519' || 'eddsa' || 'es256' => 64,
      'es384' => 96,
      'es512' => 132,
      'ps256' || 'ps384' || 'ps512' => 512,
      _ => 0,
    };
  }

  static String _resolveExecutable(String executable) {
    final file = File(executable);
    if (file.isAbsolute) {
      if (!file.existsSync()) {
        throw C2paSigningException(
          'OpenSSL executable does not exist: $executable',
        );
      }
      return file.path;
    }
    if (executable.contains('/') || executable.contains(r'\')) {
      throw C2paSigningException(
        'OpenSSL executable must be an absolute path or a bare name',
      );
    }
    final resolved = resolveExecutableFromPath(
      executable: executable,
      path: Platform.environment['PATH'],
      isWindows: Platform.isWindows,
      pathExt: Platform.environment['PATHEXT'],
      pathSeparator: Platform.pathSeparator,
      isAbsolute: (path) => Directory(path).isAbsolute,
      exists: (path) => File(path).existsSync(),
    );
    if (resolved != null) return resolved;
    throw C2paSigningException(
      'Unable to resolve OpenSSL executable "$executable" from absolute PATH entries',
    );
  }
}

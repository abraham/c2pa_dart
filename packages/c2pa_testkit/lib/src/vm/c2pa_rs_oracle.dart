import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../fixture_asset.dart';

const _assetPlaceholder = '{asset}';
const _jsonPlaceholder = '{json}';
const _crJsonPlaceholder = '{crjson}';

/// A VM-only command line for invoking a pinned c2pa-rs oracle binary.
///
/// The executable is supplied by the caller; use an absolute path or a name
/// resolvable on `PATH` for the current VM process.
final class C2paRsOracleCommand {
  /// Creates an oracle command with immutable arguments and environment.
  ///
  /// Throws [ArgumentError] when [executable] or [pinnedVersion] is blank.
  C2paRsOracleCommand({
    required this.executable,
    required Iterable<String> arguments,
    required this.pinnedVersion,
    Map<String, String> environment = const {},
  }) : arguments = List.unmodifiable(arguments),
       environment = Map.unmodifiable(environment) {
    if (executable.trim().isEmpty || pinnedVersion.trim().isEmpty) {
      throw ArgumentError('Executable and pinnedVersion must be non-empty.');
    }
  }

  /// The c2patool or c2pa-rs executable passed to `Process.start`.
  final String executable;

  /// Command arguments, optionally containing oracle file placeholders.
  ///
  /// The oracle replaces `{asset}`, `{json}`, and `{crjson}` before launch.
  final List<String> arguments;

  /// Human-readable version label recorded with every oracle result.
  final String pinnedVersion;

  /// Extra environment variables for the subprocess.
  ///
  /// Parent environment variables are still included by the oracle runner.
  final Map<String, String> environment;
}

/// Captured output from one VM-only c2pa-rs oracle invocation.
final class C2paRsOracleResult {
  /// Creates an immutable oracle result for a completed subprocess.
  const C2paRsOracleResult({
    required this.commandVersion,
    required this.exitCode,
    required this.json,
    required this.crJson,
    required this.jsonText,
    required this.crJsonText,
    required this.stdout,
    required this.stderr,
  });

  /// Version label copied from the pinned oracle command.
  final String commandVersion;

  /// Subprocess exit code, including nonzero codes that still wrote JSON.
  final int exitCode;

  /// Decoded JSON report emitted by the oracle.
  final Object? json;

  /// Decoded crJSON report, or `null` when no crJSON file was emitted.
  final Object? crJson;

  /// Raw JSON report text used for diagnostics and golden updates.
  final String jsonText;

  /// Raw crJSON report text, or `null` when the oracle did not write one.
  final String? crJsonText;

  /// UTF-8 stdout captured from the subprocess.
  final String stdout;

  /// UTF-8 stderr captured from the subprocess.
  final String stderr;
}

/// Base class for VM-only oracle subprocess failures.
sealed class C2paRsOracleException implements Exception {
  /// Creates an oracle exception with a diagnostic [message].
  const C2paRsOracleException(this.message);

  /// Human-readable explanation suitable for failed conformance tests.
  final String message;

  /// Formats the exception type and [message] for test failure output.
  @override
  String toString() => '$runtimeType: $message';
}

/// A timeout while waiting for the VM-only oracle subprocess.
final class C2paRsOracleTimeoutException extends C2paRsOracleException {
  /// Creates a timeout failure for the configured [timeout].
  const C2paRsOracleTimeoutException(Duration timeout)
    : super('Oracle process exceeded timeout of $timeout.');
}

/// An oracle failure caused by stdout, stderr, or report size limits.
final class C2paRsOracleOutputException extends C2paRsOracleException {
  /// Creates an output-limit failure for [limit] bytes.
  const C2paRsOracleOutputException(int limit)
    : super('Oracle output exceeded the $limit byte limit.');
}

/// An oracle failure caused by non-UTF-8 or malformed JSON output.
final class C2paRsOracleFormatException extends C2paRsOracleException {
  /// Creates a format failure with a parser diagnostic [message].
  const C2paRsOracleFormatException(super.message);
}

/// Runs an explicitly configured, version-pinned c2pa-rs command.
///
/// Arguments may contain `{asset}`, `{json}`, and `{crjson}` placeholders.
/// The adapter writes all transient files beneath caller-owned
/// [scratchDirectory] and removes each invocation directory after completion.
///
/// This helper is VM-only, shells out to c2patool or a c2pa-rs test binary,
/// and is not safe for web tests. Missing binaries surface from
/// `Process.start`, typically as a [ProcessException].
final class C2paRsOracle {
  /// Creates a VM-only oracle runner with bounded runtime and output.
  ///
  /// [scratchDirectory] must be absolute and is created as needed.
  C2paRsOracle({
    required this.command,
    required Directory scratchDirectory,
    this.timeout = const Duration(seconds: 10),
    this.maxOutputBytes = 1024 * 1024,
  }) : scratchDirectory = scratchDirectory.absolute {
    if (!Uri.file(scratchDirectory.path).isAbsolute) {
      throw ArgumentError.value(
        scratchDirectory.path,
        'scratchDirectory',
        'must be absolute',
      );
    }
    if (timeout <= Duration.zero) {
      throw ArgumentError.value(timeout, 'timeout', 'must be positive');
    }
    if (maxOutputBytes < 1) {
      throw ArgumentError.value(
        maxOutputBytes,
        'maxOutputBytes',
        'must be positive',
      );
    }
  }

  /// The external c2patool or c2pa-rs command to run for each asset.
  final C2paRsOracleCommand command;

  /// Absolute directory used for per-invocation asset and report files.
  final Directory scratchDirectory;

  /// Maximum wall-clock time allowed for one oracle subprocess.
  final Duration timeout;

  /// Combined byte limit for stdout, stderr, JSON, and crJSON output.
  final int maxOutputBytes;

  static int _runSequence = 0;

  /// Inspects [asset] by writing it to disk and launching the oracle command.
  ///
  /// Throws [C2paRsOracleTimeoutException] on timeout,
  /// [C2paRsOracleOutputException] when output exceeds [maxOutputBytes],
  /// [C2paRsOracleFormatException] for invalid text or JSON, and
  /// [ProcessException] when the executable cannot be started.
  Future<C2paRsOracleResult> inspect(FixtureAsset asset) async {
    await scratchDirectory.create(recursive: true);
    final runDirectory = Directory.fromUri(
      scratchDirectory.uri.resolve(
        'run-$pid-${DateTime.now().microsecondsSinceEpoch}-'
        '${_runSequence++}/',
      ),
    );
    await runDirectory.create();

    try {
      final assetFile = File.fromUri(
        runDirectory.uri.resolve('asset${_safeExtension(asset.name)}'),
      );
      final jsonFile = File.fromUri(runDirectory.uri.resolve('report.json'));
      final crJsonFile = File.fromUri(
        runDirectory.uri.resolve('report.cr.json'),
      );
      await assetFile.writeAsBytes(asset.bytes, flush: true);

      final replacements = <String, String>{
        _assetPlaceholder: assetFile.path,
        _jsonPlaceholder: jsonFile.path,
        _crJsonPlaceholder: crJsonFile.path,
      };
      String replacePlaceholders(String argument) {
        var result = argument;
        for (final replacement in replacements.entries) {
          result = result.replaceAll(replacement.key, replacement.value);
        }
        return result;
      }

      final process = await Process.start(
        command.executable,
        command.arguments.map(replacePlaceholders).toList(growable: false),
        workingDirectory: runDirectory.path,
        environment: command.environment,
        includeParentEnvironment: true,
        runInShell: false,
      );

      var capturedBytes = 0;
      var outputExceeded = false;
      final stdoutBytes = BytesBuilder(copy: false);
      final stderrBytes = BytesBuilder(copy: false);

      Future<void> capture(Stream<List<int>> stream, BytesBuilder target) =>
          stream.forEach((chunk) {
            capturedBytes += chunk.length;
            if (capturedBytes > maxOutputBytes) {
              outputExceeded = true;
              process.kill();
              return;
            }
            target.add(chunk);
          });

      final stdoutDone = capture(process.stdout, stdoutBytes);
      final stderrDone = capture(process.stderr, stderrBytes);
      final exitFuture = process.exitCode;
      late final int exitCode;
      var timedOut = false;
      try {
        exitCode = await exitFuture.timeout(timeout);
      } on TimeoutException {
        timedOut = true;
        process.kill();
        exitCode = await exitFuture;
      }
      await Future.wait([stdoutDone, stderrDone]);

      if (timedOut) throw C2paRsOracleTimeoutException(timeout);
      if (outputExceeded) {
        throw C2paRsOracleOutputException(maxOutputBytes);
      }

      late final String stdout;
      late final String stderr;
      try {
        stdout = utf8.decode(stdoutBytes.takeBytes());
        stderr = utf8.decode(stderrBytes.takeBytes());
      } on FormatException catch (error) {
        throw C2paRsOracleFormatException(
          'Oracle emitted non-UTF-8 process output: ${error.message}',
        );
      }
      final hasJsonFile = await jsonFile.exists();
      final hasCrJsonFile = await crJsonFile.exists();
      final fileOutputBytes =
          (hasJsonFile ? await jsonFile.length() : 0) +
          (hasCrJsonFile ? await crJsonFile.length() : 0);
      if (capturedBytes + fileOutputBytes > maxOutputBytes) {
        throw C2paRsOracleOutputException(maxOutputBytes);
      }
      final jsonText = hasJsonFile
          ? await jsonFile.readAsString()
          : stdout.trim();
      if (jsonText.isEmpty) {
        throw const C2paRsOracleFormatException(
          'Oracle did not emit a JSON report.',
        );
      }
      final crJsonText = hasCrJsonFile ? await crJsonFile.readAsString() : null;

      return C2paRsOracleResult(
        commandVersion: command.pinnedVersion,
        exitCode: exitCode,
        json: _decodeReport(jsonText, 'JSON'),
        crJson: crJsonText == null ? null : _decodeReport(crJsonText, 'crJSON'),
        jsonText: jsonText,
        crJsonText: crJsonText,
        stdout: stdout,
        stderr: stderr,
      );
    } finally {
      if (await runDirectory.exists()) {
        await runDirectory.delete(recursive: true);
      }
    }
  }

  static Object? _decodeReport(String source, String kind) {
    try {
      return jsonDecode(source);
    } on FormatException catch (error) {
      throw C2paRsOracleFormatException(
        'Oracle emitted malformed $kind: ${error.message}',
      );
    }
  }

  String _safeExtension(String name) {
    final fileName = name.replaceAll(r'\', '/').split('/').last;
    final dot = fileName.lastIndexOf('.');
    if (dot <= 0) return '.bin';
    final extension = fileName.substring(dot);
    return RegExp(r'^\.[A-Za-z0-9]{1,10}$').hasMatch(extension)
        ? extension.toLowerCase()
        : '.bin';
  }
}

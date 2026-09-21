import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:c2pa/c2pa.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:c2pa_io/c2pa_io_vm.dart';

import 'signers.dart';

part 'cli/archive_load.dart';
part 'cli/archive_save.dart';
part 'cli/base.dart';
part 'cli/extract.dart';
part 'cli/fragment_inspect.dart';
part 'cli/fragment_sign.dart';
part 'cli/inspect.dart';
part 'cli/remote.dart';
part 'cli/remove.dart';
part 'cli/replace.dart';
part 'cli/sign.dart';
part 'cli/validate.dart';

/// Development version string reported by the command-line interface.
const c2patoolVersion = '0.1.0-dev.1';

/// Process exit codes used by `c2patool_dart`.
abstract final class CliExitCode {
  /// Exit code for successful command completion.
  static const success = 0;

  /// Exit code for validation or parsing failures in C2PA content.
  static const validation = 65;

  /// Exit code for policy failures, such as blocked network access.
  static const policy = 77;

  /// Exit code for invalid command-line arguments or option combinations.
  static const usage = 64;

  /// Exit code for file, network, or generic I/O failures.
  static const io = 74;

  /// Exit code for signing failures.
  static const signing = 75;
}

/// Result produced by running a CLI command in-process.
final class CliResult {
  /// Creates a command result with buffered [stdout] and [stderr] text.
  const CliResult(this.exitCode, {this.stdout = '', this.stderr = ''});

  /// Process exit code that should be returned to the caller.
  final int exitCode;

  /// Text to write to standard output.
  final String stdout;

  /// Text to write to standard error.
  final String stderr;
}

/// Runs `c2patool_dart` with [arguments] and writes buffered output to sinks.
Future<int> runC2paCli(
  List<String> arguments, {
  IOSink? stdoutSink,
  IOSink? stderrSink,
}) async {
  // The process-owned sinks must remain open after this command returns.
  // ignore: close_sinks
  final out = stdoutSink ?? stdout;
  // ignore: close_sinks
  final err = stderrSink ?? stderr;
  final result = await C2paCli().run(arguments);
  if (result.stdout.isNotEmpty) out.write(result.stdout);
  if (result.stderr.isNotEmpty) err.write(result.stderr);
  return result.exitCode;
}

/// In-process implementation of the `c2patool_dart` command-line interface.
final class C2paCli extends CommandRunner<CliResult> {
  /// Creates a CLI runner, optionally observing each input path as it opens.
  C2paCli({this.onInputOpened})
    : super('c2patool', 'c2patool_dart $c2patoolVersion') {
    argParser.addFlag('version', negatable: false);
    addCommand(_InspectCommand());
    addCommand(_ValidateCommand());
    addCommand(_ExtractCommand());
    addCommand(_SignCommand());
    addCommand(_ArchiveSaveCommand());
    addCommand(_ArchiveLoadCommand());
    addCommand(_RemoveCommand());
    addCommand(_ReplaceCommand());
    addCommand(_RemoteCommand());
    addCommand(_FragmentSignCommand());
    addCommand(_FragmentInspectCommand());
  }

  /// Optional callback invoked after each input file is opened.
  final Future<void> Function(String path)? onInputOpened;

  /// Parses and executes [args], returning buffered output and exit code.
  @override
  Future<CliResult> run(Iterable<String> args) async {
    ArgResults options;
    try {
      options = parse(args);
    } on UsageException catch (error) {
      return _usage(error.message);
    }
    if (options['version'] as bool) {
      return const CliResult(
        CliExitCode.success,
        stdout: 'c2patool_dart $c2patoolVersion\n',
      );
    }
    if (options['help'] as bool) {
      return CliResult(CliExitCode.success, stdout: _help());
    }
    if (options.command == null) {
      // `ArgParser` leaves an unrecognised leading word in `rest` rather than
      // reporting it, so distinguish the two cases the user can hit here.
      final rest = options.rest;
      return _usage(
        rest.isEmpty
            ? 'A command is required'
            : 'Could not find a command named "${rest.first}".',
      );
    }
    if (options.command!['help'] as bool) {
      return CliResult(
        CliExitCode.success,
        stdout: _commandHelp(options.command!.name!),
      );
    }
    if (options.command!.name == 'help') {
      final rest = options.command!.rest;
      if (rest.isEmpty) {
        return CliResult(CliExitCode.success, stdout: _help());
      }
      if (rest.length == 1) {
        final command = commands[rest.single];
        if (command != null && !command.hidden) {
          return CliResult(
            CliExitCode.success,
            stdout: _commandHelp(rest.single),
          );
        }
      }
      return _usage('Could not find a command named "${rest.first}".');
    }
    try {
      return await runCommand(options) ?? _usage('A command is required');
    } on UsageException catch (error) {
      return _usage(error.message);
    } on _CliUsageException catch (error) {
      return _usage(error.message);
    } on C2paUriPolicyException catch (error) {
      return _error(CliExitCode.policy, error.message);
    } on C2paNetworkException catch (error) {
      return _error(CliExitCode.policy, error.message);
    } on C2paValidationException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on C2paParseException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on C2paSigningException catch (error) {
      return _error(CliExitCode.signing, error.message);
    } on FileSystemException catch (error) {
      return _error(CliExitCode.io, error.message);
    } on C2paException catch (error) {
      return _error(CliExitCode.io, error.message);
    } on FormatException catch (error) {
      return _error(CliExitCode.validation, error.message);
    } on Object catch (error) {
      return _error(CliExitCode.io, error.toString());
    }
  }

  CliResult _usage(String message) => CliResult(
    CliExitCode.usage,
    stderr: 'Usage error: $message\n\n${_help()}',
  );

  /// Generated from registered commands so the table cannot drift.
  String _help() =>
      'c2patool_dart $c2patoolVersion\n\n'
      'Usage: c2patool <command> [options]\n\n'
      'Commands:\n'
      '${commands.values.where((c) => !c.hidden).map((c) => '  ${c.name.padRight(18)}${c.description}\n').join()}'
      '\n${argParser.usage}\n';

  String _commandHelp(String name) =>
      'Usage: c2patool $name [options]\n\n'
      '${commands[name]!.argParser.usage}\n';
}

final class _CliUsageException implements Exception {
  const _CliUsageException(this.message);
  final String message;
}

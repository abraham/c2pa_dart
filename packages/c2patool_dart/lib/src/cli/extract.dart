part of '../cli.dart';

final class _ExtractCommand extends _C2paCommand {
  _ExtractCommand() {
    _addReaderOptions(argParser);
    argParser
      ..addOption('manifest-output')
      ..addOption('resources');
  }

  @override
  String get name => 'extract';

  @override
  String get description => 'Extract a manifest store and resources';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 1, '<asset>');
    final manifestOutput = options['manifest-output'] as String?;
    final resourceDirectory = options['resources'] as String?;
    if (manifestOutput == null && resourceDirectory == null) {
      throw const _CliUsageException(
        'extract requires --manifest-output and/or --resources',
      );
    }
    final reader = await _readAsset(options.rest.single, options);
    final resourceOutputs = <File>[];
    if (resourceDirectory != null) {
      final directory = Directory(resourceDirectory);
      for (var index = 0; index < reader.resources.length; index++) {
        final resource = reader.resources[index];
        resourceOutputs.add(
          _containedOutput(
            directory,
            _safeResourceName(resource.name ?? resource.label, index),
          ),
        );
      }
    }
    await _validateOutputs(
      options,
      files: [?manifestOutput, ...resourceOutputs.map((file) => file.path)],
      directories: [?resourceDirectory],
      inputs: [options.rest.single, ?options['manifest'] as String?],
    );
    if (manifestOutput != null) {
      await _atomicWrite(
        manifestOutput,
        reader.manifestBytes,
        overwrite: options['force'] as bool,
      );
    }
    if (resourceDirectory != null) {
      final directory = Directory(resourceDirectory);
      await directory.create(recursive: true);
      for (var index = 0; index < reader.resources.length; index++) {
        await _atomicWrite(
          resourceOutputs[index].path,
          reader.resources[index].bytes,
          overwrite: options['force'] as bool,
        );
      }
    }
    return const CliResult(CliExitCode.success);
  }
}

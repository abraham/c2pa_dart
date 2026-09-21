part of '../cli.dart';

final class _RemoveCommand extends _C2paCommand {
  _RemoveCommand() {
    _addMutationOptions(argParser);
  }

  @override
  String get name => 'remove';

  @override
  String get description => 'Remove an embedded manifest';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 1, '<asset>');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [options.rest.single],
    );
    final source = await _openSource(options.rest.single, options);
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await AssetHandlerRegistry().removeManifest(
        source,
        sink,
        mimeType: options['mime-type'] as String?,
        fileExtension: _extension(options.rest.single),
      );
      await sink.close();
    } on Object {
      await sink.abort();
      rethrow;
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }
}

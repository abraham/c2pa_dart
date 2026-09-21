part of '../cli.dart';

final class _ReplaceCommand extends _C2paCommand {
  _ReplaceCommand() {
    _addMutationOptions(argParser);
    argParser
      ..addOption('manifest')
      ..addOption('max-manifest-bytes', defaultsTo: '${64 * 1024 * 1024}');
  }

  @override
  String get name => 'replace';

  @override
  String get description => 'Replace an embedded manifest';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 1, '<asset>');
    final manifestPath = _requiredOption(options, 'manifest');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [options.rest.single, manifestPath],
    );
    final manifest = await _readBoundedFile(
      manifestPath,
      _integer(options, 'max-manifest-bytes'),
    );
    final source = await _openSource(options.rest.single, options);
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await AssetHandlerRegistry().replaceManifest(
        source,
        manifest,
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

part of '../cli.dart';

final class _ArchiveSaveCommand extends _C2paCommand {
  _ArchiveSaveCommand() {
    _addDefinitionOptions(argParser);
    argParser
      ..addOption('output', abbr: 'o')
      ..addOption('base-path')
      ..addOption('remote-url')
      ..addFlag('no-embed', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace existing output paths',
      );
  }

  @override
  String get name => 'archive-save';

  @override
  String get description => 'Save a JSON definition as a working archive';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 0, '');
    final output = _requiredOption(options, 'output');
    await _validateOutputs(
      options,
      files: [output],
      inputs: [_requiredOption(options, 'manifest')],
    );
    final context = C2paContext();
    final builder = await _builderFromDefinition(options, context);
    await _atomicWrite(
      output,
      builder
          .withArchiveConfiguration(
            basePath: options['base-path'] as String?,
            remoteManifestUrl: _optionalUri(options['remote-url'] as String?),
            noEmbed: options['no-embed'] as bool,
          )
          .toArchive(),
      overwrite: options['force'] as bool,
    );
    return const CliResult(CliExitCode.success);
  }
}

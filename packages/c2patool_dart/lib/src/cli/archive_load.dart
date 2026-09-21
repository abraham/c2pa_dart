part of '../cli.dart';

final class _ArchiveLoadCommand extends _C2paCommand {
  _ArchiveLoadCommand() {
    _addSignerOptions(argParser);
    argParser
      ..addOption('archive')
      ..addOption('input', abbr: 'i')
      ..addOption('output', abbr: 'o')
      ..addOption('asset-output')
      ..addOption('mime-type')
      ..addFlag('no-embed', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace existing output paths',
      )
      ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');
  }

  @override
  String get name => 'archive-load';

  @override
  String get description => 'Load/sign a working archive';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 0, '');
    final archive = _requiredOption(options, 'archive');
    final output = _requiredOption(options, 'output');
    final input = options['input'] as String?;
    final assetOutput = options['asset-output'] as String?;
    if (assetOutput != null && input == null) {
      throw const _CliUsageException('--asset-output requires --input');
    }
    await _validateOutputs(
      options,
      files: [output, ?assetOutput],
      inputs: [archive, ?input],
    );
    final builder = await _signingBuilderFromArchive(options, archive);
    final createsSidecar = options['no-embed'] as bool || builder.noEmbed;
    if (assetOutput != null && !createsSidecar) {
      throw const _CliUsageException(
        '--asset-output requires --no-embed or a no-embed archive',
      );
    }
    if (assetOutput != null && builder.remoteManifestUrl == null) {
      throw const _CliUsageException(
        '--asset-output requires a remote-manifest archive',
      );
    }
    if (builder.remoteManifestUrl != null &&
        input != null &&
        createsSidecar &&
        assetOutput == null) {
      throw const _CliUsageException(
        'A remote archive requires --asset-output',
      );
    }
    if (input == null) {
      await _atomicWrite(
        output,
        await builder.build(),
        overwrite: options['force'] as bool,
      );
      return const CliResult(CliExitCode.success);
    }
    final source = await _openSource(input, options);
    if (createsSidecar) {
      try {
        final result = await builder.buildSidecar(
          source: source,
          mimeType: options['mime-type'] as String?,
          fileName: input,
        );
        await _atomicWrite(
          output,
          result.manifestBytes,
          overwrite: options['force'] as bool,
        );
        if (result.assetBytes != null) {
          await _atomicWrite(
            assetOutput!,
            result.assetBytes!,
            overwrite: options['force'] as bool,
          );
        }
      } finally {
        await source.close();
      }
      return const CliResult(CliExitCode.success);
    }
    final sink = await FileByteSink.open(
      output,
      overwrite: options['force'] as bool,
    );
    try {
      await builder.saveToSource(
        source: source,
        output: sink,
        mimeType: options['mime-type'] as String?,
        fileName: input,
        embedManifest: !(options['no-embed'] as bool),
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

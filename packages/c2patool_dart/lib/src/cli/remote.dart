part of '../cli.dart';

final class _RemoteCommand extends _C2paCommand {
  _RemoteCommand() {
    _addMutationOptions(argParser);
    argParser.addOption('url', help: 'Omit to remove the URL');
  }

  @override
  String get name => 'remote';

  @override
  String get description => 'Set/remove an asset remote-manifest URL';

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
    try {
      final url = options['url'] as String?;
      final bytes = url == null
          ? await C2paBuilder.removeRemoteManifestReference(
              source: source,
              mimeType: options['mime-type'] as String?,
              fileName: options.rest.single,
            )
          : await C2paBuilder.updateRemoteManifestReference(
              source: source,
              remoteManifestUrl: _optionalUri(url)!,
              mimeType: options['mime-type'] as String?,
              fileName: options.rest.single,
            );
      await _atomicWrite(output, bytes, overwrite: options['force'] as bool);
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }
}

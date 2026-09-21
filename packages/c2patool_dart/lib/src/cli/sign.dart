part of '../cli.dart';

final class _SignCommand extends _C2paCommand {
  _SignCommand() {
    _addSignerOptions(argParser);
    argParser
      ..addOption('manifest')
      ..addOption('archive')
      ..addMultiOption('cert')
      ..addOption('input', abbr: 'i')
      ..addOption('output', abbr: 'o')
      ..addOption('asset-output')
      ..addOption('mime-type')
      ..addFlag('sidecar', negatable: false)
      ..addFlag('no-embed', negatable: false)
      ..addFlag(
        'embed',
        negatable: false,
        help: 'Override an archive configured for no-embed output',
      )
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace existing output paths',
      )
      ..addOption('remote-url')
      ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');
  }

  @override
  String get name => 'sign';

  @override
  String get description =>
      'Build/sign standalone, embedded, or sidecar output';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 0, '');
    final output = _requiredOption(options, 'output');
    final input = options['input'] as String?;
    final sidecar = options['sidecar'] as bool;
    final archivePath = options['archive'] as String?;
    final assetOutput = options['asset-output'] as String?;
    final manifestPath = options['manifest'] as String?;
    if ((archivePath == null) == (manifestPath == null)) {
      throw const _CliUsageException(
        'sign requires exactly one of --manifest or --archive',
      );
    }
    if (archivePath != null && (options['cert'] as List<String>).isNotEmpty) {
      throw const _CliUsageException('--cert cannot be used with --archive');
    }
    if (input == null && sidecar) {
      throw const _CliUsageException('--sidecar requires --input');
    }
    if ((options['no-embed'] as bool) && (options['embed'] as bool)) {
      throw const _CliUsageException(
        '--embed and --no-embed are mutually exclusive',
      );
    }
    final requestedRemoteUrl = _optionalUri(options['remote-url'] as String?);
    final requestedNoEmbed = options['no-embed'] as bool;
    if (manifestPath != null &&
        requestedRemoteUrl != null &&
        (input == null ||
            (!sidecar && !requestedNoEmbed) ||
            assetOutput == null)) {
      throw const _CliUsageException(
        '--remote-url requires --input, --asset-output, and '
        '--sidecar or --no-embed',
      );
    }
    final C2paBuilder builder;
    if (archivePath == null) {
      final algorithm = (options['algorithm'] as String?) ?? 'es256';
      final context = await _signingContext(options, algorithm);
      builder = await _builderFromDefinition(
        options,
        context,
        signingAlgorithm: algorithm,
      );
    } else {
      builder = await _signingBuilderFromArchive(options, archivePath);
    }
    final effectiveNoEmbed = options['no-embed'] as bool
        ? true
        : options['embed'] as bool
        ? false
        : builder.noEmbed;
    final effectiveRemoteUrl = requestedRemoteUrl ?? builder.remoteManifestUrl;
    final createsSidecar = sidecar || effectiveNoEmbed;
    if (assetOutput != null && (input == null || !createsSidecar)) {
      throw const _CliUsageException(
        '--asset-output requires --input and --sidecar or --no-embed',
      );
    }
    if (assetOutput != null && effectiveRemoteUrl == null) {
      throw const _CliUsageException('--asset-output requires --remote-url');
    }
    if (effectiveRemoteUrl != null &&
        input != null &&
        (!createsSidecar || assetOutput == null)) {
      throw const _CliUsageException(
        '--remote-url requires --input, --asset-output, and '
        '--sidecar or --no-embed',
      );
    }
    await _validateOutputs(
      options,
      files: [output, ?assetOutput],
      inputs: [?input, ?archivePath, ?manifestPath],
    );
    final configured = builder.withArchiveConfiguration(
      remoteManifestUrl: effectiveRemoteUrl,
      noEmbed: effectiveNoEmbed,
    );

    if (input == null) {
      await _atomicWrite(
        output,
        await configured.build(),
        overwrite: options['force'] as bool,
      );
      return const CliResult(CliExitCode.success);
    }
    final source = await _openSource(input, options);
    try {
      if (createsSidecar) {
        final result = await configured.buildSidecar(
          source: source,
          remoteManifestUrl: effectiveRemoteUrl,
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
      } else {
        final sink = await FileByteSink.open(
          output,
          overwrite: options['force'] as bool,
        );
        try {
          await configured.saveToSource(
            source: source,
            output: sink,
            mimeType: options['mime-type'] as String?,
            fileName: input,
          );
          await sink.close();
        } on Object {
          await sink.abort();
          rethrow;
        }
      }
    } finally {
      await source.close();
    }
    return const CliResult(CliExitCode.success);
  }
}

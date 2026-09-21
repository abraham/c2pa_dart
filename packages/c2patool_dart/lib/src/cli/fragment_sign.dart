part of '../cli.dart';

final class _FragmentSignCommand extends _C2paCommand {
  _FragmentSignCommand() {
    _addSignerOptions(argParser);
    argParser
      ..addOption('manifest')
      ..addOption('archive')
      ..addMultiOption('cert')
      ..addOption('init')
      ..addMultiOption('fragment')
      ..addOption('output-dir')
      ..addOption('mime-type')
      ..addOption('merkle-reservation', defaultsTo: '1048576')
      ..addOption('fixed-block-size')
      ..addFlag('variable-block-sizes', negatable: false)
      ..addFlag(
        'force',
        negatable: false,
        help: 'Replace an existing output directory',
      )
      ..addOption('max-input-bytes', defaultsTo: '${2 * 1024 * 1024 * 1024}');
  }

  @override
  String get name => 'fragment-sign';

  @override
  String get description => 'Sign fragmented ISO BMFF input';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 0, '');
    final initPath = _requiredOption(options, 'init');
    final fragments = (options['fragment'] as List<String>);
    if (fragments.isEmpty) {
      throw const _CliUsageException(
        'fragment-sign requires at least one --fragment',
      );
    }
    final archivePath = options['archive'] as String?;
    final manifestPath = options['manifest'] as String?;
    if ((archivePath == null) == (manifestPath == null)) {
      throw const _CliUsageException(
        'fragment-sign requires exactly one of --manifest or --archive',
      );
    }
    if (archivePath != null && (options['cert'] as List<String>).isNotEmpty) {
      throw const _CliUsageException('--cert cannot be used with --archive');
    }
    if (options['variable-block-sizes'] as bool &&
        options['fixed-block-size'] != null) {
      throw const _CliUsageException(
        '--fixed-block-size and --variable-block-sizes are mutually exclusive',
      );
    }
    final outputPath = _requiredOption(options, 'output-dir');
    final outputDirectory = Directory(outputPath);
    final generatedOutputs = <String>[
      _containedOutput(outputDirectory, 'init.mp4').path,
      for (var index = 0; index < fragments.length; index++)
        _containedOutput(outputDirectory, 'fragment-$index.m4s').path,
    ];
    await _validateOutputs(
      options,
      files: generatedOutputs,
      directories: [outputPath],
      inputs: [initPath, ...fragments, ?archivePath, ?manifestPath],
    );
    await outputDirectory.create(recursive: true);
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
    final init = await _openSource(initPath, options);
    final sources = <FileByteSource>[];
    try {
      for (final path in fragments) {
        sources.add(await _openSource(path, options));
      }
      final result = await builder.buildFragmentedBmff(
        initializationSegment: init,
        fragments: sources,
        merkleReservationBytes: _integer(options, 'merkle-reservation'),
        fixedBlockSize: _nullableInteger(options, 'fixed-block-size'),
        useVariableBlockSizes: options['variable-block-sizes'] as bool,
        mimeType: options['mime-type'] as String?,
        fileName: initPath,
      );
      if (result.fragments.length != fragments.length) {
        throw C2paSigningException(
          'Fragment signer returned ${result.fragments.length} fragments for '
          '${fragments.length} inputs',
        );
      }
      await _atomicWrite(
        generatedOutputs.first,
        result.initializationSegment,
        overwrite: options['force'] as bool,
      );
      for (var index = 0; index < result.fragments.length; index++) {
        await _atomicWrite(
          generatedOutputs[index + 1],
          result.fragments[index],
          overwrite: options['force'] as bool,
        );
      }
    } finally {
      await init.close();
      for (final source in sources) {
        await source.close();
      }
    }
    return const CliResult(CliExitCode.success);
  }
}

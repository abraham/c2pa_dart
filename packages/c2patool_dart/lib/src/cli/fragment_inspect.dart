part of '../cli.dart';

final class _FragmentInspectCommand extends _C2paCommand {
  _FragmentInspectCommand() {
    _addReaderOptions(argParser);
    argParser
      ..addOption('init')
      ..addMultiOption('fragment');
  }

  @override
  String get name => 'fragment-inspect';

  @override
  String get description => 'Validate fragmented ISO BMFF input';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    _requirePositionals(options, 0, '');
    final initPath = _requiredOption(options, 'init');
    final fragmentPaths = options['fragment'] as List<String>;
    if (fragmentPaths.isEmpty) {
      throw const _CliUsageException(
        'fragment-inspect requires at least one --fragment',
      );
    }
    final init = await _openSource(initPath, options);
    final fragments = <FileByteSource>[];
    try {
      for (final path in fragmentPaths) {
        fragments.add(await _openSource(path, options));
      }
      final reader = await C2paReader.fromFragmentedBmff(
        initializationSegment: init,
        fragments: fragments,
        mimeType: options['mime-type'] as String?,
        fileName: initPath,
        context: await _readerContext(options),
      );
      final json = reader.encodeSdkJson(options: _jsonOptions(options));
      return CliResult(
        reader.validationResults.state == ValidationState.invalid
            ? CliExitCode.validation
            : CliExitCode.success,
        stdout: '$json\n',
      );
    } finally {
      await init.close();
      for (final source in fragments) {
        await source.close();
      }
    }
  }
}

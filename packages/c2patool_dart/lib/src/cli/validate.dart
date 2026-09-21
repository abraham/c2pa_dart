part of '../cli.dart';

final class _ValidateCommand extends _C2paCommand {
  _ValidateCommand() {
    _addReaderOptions(argParser);
    argParser.addOption('output', abbr: 'o');
  }

  @override
  String get name => 'validate';

  @override
  String get description => 'Inspect and fail when validation is invalid';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    return _inspect(options, validate: true);
  }
}

part of '../cli.dart';

final class _InspectCommand extends _C2paCommand {
  _InspectCommand() {
    _addReaderOptions(argParser);
    argParser.addOption('output', abbr: 'o');
  }

  @override
  String get name => 'inspect';

  @override
  String get description => 'Print SDK, detailed, or crJSON output';

  @override
  Future<CliResult> run() async {
    final options = argResults!;
    return _inspect(options, validate: false);
  }
}

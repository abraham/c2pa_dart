import 'dart:io';

import 'package:c2patool_dart/c2patool_dart.dart';

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    stderr.writeln('usage: dart run example/c2patool_dart.dart <asset>');
    exitCode = CliExitCode.usage;
    return;
  }
  exitCode = await runC2paCli(['inspect', '--pretty', arguments.single]);
}

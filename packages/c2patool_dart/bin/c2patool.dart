import 'dart:io';

import 'package:c2patool_dart/c2patool_dart.dart';

Future<void> main(List<String> arguments) async {
  exitCode = await runC2paCli(arguments);
}

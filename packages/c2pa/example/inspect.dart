import 'dart:io';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_io/c2pa_io_vm.dart';

Future<void> main(List<String> arguments) async {
  if (arguments.length != 1) {
    stderr.writeln('usage: dart run example/inspect.dart <asset>');
    exitCode = 64;
    return;
  }

  final source = await FileByteSource.open(arguments.single);
  try {
    final reader = await C2paReader.fromSource(
      source: source,
      fileName: arguments.single,
      context: C2paContext(),
    );
    stdout.writeln(reader.toSdkJson());
  } finally {
    await source.close();
  }
}

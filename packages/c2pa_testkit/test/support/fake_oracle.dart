import 'dart:convert';
import 'dart:io';

Future<void> main(List<String> arguments) async {
  final values = <String, String>{};
  for (var index = 0; index < arguments.length; index += 2) {
    values[arguments[index]] = arguments[index + 1];
  }

  final mode = values['--mode'] ?? 'success';
  if (mode == 'timeout') {
    await Future<void>.delayed(const Duration(seconds: 2));
    return;
  }
  if (mode == 'oversized-output') {
    stdout.write('x' * 4096);
    return;
  }
  if (mode == 'stdout-json') {
    stdout.write(jsonEncode({'source': 'stdout'}));
    return;
  }

  final asset = await File(values['--asset']!).readAsBytes();
  final jsonFile = File(values['--json']!);
  final crJsonFile = File(values['--crjson']!);
  if (mode == 'malformed') {
    await jsonFile.writeAsString('{not-json');
    return;
  }
  if (mode == 'oversized-report') {
    await jsonFile.writeAsString(jsonEncode({'padding': 'x' * 4096}));
    return;
  }
  if (mode == 'combined-reports') {
    await jsonFile.writeAsString(jsonEncode({'padding': 'x' * 140}));
    await crJsonFile.writeAsString(jsonEncode({'padding': 'x' * 140}));
    return;
  }

  await jsonFile.writeAsString(
    jsonEncode({
      'active_manifest': 'urn:manifest:active',
      'assetLength': asset.length,
    }),
  );
  await crJsonFile.writeAsString(
    jsonEncode({
      'manifests': ['urn:manifest:active'],
    }),
  );
  stderr.write('fake oracle diagnostic');
  if (mode == 'nonzero') exitCode = 7;
}

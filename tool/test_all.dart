import 'dart:io';

const _packages = <String>[
  'c2pa_io',
  'c2pa_codec',
  'c2pa_crypto',
  'c2pa_formats',
  'c2pa',
  'c2pa_testkit',
  'c2patool_dart',
];

Future<void> main() async {
  for (final package in _packages) {
    final testDirectory = Directory('packages/$package/test');
    if (!testDirectory.existsSync()) {
      continue;
    }

    stdout.writeln('==> Testing $package');
    final process = await Process.start(
      Platform.resolvedExecutable,
      const ['test'],
      workingDirectory: 'packages/$package',
      mode: ProcessStartMode.inheritStdio,
    );
    final result = await process.exitCode;
    if (result != 0) {
      exitCode = result;
      return;
    }
  }
}

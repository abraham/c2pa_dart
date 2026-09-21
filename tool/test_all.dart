import 'dart:io';

/// Directories with a `test/` suite, in dependency order.
///
/// `.` is the workspace root, whose suite covers the repository tooling in
/// `tool/` rather than any published package.
const _suites = <String>[
  '.',
  'packages/c2pa_io',
  'packages/c2pa_codec',
  'packages/c2pa_crypto',
  'packages/c2pa_formats',
  'packages/c2pa',
  'packages/c2pa_testkit',
  'packages/c2patool_dart',
];

Future<void> main() async {
  for (final suite in _suites) {
    final testDirectory = Directory('$suite/test');
    if (!testDirectory.existsSync()) {
      continue;
    }

    final label = suite == '.' ? 'workspace tooling' : suite.split('/').last;
    stdout.writeln('==> Testing $label');
    final process = await Process.start(
      Platform.resolvedExecutable,
      const ['test'],
      workingDirectory: suite,
      mode: ProcessStartMode.inheritStdio,
    );
    final result = await process.exitCode;
    if (result != 0) {
      exitCode = result;
      return;
    }
  }
}

import 'dart:io';

/// The workspace root's suite, which covers the repository tooling in
/// `tool/` (including commitlint-backed changelog checks) rather than any
/// published package. It needs `npm ci` and is Node-version sensitive, so CI
/// only runs it on one OS; the other suites are pure Dart and run on every
/// OS in the matrix.
const _workspaceToolingSuite = '.';

/// Directories with a published package's `test/` suite, in dependency
/// order.
const _packageSuites = <String>[
  'packages/c2pa_io',
  'packages/c2pa_codec',
  'packages/c2pa_crypto',
  'packages/c2pa_formats',
  'packages/c2pa',
  'packages/c2pa_testkit',
  'packages/c2patool_dart',
];

Future<void> main(List<String> args) async {
  final suites = switch (args) {
    ['--workspace-only'] => const [_workspaceToolingSuite],
    ['--packages-only'] => _packageSuites,
    [] => [_workspaceToolingSuite, ..._packageSuites],
    _ => throw ArgumentError(
      'Usage: test_all.dart [--workspace-only|--packages-only]',
    ),
  };
  for (final suite in suites) {
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

/// Adds the commits made since the last release to the changelogs.
///
/// The root changelog receives every commit. A package changelog receives the
/// commits that are unscoped or scoped to that package.
///
/// Usage:
///
/// ```
/// dart run tool/update_changelogs.dart
/// dart run tool/update_changelogs.dart --dry-run
/// dart run tool/update_changelogs.dart --since <ref> --version 0.1.0-dev.2
/// ```
library;

import 'dart:io';

import 'changelog.dart';
import 'conventional_commits.dart';

/// Workspace packages, in dependency order.
const List<String> _packages = c2paPackages;

Future<void> main(List<String> arguments) async {
  var dryRun = false;
  var force = false;
  String? since;
  String? version;

  for (var index = 0; index < arguments.length; index++) {
    final argument = arguments[index];
    switch (argument) {
      case '-h':
      case '--help':
        stdout.writeln(_usage);
        return;
      case '--dry-run':
        dryRun = true;
      case '--force':
        force = true;
      case '--since':
        if (index + 1 >= arguments.length) {
          return _fail('--since requires a value');
        }
        since = arguments[++index];
      case '--version':
        if (index + 1 >= arguments.length) {
          return _fail('--version requires a value');
        }
        version = arguments[++index];
      default:
        return _fail('unknown argument: $argument');
    }
  }

  version ??= _readWorkspaceVersion();
  if (version == null) {
    return _fail('could not read the version from packages/c2pa/pubspec.yaml');
  }

  since ??= await _lastReleaseCommit();
  final range = since == null ? 'HEAD' : '$since..HEAD';
  if (since == null) {
    stdout.writeln(
      'No release commit found; using the entire history. Later runs will '
      'start from the newest "build:" commit naming a version.',
    );
  } else {
    final subject = await _subject(since);
    stdout.writeln('Collecting commits since $since ($subject).');
  }

  final commits = await _commitsIn(range);
  if (commits == null) {
    return _fail('could not read commits in $range');
  }

  final parsed = <ConventionalCommit>[];
  final unparsed = <String>[];
  for (final message in commits) {
    final commit = parseConventionalCommit(message);
    if (commit == null) {
      unparsed.add(message.split('\n').first);
      continue;
    }
    parsed.add(commit);
  }

  if (unparsed.isNotEmpty) {
    // Not fatal: the commit linter is what enforces the format, and this tool
    // should still produce a changelog for the commits that do parse.
    stderr.writeln('Skipped ${unparsed.length} commit(s) that do not parse:');
    for (final subject in unparsed) {
      stderr.writeln('  $subject');
    }
  }

  _warnAboutUnknownScopes(parsed);

  final targets = <String, String>{
    'CHANGELOG.md': 'workspace',
    for (final package in _packages) 'packages/$package/CHANGELOG.md': package,
  };

  var changed = 0;
  // Everything is planned before anything is written. Bailing out midway
  // through the loop would leave some changelogs updated and the rest not,
  // which is a worse state to recover from than not having run at all.
  final planned = <String, String>{};
  final conflicts = <String>[];

  for (final entry in targets.entries) {
    final path = entry.key;
    final package = entry.value == 'workspace' ? null : entry.value;
    final selected = entriesForPackage(
      parsed,
      package: package,
      packages: _packages,
    );

    // A package with nothing to report keeps its existing changelog rather
    // than gaining an empty section.
    if (package != null && selected.isEmpty) {
      stdout.writeln('  --    $path (no matching commits)');
      continue;
    }

    final body = renderChangelogBody(selected, showScopes: package == null);
    final file = File(path);
    final existing = file.existsSync()
        ? file.readAsStringSync()
        : _newDocument();

    final String updated;
    try {
      updated = upsertChangelogSection(existing, version, body, force: force);
    } on ChangelogConflict catch (error) {
      conflicts.add('$path: $error');
      continue;
    }

    if (updated == existing) {
      stdout.writeln('  --    $path (already up to date)');
      continue;
    }

    changed++;
    planned[path] = updated;
    stdout.writeln(
      '  write $path (${selected.length} entr'
      '${selected.length == 1 ? 'y' : 'ies'})',
    );
  }

  // Reporting every conflict at once saves rerunning to discover the next one.
  if (conflicts.isNotEmpty) {
    stderr.writeln();
    stderr.writeln(
      'error: nothing was written. '
      '${conflicts.length} changelog(s) already have notes for $version:',
    );
    for (final conflict in conflicts) {
      stderr.writeln('  $conflict');
    }
    stderr.writeln();
    stderr.writeln(
      'Bump the version first with scripts/bump-version.sh, '
      'or pass --force to replace what is there.',
    );
    exitCode = 2;
    return;
  }

  if (!dryRun) {
    planned.forEach((path, contents) => File(path).writeAsStringSync(contents));
  }

  stdout.writeln();
  if (dryRun) {
    stdout.writeln('Dry run: $changed file(s) would change.');
    return;
  }
  stdout.writeln('Updated $changed file(s) for $version.');
}

const String _usage = '''
Adds the commits made since the last release to the changelogs.

Usage:
  dart run tool/update_changelogs.dart [options]

Options:
  --since <ref>       Start after this commit instead of the last release.
  --version <v>       Section to write; defaults to the workspace version.
  --dry-run           Report what would change without writing.
  --force             Replace an existing section that has content.
  -h, --help          Show this message.

The root changelog receives every commit. A package changelog receives the
commits that are unscoped or scoped to that package.''';

void _fail(String message) {
  stderr.writeln('error: $message');
  exitCode = 2;
}

/// The header a changelog starts with when one has to be created.
String _newDocument() => '# Changelog\n';

String? _readWorkspaceVersion() {
  final pubspec = File('packages/c2pa/pubspec.yaml');
  if (!pubspec.existsSync()) {
    return null;
  }
  for (final line in pubspec.readAsLinesSync()) {
    if (line.startsWith('version: ')) {
      return line.substring('version: '.length).trim();
    }
  }
  return null;
}

/// Finds the newest release commit, which is a `build` commit whose
/// description is just the version.
Future<String?> _lastReleaseCommit() async {
  final result = await Process.run('git', [
    'log',
    '--no-merges',
    '--format=%H%x1f%s',
    '--max-count=500',
  ]);
  if (result.exitCode != 0) {
    return null;
  }
  for (final line in (result.stdout as String).split('\n')) {
    final parts = line.split('\x1f');
    if (parts.length != 2) {
      continue;
    }
    final commit = parseConventionalCommit(parts[1]);
    if (commit != null && isReleaseCommit(commit)) {
      return parts[0];
    }
  }
  return null;
}

Future<String> _subject(String sha) async {
  final result = await Process.run('git', ['show', '-s', '--format=%s', sha]);
  return result.exitCode == 0 ? (result.stdout as String).trim() : sha;
}

/// Reads the full message of every non-merge commit in [range], oldest first.
Future<List<String>?> _commitsIn(String range) async {
  const separator = '\x1e';
  final result = await Process.run('git', [
    'log',
    '--no-merges',
    '--reverse',
    '--format=%B$separator',
    range,
  ]);
  if (result.exitCode != 0) {
    return null;
  }
  return (result.stdout as String)
      .split(separator)
      .map((message) => message.trim())
      .where((message) => message.isNotEmpty)
      .toList();
}

void _warnAboutUnknownScopes(List<ConventionalCommit> commits) {
  final unknown = <String>{};
  for (final commit in commits) {
    final scope = commit.scope?.trim();
    if (scope == null || scope.isEmpty) {
      continue;
    }
    unknown.addAll(unresolvableScopeParts(scope, _packages));
  }
  if (unknown.isEmpty) {
    return;
  }
  // commitlint rejects these, so they only reach here from commits made before
  // the rule existed. They still route to the root changelog only, which looks
  // like it worked, so say so rather than letting it pass unremarked.
  stderr.writeln(
    'warning: scope names neither a package nor "$rootScope", '
    'so it reached the root changelog only: '
    '${(unknown.toList()..sort()).join(', ')}',
  );
}

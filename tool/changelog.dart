/// Turns conventional commits into changelog sections.
///
/// Kept free of `dart:io` so the grouping, scope routing, and section splicing
/// can be tested directly rather than only through a script that rewrites
/// files in place.
library;

import 'conventional_commits.dart';

/// Workspace packages, in dependency order.
///
/// This has to agree with the `workspace:` list in the root `pubspec.yaml`,
/// which is the authority; `test/changelog_test.dart` asserts that it does. A
/// package missing here would be skipped silently when changelogs are written.
const List<String> c2paPackages = <String>[
  'c2pa_io',
  'c2pa_codec',
  'c2pa_crypto',
  'c2pa_formats',
  'c2pa',
  'c2pa_testkit',
  'c2patool_dart',
];

/// The scope naming the workspace itself rather than any one package.
///
/// Commits scoped this way reach the root changelog only, which is where
/// changes to CI, tooling, and documentation belong.
const String rootScope = 'root';

/// Scopes Dependabot writes itself and that we cannot rename.
///
/// Dependabot's `commit-message.include: scope` option only ever appends
/// `deps` or `deps-dev` (https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#include),
/// and it applies the same vocabulary by default when it detects a
/// conventional-commit style in a repository's history, which is what
/// produces messages like `chore(deps): bump actions/setup-node from 4 to 7`
/// here. There is no dependabot.yml setting that swaps in a workspace
/// package or `root` instead, so both words are accepted as scopes and,
/// like `root`, resolve to no package: a dependency bump reaches the root
/// changelog alone.
const List<String> dependabotScopes = <String>['deps', 'deps-dev'];

/// Every scope a commit message may carry.
///
/// Each package may be named in full or, where it has one, by its short form,
/// so `codec` and `c2pa_codec` are both accepted and both resolve to
/// `c2pa_codec`. `commitlint.config.mjs` derives the same set from
/// `pubspec.yaml` and rejects anything outside it.
List<String> allowedScopes(Iterable<String> packages) => <String>[
  ...packages,
  ...packages.map(shortScopeFor).whereType<String>(),
  rootScope,
  ...dependabotScopes,
];

/// The short form of [package], or null when it has none.
///
/// `c2pa_codec` shortens to `codec`. `c2pa` is already short, and
/// `c2patool_dart` does not carry the `c2pa_` prefix, so it is named
/// explicitly.
String? shortScopeFor(String package) {
  if (package.startsWith('c2pa_')) {
    return package.substring(5);
  }
  if (package == 'c2patool_dart') {
    return 'c2patool';
  }
  return null;
}

/// The placeholder `scripts/bump-version.sh` writes into a fresh section.
///
/// A section containing only this is considered empty, so the normal
/// bump-then-generate flow does not need `--force`.
const String changelogStub = '- Describe the changes in this release.';

/// Raised when a changelog cannot be updated without discarding existing text.
class ChangelogConflict implements Exception {
  const ChangelogConflict(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Headings for each commit type, in the order they should appear.
///
/// A type missing from this map is still rendered, under its own name, so an
/// unexpected type is visible rather than silently dropped.
const Map<String, String> changelogSectionTitles = <String, String>{
  'feat': 'Features',
  'fix': 'Bug fixes',
  'perf': 'Performance',
  'revert': 'Reverts',
  'refactor': 'Refactoring',
  'docs': 'Documentation',
  'test': 'Tests',
  'build': 'Build',
  'ci': 'Continuous integration',
  'style': 'Style',
  'chore': 'Chores',
};

/// The delimiters commitlint splits a scope list on.
///
/// Taken from @commitlint/rules/scope-enum, which defaults to `/`, `\\` and
/// `,`, the last optionally followed by a space. Matching it exactly is the
/// point: a scope list commitlint accepts has to route the same way here.
final RegExp scopeListSeparator = RegExp(r', ?|/|\\');

/// Whether [commit] is the release marker the changelog range is measured from.
///
/// A release is a `build` commit whose description is nothing but the version,
/// which is what `scripts/bump-version.sh` produces. Requiring the version
/// keeps an ordinary build change, such as `build: raise the lint version`,
/// from silently becoming a boundary and truncating the next changelog.
bool isReleaseCommit(ConventionalCommit commit) =>
    commit.type.toLowerCase() == 'build' &&
    RegExp(r'^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')
        .hasMatch(commit.description.trim());

/// Resolves a commit scope to a workspace package, or null when the scope does
/// not name one.
///
/// Both the full package name and the short form are accepted, so
/// `feat(codec):` and `feat(c2pa_codec):` route to the same place.
String? resolveScopeToPackage(String scope, Iterable<String> packages) {
  final normalized = scope.trim().toLowerCase();
  if (normalized.isEmpty || normalized == rootScope) {
    return null;
  }
  for (final package in packages) {
    if (package == normalized || shortScopeFor(package) == normalized) {
      return package;
    }
  }
  return null;
}

/// Resolves a scope, which may list several, to the packages it names.
///
/// commitlint accepts `fix(codec,io):` by splitting on its delimiters and
/// checking each part, so routing has to split the same way; treating the list
/// as one unknown scope would send the commit to the root changelog alone and
/// reach neither package. Parts naming no package, including `root`,
/// contribute nothing.
Set<String> resolveScopesToPackages(String scope, Iterable<String> packages) {
  return <String>{
    for (final part in scope.split(scopeListSeparator))
      ?resolveScopeToPackage(part, packages),
  };
}

/// The parts of [scope] that name neither a package nor the root.
Set<String> unresolvableScopeParts(String scope, Iterable<String> packages) {
  return <String>{
    for (final part in scope.split(scopeListSeparator))
      if (part.trim().isNotEmpty &&
          part.trim().toLowerCase() != rootScope &&
          resolveScopeToPackage(part, packages) == null)
        part.trim(),
  };
}

/// Selects the commits that belong in one changelog.
///
/// A null [package] selects the root changelog, which gets everything. A
/// package changelog gets commits that are unscoped or scoped to that package;
/// a commit scoped to anything else, including a non-package scope such as
/// `ci`, belongs only to the root.
List<ConventionalCommit> entriesForPackage(
  List<ConventionalCommit> commits, {
  String? package,
  required Iterable<String> packages,
}) {
  return commits.where((commit) {
    if (isReleaseCommit(commit)) {
      return false;
    }
    if (package == null) {
      return true;
    }
    final scope = commit.scope;
    if (scope == null || scope.trim().isEmpty) {
      return true;
    }
    return resolveScopesToPackages(scope, packages).contains(package);
  }).toList();
}

/// Renders [commits] as the body of a changelog section.
///
/// Breaking changes are pulled into their own leading section and are not
/// repeated under their type, so each commit is listed exactly once.
/// Scopes are shown only when [showScopes] is true, because inside a package's
/// own changelog the scope repeats the filename.
String renderChangelogBody(
  List<ConventionalCommit> commits, {
  bool showScopes = true,
  Iterable<String> packages = c2paPackages,
}) {
  if (commits.isEmpty) {
    return '- No user facing changes.';
  }

  final buffer = StringBuffer();
  final breaking = commits.where((commit) => commit.isBreaking).toList();
  final rest = commits.where((commit) => !commit.isBreaking).toList();

  void writeSection(String title, List<ConventionalCommit> entries) {
    if (entries.isEmpty) {
      return;
    }
    if (buffer.isNotEmpty) {
      buffer.writeln();
    }
    buffer.writeln('### $title');
    buffer.writeln();
    for (final entry in entries) {
      buffer.writeln(
        '- ${_bullet(entry, showScopes: showScopes, packages: packages)}',
      );
    }
  }

  writeSection('Breaking changes', breaking);

  final seen = <String>{};
  final ordered = <String>[
    ...changelogSectionTitles.keys,
    // Any type not in the table still gets a section, after the known ones.
    ...rest.map((commit) => commit.type.toLowerCase()),
  ];
  for (final type in ordered) {
    if (!seen.add(type)) {
      continue;
    }
    final entries = rest
        .where((commit) => commit.type.toLowerCase() == type)
        .toList();
    writeSection(changelogSectionTitles[type] ?? type, entries);
  }

  return buffer.toString().trimRight();
}

String _bullet(
  ConventionalCommit commit, {
  required bool showScopes,
  required Iterable<String> packages,
}) {
  final scope = commit.scope?.trim();
  if (showScopes && scope != null && scope.isNotEmpty) {
    // A scope may be written short or in full; the changelog always shows the
    // full package name so the same package reads the same way throughout.
    // A scope naming no package is left as written, which keeps a stale or
    // mistyped one visible instead of quietly tidying it away.
    final resolved = resolveScopesToPackages(scope, packages);
    final label = resolved.isEmpty
        ? scope
        : (resolved.toList()..sort()).join(', ');
    return '**$label**: ${commit.description}';
  }
  return commit.description;
}

/// Inserts or replaces the `## [version]` section of [document] with [body].
///
/// Throws [ChangelogConflict] when the section already holds text that was not
/// written by this tool, unless [force] is set, so hand written release notes
/// are not silently discarded.
String upsertChangelogSection(
  String document,
  String version,
  String body, {
  bool force = false,
}) {
  final normalized = document.replaceAll('\r\n', '\n');
  final lines = normalized.isEmpty ? <String>[] : normalized.split('\n');
  final heading = '## $version';

  var start = -1;
  for (var index = 0; index < lines.length; index++) {
    if (lines[index].trimRight() == heading) {
      start = index;
      break;
    }
  }

  if (start == -1) {
    return _insertNewSection(lines, heading, body);
  }

  var end = lines.length;
  for (var index = start + 1; index < lines.length; index++) {
    if (lines[index].startsWith('## ')) {
      end = index;
      break;
    }
  }

  final existing = lines.sublist(start + 1, end).join('\n').trim();
  if (!force && existing.isNotEmpty && existing != changelogStub) {
    throw ChangelogConflict(
      'the "$version" section already has content; '
      'pass --force to replace it',
    );
  }

  final replacement = <String>[
    ...lines.sublist(0, start),
    heading,
    '',
    ...body.split('\n'),
    '',
    ...lines.sublist(end),
  ];
  return _tidy(replacement);
}

String _insertNewSection(List<String> lines, String heading, String body) {
  var insertAt = lines.length;
  for (var index = 0; index < lines.length; index++) {
    if (lines[index].startsWith('## ')) {
      insertAt = index;
      break;
    }
  }

  // No existing release sections: keep any title and intro prose above the new
  // section rather than pushing the new section above the title.
  if (insertAt == lines.length) {
    final tail = <String>[...lines, '', heading, '', ...body.split('\n'), ''];
    return _tidy(tail);
  }

  return _tidy(<String>[
    ...lines.sublist(0, insertAt),
    heading,
    '',
    ...body.split('\n'),
    '',
    ...lines.sublist(insertAt),
  ]);
}

/// Collapses runs of blank lines and guarantees exactly one trailing newline.
String _tidy(List<String> lines) {
  final output = <String>[];
  for (final line in lines) {
    if (line.trim().isEmpty &&
        output.isNotEmpty &&
        output.last.trim().isEmpty) {
      continue;
    }
    output.add(line.trimRight());
  }
  while (output.isNotEmpty && output.first.trim().isEmpty) {
    output.removeAt(0);
  }
  while (output.isNotEmpty && output.last.trim().isEmpty) {
    output.removeLast();
  }
  return '${output.join('\n')}\n';
}

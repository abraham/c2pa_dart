import 'dart:io';

import 'package:test/test.dart';

import '../tool/changelog.dart';
import '../tool/conventional_commits.dart';

const _packages = c2paPackages;

ConventionalCommit commit(String message) => parseConventionalCommit(message)!;

List<String> descriptionsFor(List<String> messages, {String? package}) =>
    entriesForPackage(
      messages.map(commit).toList(),
      package: package,
      packages: _packages,
    ).map((entry) => entry.description).toList();

void main() {
  _scopeAgreementTests();
  _commitlintRuleTests();

  group('scope resolution', () {
    test('matches a full package name', () {
      expect(resolveScopeToPackage('c2pa_codec', _packages), 'c2pa_codec');
    });

    test('matches a short package name', () {
      expect(resolveScopeToPackage('codec', _packages), 'c2pa_codec');
      expect(resolveScopeToPackage('io', _packages), 'c2pa_io');
      expect(resolveScopeToPackage('testkit', _packages), 'c2pa_testkit');
    });

    test('matches the umbrella package exactly', () {
      expect(resolveScopeToPackage('c2pa', _packages), 'c2pa');
    });

    test('matches the cli by either name', () {
      expect(
        resolveScopeToPackage('c2patool_dart', _packages),
        'c2patool_dart',
      );
      expect(resolveScopeToPackage('c2patool', _packages), 'c2patool_dart');
    });

    test('is case and whitespace insensitive', () {
      expect(resolveScopeToPackage('  Codec ', _packages), 'c2pa_codec');
    });

    test('resolves a list to every package it names', () {
      expect(resolveScopesToPackages('codec,io', _packages), <String>{
        'c2pa_codec',
        'c2pa_io',
      });
      expect(resolveScopesToPackages('codec, io', _packages), <String>{
        'c2pa_codec',
        'c2pa_io',
      });
      expect(resolveScopesToPackages('codec/io', _packages), <String>{
        'c2pa_codec',
        'c2pa_io',
      });
    });

    test('drops list parts that name no package', () {
      expect(resolveScopesToPackages('codec,root', _packages), <String>{
        'c2pa_codec',
      });
      expect(resolveScopesToPackages('root', _packages), isEmpty);
    });

    test('reports the list parts that name nothing', () {
      expect(unresolvableScopeParts('codec,bogus', _packages), <String>{
        'bogus',
      });
      expect(unresolvableScopeParts('codec,root', _packages), isEmpty);
    });

    test('returns null for a scope that names no package', () {
      expect(resolveScopeToPackage('ci', _packages), isNull);
      expect(resolveScopeToPackage('readme', _packages), isNull);
      expect(resolveScopeToPackage('codecs', _packages), isNull);
      expect(resolveScopeToPackage('', _packages), isNull);
    });
  });

  group('routing', () {
    const messages = <String>[
      'feat: an unscoped feature',
      'fix(codec): a codec fix',
      'fix(c2pa_io): an io fix',
      'ci(ci): a non package scope',
      'docs(readme): another non package scope',
    ];

    test('the root changelog gets everything', () {
      expect(descriptionsFor(messages), <String>[
        'an unscoped feature',
        'a codec fix',
        'an io fix',
        'a non package scope',
        'another non package scope',
      ]);
    });

    test('a package gets unscoped commits and its own', () {
      expect(descriptionsFor(messages, package: 'c2pa_codec'), <String>[
        'an unscoped feature',
        'a codec fix',
      ]);
    });

    test('a package does not get another package\'s commits', () {
      expect(descriptionsFor(messages, package: 'c2pa_io'), <String>[
        'an unscoped feature',
        'an io fix',
      ]);
    });

    test('a non package scope reaches the root only', () {
      for (final package in _packages) {
        expect(
          descriptionsFor(messages, package: package),
          isNot(contains('a non package scope')),
          reason: '$package should not receive a commit scoped to "ci"',
        );
      }
    });

    test('an empty scope counts as unscoped', () {
      expect(
        descriptionsFor(['feat(): still everyone'], package: 'c2pa_io'),
        <String>['still everyone'],
      );
    });

    test('release commits are excluded everywhere', () {
      const withRelease = <String>['build: 0.1.0-dev.2', 'feat: a feature'];
      expect(descriptionsFor(withRelease), <String>['a feature']);
      expect(descriptionsFor(withRelease, package: 'c2pa_io'), <String>[
        'a feature',
      ]);
    });

    test('an ordinary build commit is kept', () {
      expect(
        descriptionsFor(<String>['build: raise the lint version']),
        <String>['raise the lint version'],
      );
    });

    test('a multi scope commit reaches every package it names', () {
      const messages = <String>['fix(codec,io): a shared fix'];
      expect(descriptionsFor(messages, package: 'c2pa_codec'), hasLength(1));
      expect(descriptionsFor(messages, package: 'c2pa_io'), hasLength(1));
      expect(descriptionsFor(messages, package: 'c2pa_crypto'), isEmpty);
      expect(descriptionsFor(messages), hasLength(1));
    });

    test('a multi scope commit accepts every commitlint delimiter', () {
      for (final scope in <String>['codec,io', 'codec, io', 'codec/io']) {
        expect(
          descriptionsFor(<String>['fix($scope): a fix'], package: 'c2pa_io'),
          hasLength(1),
          reason: 'scope "$scope" did not reach c2pa_io',
        );
      }
    });

    test('a list mixing a package and root reaches only the package', () {
      const messages = <String>['fix(codec,root): a fix'];
      expect(descriptionsFor(messages, package: 'c2pa_codec'), hasLength(1));
      expect(descriptionsFor(messages, package: 'c2pa_io'), isEmpty);
    });
  });

  group('release commits', () {
    test('a build commit naming a version is a release', () {
      expect(isReleaseCommit(commit('build: 0.1.0-dev.2')), isTrue);
      expect(isReleaseCommit(commit('build: 1.2.3')), isTrue);
      expect(isReleaseCommit(commit('build: v1.2.3')), isTrue);
    });

    test('an ordinary build commit is not a release', () {
      expect(isReleaseCommit(commit('build: raise the lint version')), isFalse);
      expect(
        isReleaseCommit(commit('build: bump to 1.2.3 everywhere')),
        isFalse,
      );
    });

    test('another type naming a version is not a release', () {
      expect(isReleaseCommit(commit('chore: 0.1.0-dev.2')), isFalse);
      expect(isReleaseCommit(commit('feat: 1.2.3')), isFalse);
    });
  });

  group('rendering', () {
    test('groups by type under headings', () {
      final body = renderChangelogBody([
        commit('feat: a feature'),
        commit('fix: a fix'),
      ]);
      expect(body, contains('### Features'));
      expect(body, contains('### Bug fixes'));
      expect(
        body.indexOf('### Features'),
        lessThan(body.indexOf('### Bug fixes')),
      );
    });

    test('lists breaking changes first and only once', () {
      final body = renderChangelogBody([
        commit('feat!: a breaking feature'),
        commit('feat: a normal feature'),
      ]);
      expect(body.indexOf('### Breaking changes'), 0);
      expect('a breaking feature'.allMatches(body).length, 1);
      expect(body, contains('### Features'));
    });

    test('normalizes a short scope to the full package name', () {
      final body = renderChangelogBody([commit('fix(codec): a fix')]);
      expect(body, contains('- **c2pa_codec**: a fix'));
    });

    test('names every package a multi scope commit reaches', () {
      final body = renderChangelogBody([commit('fix(codec,io): a fix')]);
      expect(body, contains('- **c2pa_codec, c2pa_io**: a fix'));
    });

    test('leaves a scope that names no package as written', () {
      final body = renderChangelogBody([commit('ci(ci): a fix')]);
      expect(body, contains('- **ci**: a fix'));
    });

    test('shows the root scope as written', () {
      final body = renderChangelogBody([commit('chore(root): a chore')]);
      expect(body, contains('- **root**: a chore'));
    });

    test('hides scopes inside a package changelog', () {
      final body = renderChangelogBody([
        commit('fix(codec): a fix'),
      ], showScopes: false);
      expect(body, contains('- a fix'));
      expect(body, isNot(contains('**codec**')));
    });

    test('renders an unknown type under its own name', () {
      final body = renderChangelogBody([commit('wibble: a thing')]);
      expect(body, contains('### wibble'));
    });

    test('reports an empty set rather than producing nothing', () {
      expect(renderChangelogBody([]), contains('No user facing changes.'));
    });
  });

  group('section splicing', () {
    test('creates a section in an empty document', () {
      final result = upsertChangelogSection('# Changelog\n', '1.0.0', '- a');
      expect(result, '# Changelog\n\n## 1.0.0\n\n- a\n');
    });

    test('inserts above an existing older section', () {
      const document = '# Changelog\n\n## 0.9.0\n\n- old\n';
      final result = upsertChangelogSection(document, '1.0.0', '- new');
      expect(result.indexOf('## 1.0.0'), lessThan(result.indexOf('## 0.9.0')));
      expect(result, contains('- old'));
    });

    test('replaces the bump-version stub without --force', () {
      final document = '# Changelog\n\n## 1.0.0\n\n$changelogStub\n';
      final result = upsertChangelogSection(document, '1.0.0', '- real');
      expect(result, contains('- real'));
      expect(result, isNot(contains(changelogStub)));
    });

    test('refuses to discard existing notes without --force', () {
      const document = '# Changelog\n\n## 1.0.0\n\n- hand written\n';
      expect(
        () => upsertChangelogSection(document, '1.0.0', '- generated'),
        throwsA(isA<ChangelogConflict>()),
      );
    });

    test('replaces existing notes with --force', () {
      const document = '# Changelog\n\n## 1.0.0\n\n- hand written\n';
      final result = upsertChangelogSection(
        document,
        '1.0.0',
        '- generated',
        force: true,
      );
      expect(result, contains('- generated'));
      expect(result, isNot(contains('hand written')));
    });

    test('leaves later sections untouched when replacing', () {
      const document =
          '# Changelog\n\n## 1.0.0\n\n$changelogStub\n\n## 0.9.0\n\n- old\n';
      final result = upsertChangelogSection(document, '1.0.0', '- new');
      expect(result, contains('## 0.9.0'));
      expect(result, contains('- old'));
      expect(result, contains('- new'));
    });

    test('does not treat a similar version as the same section', () {
      const document = '# Changelog\n\n## 1.0.10\n\n- ten\n';
      final result = upsertChangelogSection(document, '1.0.1', '- one');
      expect(result, contains('## 1.0.1\n'));
      expect(result, contains('- ten'));
    });

    test('ends with exactly one trailing newline', () {
      final result = upsertChangelogSection('# Changelog\n', '1.0.0', '- a');
      expect(result.endsWith('- a\n'), isTrue);
    });

    test('is idempotent when rerun with the same body', () {
      final once = upsertChangelogSection('# Changelog\n', '1.0.0', '- a');
      final twice = upsertChangelogSection(once, '1.0.0', '- a', force: true);
      expect(twice, once);
    });
  });
}

/// Reads the `workspace:` list from the root pubspec.yaml.
///
/// Deliberately independent of the constant it is checking; deriving both from
/// the same place would make the comparison vacuous.
List<String> _pubspecWorkspacePackages() {
  final lines = File('pubspec.yaml').readAsLinesSync();
  final start = lines.indexWhere((line) => line.trimRight() == 'workspace:');
  if (start < 0) {
    fail('pubspec.yaml has no workspace: list');
  }
  final names = <String>[];
  for (final line in lines.skip(start + 1)) {
    if (line.trim().isEmpty) continue;
    // The block ends at the next key in column zero.
    if (!line.startsWith(' ') && !line.startsWith('\t')) break;
    final match = RegExp(r'^\s*-\s*packages/([A-Za-z0-9_]+)\s*$')
        .firstMatch(line);
    if (match != null) names.add(match.group(1)!);
  }
  return names;
}

/// Runs the scope list commitlint actually resolves through its own config.
///
/// This executes commitlint rather than re-reading the config file, so it
/// catches a rule that is overridden or dropped somewhere in the chain, not
/// just a change to the literal in commitlint.config.mjs.
List<String>? _commitlintScopeEnum() {
  if (!File('node_modules/@commitlint/load/package.json').existsSync()) {
    return null;
  }
  const script =
      '(async () => {'
      'const load = (await import("@commitlint/load")).default;'
      'const cfg = await load({}, {cwd: process.cwd()});'
      'process.stdout.write(JSON.stringify(cfg.rules["scope-enum"][2]));'
      '})()';
  final result = Process.runSync('node', <String>['-e', script]);
  if (result.exitCode != 0) {
    fail('could not read commitlint config: ${result.stderr}');
  }
  final raw = (result.stdout as String).trim();
  return (raw.substring(1, raw.length - 1))
      .split(',')
      .map((part) => part.trim().replaceAll('"', ''))
      .where((part) => part.isNotEmpty)
      .toList();
}

void _scopeAgreementTests() {
  group('scope validation', () {
    test('the package list matches the pubspec workspace', () {
      expect(c2paPackages.toSet(), _pubspecWorkspacePackages().toSet());
    });

    test('every package has a distinct short form or none', () {
      final shorts = c2paPackages.map(shortScopeFor).whereType<String>();
      expect(shorts.toSet().length, shorts.length);
    });

    test('root is allowed but routes to no package', () {
      expect(allowedScopes(_packages), contains(rootScope));
      expect(resolveScopeToPackage(rootScope, _packages), isNull);
    });

    test('every allowed scope except root resolves to a package', () {
      for (final scope in allowedScopes(_packages)) {
        if (scope == rootScope) continue;
        expect(
          resolveScopeToPackage(scope, _packages),
          isNotNull,
          reason: '"$scope" is accepted but routes nowhere',
        );
      }
    });

    test('commitlint accepts exactly the scopes that route', () {
      final enumerated = _commitlintScopeEnum();
      if (enumerated == null) {
        // Skipping locally is a convenience; skipping in CI would mean this
        // check never runs anywhere, which is worse than not having it.
        if (Platform.environment['CI'] == 'true') {
          fail(
            'commitlint is not installed, so the scope rules were not '
            'checked; the workflow must run npm ci before the Dart tests',
          );
        }
        markTestSkipped('commitlint is not installed; run npm ci');
        return;
      }
      expect(
        enumerated.toSet(),
        allowedScopes(_packages).toSet(),
        reason:
            'commitlint.config.mjs and tool/changelog.dart disagree about '
            'which scopes are valid',
      );
    });
  });
}

/// True when commitlint accepts [message], false when it rejects it.
///
/// Runs the real binary against the real configuration, so these tests fail if
/// a rule is dropped rather than only if the config literal changes.
bool _commitlintAccepts(String message) {
  final file = File(
    '${Directory.systemTemp.path}/c2pa_commitlint_${message.hashCode}.txt',
  );
  file.writeAsStringSync('$message\n');
  try {
    final result = Process.runSync('node_modules/.bin/commitlint', <String>[
      '--edit',
      file.path,
    ]);
    return result.exitCode == 0;
  } finally {
    if (file.existsSync()) {
      file.deleteSync();
    }
  }
}

void _commitlintRuleTests() {
  group('commitlint scope rules', () {
    setUpAll(() {
      if (File('node_modules/.bin/commitlint').existsSync()) {
        return;
      }
      // Skipping locally is a convenience; skipping in CI would mean these
      // never run anywhere, which is worse than not having them.
      if (Platform.environment['CI'] == 'true') {
        fail(
          'commitlint is not installed, so the scope rules were not '
          'checked; the workflow must run npm ci before the Dart tests',
        );
      }
    });

    bool? accepts(String message) =>
        File('node_modules/.bin/commitlint').existsSync()
        ? _commitlintAccepts(message)
        : null;

    void expectAccepted(String message) {
      final result = accepts(message);
      if (result == null) {
        markTestSkipped('commitlint is not installed; run npm ci');
        return;
      }
      expect(result, isTrue, reason: 'commitlint rejected: $message');
    }

    void expectRejected(String message) {
      final result = accepts(message);
      if (result == null) {
        markTestSkipped('commitlint is not installed; run npm ci');
        return;
      }
      expect(result, isFalse, reason: 'commitlint accepted: $message');
    }

    test('accepts a full package name', () {
      expectAccepted('fix(c2pa_codec): a fix');
    });

    test('accepts a short package name', () {
      expectAccepted('fix(codec): a fix');
    });

    test('accepts the root scope', () {
      expectAccepted('chore(root): a chore');
    });

    test('accepts no scope at all', () {
      expectAccepted('fix: applies to every package');
    });

    test('rejects a scope naming no package', () {
      expectRejected('fix(ci): a fix');
    });

    test('rejects a mistyped scope', () {
      expectRejected('fix(codecs): a fix');
    });

    test('rejects a scope in the wrong case', () {
      expectRejected('fix(Codec): a fix');
    });

    // These route to several packages, so both sides have to accept them.
    test('accepts a comma separated scope list', () {
      expectAccepted('fix(codec,io): a fix');
    });

    test('accepts a comma and space separated scope list', () {
      expectAccepted('fix(codec, io): a fix');
    });

    test('accepts a slash separated scope list', () {
      expectAccepted('fix(codec/io): a fix');
    });

    test('rejects a list containing an unknown scope', () {
      expectRejected('fix(codec,bogus): a fix');
    });

    test('rejects release as a type, which is no longer used', () {
      expectRejected('release: 0.1.0-dev.2');
    });

    test('accepts the build commit that marks a release', () {
      expectAccepted('build: 0.1.0-dev.2');
    });
  });
}

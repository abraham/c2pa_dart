import 'package:test/test.dart';

import '../tool/conventional_commits.dart';

void main() {
  group('header', () {
    test('parses a minimal header', () {
      final commit = parseConventionalCommit('fix: correct the offset')!;
      expect(commit.type, 'fix');
      expect(commit.scope, isNull);
      expect(commit.description, 'correct the offset');
      expect(commit.isBreaking, isFalse);
    });

    test('parses a scope', () {
      final commit = parseConventionalCommit('feat(codec): add a reader')!;
      expect(commit.type, 'feat');
      expect(commit.scope, 'codec');
      expect(commit.description, 'add a reader');
    });

    test('keeps the type in its original case', () {
      expect(parseConventionalCommit('Feat: add a reader')!.type, 'Feat');
    });

    test('parses an empty description', () {
      expect(parseConventionalCommit('fix:')!.description, isEmpty);
      expect(parseConventionalCommit('fix: ')!.description, isEmpty);
    });

    test('parses an empty scope as empty, not absent', () {
      expect(parseConventionalCommit('fix(): a thing')!.scope, isEmpty);
    });
  });

  group('breaking changes', () {
    test('detects the bang marker', () {
      expect(parseConventionalCommit('feat!: drop it')!.isBreaking, isTrue);
    });

    test('detects the bang marker alongside a scope', () {
      expect(
        parseConventionalCommit('feat(codec)!: drop it')!.isBreaking,
        isTrue,
      );
    });

    test('detects an uppercase footer', () {
      expect(
        parseConventionalCommit(
          'feat: replace it\n\nBREAKING CHANGE: the old one is gone',
        )!.isBreaking,
        isTrue,
      );
    });

    test('detects the hyphenated synonym', () {
      expect(
        parseConventionalCommit(
          'feat: replace it\n\nBREAKING-CHANGE: the old one is gone',
        )!.isBreaking,
        isTrue,
      );
    });

    test(
      'ignores a lower case footer, which the specification does not allow',
      () {
        expect(
          parseConventionalCommit(
            'feat: replace it\n\nbreaking change: the old one is gone',
          )!.isBreaking,
          isFalse,
        );
      },
    );

    test('ignores prose that merely mentions a breaking change', () {
      expect(
        parseConventionalCommit(
          'fix: correct it\n\nThis is not a breaking change: it was wrong.',
        )!.isBreaking,
        isFalse,
      );
    });
  });

  group('unparseable input', () {
    test('returns null with no prefix', () {
      expect(parseConventionalCommit('correct the offset'), isNull);
    });

    test('returns null without the space after the colon', () {
      expect(parseConventionalCommit('fix:correct the offset'), isNull);
    });

    test('returns null for a non alphabetic type', () {
      expect(parseConventionalCommit('fix 2: correct the offset'), isNull);
    });

    test('returns null for an empty message', () {
      expect(parseConventionalCommit('   \n  '), isNull);
    });

    test('returns null for a merge commit subject', () {
      expect(parseConventionalCommit("Merge branch 'side'"), isNull);
    });
  });

  test('normalizes carriage returns', () {
    final commit = parseConventionalCommit('fix: correct it\r\n\r\nBody.')!;
    expect(commit.description, 'correct it');
  });

  test('ignores the trailing newlines git leaves behind', () {
    expect(
      parseConventionalCommit('fix: correct it\n\n')!.description,
      'correct it',
    );
  });
}

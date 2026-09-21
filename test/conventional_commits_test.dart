import 'package:test/test.dart';

import '../tool/conventional_commits.dart';

List<String> rulesFor(String message, {CommitRules? rules}) =>
    validateCommitMessage(
      message,
      rules: rules ?? const CommitRules(),
    ).map((violation) => violation.rule).toList();

void main() {
  group('conforming messages', () {
    test('accepts a minimal header', () {
      expect(validateCommitMessage('fix: correct the offset'), isEmpty);
    });

    test('accepts a scope', () {
      expect(validateCommitMessage('feat(codec): add a cbor reader'), isEmpty);
    });

    test('accepts a breaking change marker', () {
      expect(
        validateCommitMessage('feat(codec)!: drop the legacy reader'),
        isEmpty,
      );
    });

    test('accepts a body after a blank line', () {
      expect(
        validateCommitMessage(
          'fix: correct the offset\n\nThe reader skipped a byte.',
        ),
        isEmpty,
      );
    });

    test('accepts an uppercase BREAKING CHANGE footer', () {
      expect(
        validateCommitMessage(
          'feat: replace the reader\n\nBody text.\n\n'
          'BREAKING CHANGE: the old reader is gone',
        ),
        isEmpty,
      );
    });

    test('accepts the BREAKING-CHANGE synonym', () {
      expect(
        validateCommitMessage(
          'feat: replace the reader\n\nBREAKING-CHANGE: the old reader is gone',
        ),
        isEmpty,
      );
    });

    test('accepts every default type', () {
      for (final type in defaultCommitTypes) {
        expect(
          validateCommitMessage('$type: do the thing'),
          isEmpty,
          reason: 'expected "$type" to be accepted',
        );
      }
    });

    test(
      'treats the type case insensitively, as the specification requires',
      () {
        expect(validateCommitMessage('Feat: add a reader'), isEmpty);
      },
    );

    test('normalizes carriage returns', () {
      expect(
        validateCommitMessage('fix: correct the offset\r\n\r\nBody.'),
        isEmpty,
      );
    });

    test('ignores trailing whitespace left by git', () {
      expect(validateCommitMessage('fix: correct the offset\n\n'), isEmpty);
    });

    test('leaves prose mentioning a breaking change alone', () {
      expect(
        validateCommitMessage(
          'fix: correct the offset\n\n'
          'This is not a breaking change: the offset was wrong.',
        ),
        isEmpty,
      );
    });
  });

  group('header format', () {
    test('rejects a message with no prefix', () {
      expect(rulesFor('correct the offset'), contains('header-format'));
    });

    test('rejects a missing space after the colon', () {
      final violations = validateCommitMessage('fix:correct the offset');
      expect(violations.map((v) => v.rule), contains('header-format'));
      expect(violations.single.message, contains('followed by a space'));
    });

    test('rejects an empty description', () {
      expect(rulesFor('fix: '), contains('description-empty'));
    });

    test(
      'rejects an empty description after git strips the trailing space',
      () {
        expect(rulesFor('fix:'), contains('description-empty'));
      },
    );

    test('reports both an empty scope and an empty description', () {
      expect(
        rulesFor('fix():'),
        containsAll(<String>['scope-empty', 'description-empty']),
      );
    });

    test('rejects an empty scope', () {
      expect(rulesFor('fix(): correct the offset'), contains('scope-empty'));
    });

    test('rejects a non alphabetic type', () {
      expect(rulesFor('fix 2: correct the offset'), contains('header-format'));
    });

    test('rejects an empty message', () {
      expect(rulesFor('   \n  '), contains('empty-message'));
    });
  });

  group('type allowlist', () {
    test('rejects "feature", the common misspelling of "feat"', () {
      final violations = validateCommitMessage('feature: initial version');
      expect(violations.map((v) => v.rule), contains('type-allowed'));
      expect(violations.single.message, contains('feat'));
    });

    test('honours a custom type set', () {
      const rules = CommitRules(types: {'feat', 'fix'});
      expect(
        rulesFor('chore: tidy up', rules: rules),
        contains('type-allowed'),
      );
      expect(rulesFor('feat: add a reader', rules: rules), isEmpty);
    });
  });

  group('body', () {
    test('rejects a body that is not preceded by a blank line', () {
      expect(
        rulesFor('fix: correct the offset\nThe reader skipped a byte.'),
        contains('body-leading-blank'),
      );
    });
  });

  group('breaking change footer', () {
    test('rejects a lowercase footer token', () {
      expect(
        rulesFor(
          'feat: replace the reader\n\nbreaking change: the old reader is gone',
        ),
        contains('breaking-change-uppercase'),
      );
    });

    test('rejects a mixed case hyphenated token', () {
      expect(
        rulesFor(
          'feat: replace the reader\n\nBreaking-Change: the old reader is gone',
        ),
        contains('breaking-change-uppercase'),
      );
    });

    test('reports the offending line number', () {
      final violations = validateCommitMessage(
        'feat: replace the reader\n\nBody.\n\nbreaking change: gone',
      );
      expect(violations.single.message, contains('line 5'));
    });
  });

  group('header length', () {
    test('rejects a header over the maximum', () {
      final header = 'fix: ${'a' * 120}';
      expect(rulesFor(header), contains('header-max-length'));
    });

    test('accepts a long header when the check is disabled', () {
      final header = 'fix: ${'a' * 120}';
      expect(
        rulesFor(header, rules: const CommitRules(maxHeaderLength: 0)),
        isEmpty,
      );
    });

    test('measures only the header, not the body', () {
      final message = 'fix: correct the offset\n\n${'a' * 200}';
      expect(rulesFor(message), isEmpty);
    });
  });

  test('reports every violation in one message, not just the first', () {
    final violations = validateCommitMessage(
      'nope(): \nBody without a blank line.',
    );
    expect(
      violations.map((v) => v.rule),
      containsAll(<String>[
        'type-allowed',
        'scope-empty',
        'description-empty',
        'body-leading-blank',
      ]),
    );
  });
}

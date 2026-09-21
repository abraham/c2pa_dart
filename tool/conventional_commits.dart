/// Validation of commit messages against Conventional Commits v1.0.0.
///
/// https://www.conventionalcommits.org/en/v1.0.0/
///
/// Kept free of `dart:io` so the rules can be unit tested directly rather than
/// only through the command line wrapper. A linter nobody tests is a linter
/// that quietly stops catching things.
library;

/// A single rule violation found in one commit message.
class CommitViolation {
  const CommitViolation(this.rule, this.message);

  /// Short stable identifier, so a violation can be discussed and searched for.
  final String rule;

  /// Human readable explanation of what is wrong and how to fix it.
  final String message;

  @override
  String toString() => '$rule: $message';

  @override
  bool operator ==(Object other) =>
      other is CommitViolation &&
      other.rule == rule &&
      other.message == message;

  @override
  int get hashCode => Object.hash(rule, message);
}

/// The commit types accepted by default.
///
/// The specification allows any noun as a type, but an open set cannot catch
/// `feature:` being written where `feat:` was meant, which is the single most
/// common mistake. The default set is the widely used Angular convention.
const Set<String> defaultCommitTypes = <String>{
  'build',
  'chore',
  'ci',
  'docs',
  'feat',
  'fix',
  'perf',
  'refactor',
  'revert',
  'style',
  'test',
};

/// Configuration for [validateCommitMessage].
class CommitRules {
  const CommitRules({
    this.types = defaultCommitTypes,
    this.maxHeaderLength = 100,
  });

  /// Accepted commit types, compared case insensitively.
  final Set<String> types;

  /// Maximum length of the header line. Zero disables the check.
  ///
  /// The specification itself sets no limit; this is a conventional default
  /// that keeps subjects readable in `git log --oneline` and on GitHub.
  final int maxHeaderLength;
}

/// `type(scope)!: description`, the full prefix grammar of the specification.
///
/// The description group is optional so that `fix:` — what git leaves behind
/// after stripping the trailing space of `fix: ` — is still recognised as a
/// prefix with an empty description rather than as unparseable text.
final RegExp _header = RegExp(r'^([A-Za-z]+)(?:\(([^()]*)\))?(!)?:(?: (.*))?$');

/// A header that got the colon right but the space after it wrong.
final RegExp _missingSpace = RegExp(
  r'^([A-Za-z]+)(?:\([^()]*\))?(?:!)?:(\S.*)$',
);

/// A `BREAKING CHANGE` footer in any casing or separator spelling.
final RegExp _breakingFooter = RegExp(
  r'^(breaking[ -]change)(: | #)',
  caseSensitive: false,
);

/// Returns every way [message] departs from Conventional Commits v1.0.0.
///
/// An empty list means the message conforms.
List<CommitViolation> validateCommitMessage(
  String message, {
  CommitRules rules = const CommitRules(),
}) {
  final violations = <CommitViolation>[];
  // Only trailing newlines are removed. Trimming all trailing whitespace would
  // turn "fix: " into "fix:" and lose the fact that the description is empty.
  final normalized = message
      .replaceAll('\r\n', '\n')
      .replaceFirst(RegExp(r'\n+$'), '');

  if (normalized.trim().isEmpty) {
    return const [
      CommitViolation('empty-message', 'the commit message is empty'),
    ];
  }

  final lines = normalized.split('\n');
  final header = lines.first;

  violations.addAll(_validateHeader(header, rules));

  // Rule 6: a body MUST begin one blank line after the description.
  if (lines.length > 1 && lines[1].trim().isNotEmpty) {
    violations.add(
      const CommitViolation(
        'body-leading-blank',
        'the body must be separated from the description by one blank line',
      ),
    );
  }

  // Rules 12 and 16: as a footer token, BREAKING CHANGE MUST be uppercase.
  // Only the footer shape is matched, so prose that merely mentions a breaking
  // change mid sentence is left alone.
  for (var index = 1; index < lines.length; index++) {
    final match = _breakingFooter.firstMatch(lines[index]);
    if (match == null) {
      continue;
    }
    final token = match.group(1)!;
    if (token != 'BREAKING CHANGE' && token != 'BREAKING-CHANGE') {
      violations.add(
        CommitViolation(
          'breaking-change-uppercase',
          'the breaking change footer must be uppercase, found "$token" on line ${index + 1}',
        ),
      );
    }
  }

  return violations;
}

List<CommitViolation> _validateHeader(String header, CommitRules rules) {
  final violations = <CommitViolation>[];

  if (rules.maxHeaderLength > 0 && header.length > rules.maxHeaderLength) {
    violations.add(
      CommitViolation(
        'header-max-length',
        'the description line is ${header.length} characters, '
            'the maximum is ${rules.maxHeaderLength}',
      ),
    );
  }

  final match = _header.firstMatch(header);
  if (match == null) {
    violations.add(_explainMalformedHeader(header));
    return violations;
  }

  final type = match.group(1)!;
  final scope = match.group(2);
  final description = match.group(4) ?? '';

  // Rule 15: units are not case sensitive, so the type is matched in lower case.
  if (!rules.types.contains(type.toLowerCase())) {
    final allowed = (rules.types.toList()..sort()).join(', ');
    violations.add(
      CommitViolation(
        'type-allowed',
        '"$type" is not an allowed type; use one of: $allowed',
      ),
    );
  }

  // Rule 4: a scope MUST be a noun, so an empty one is meaningless.
  if (scope != null && scope.trim().isEmpty) {
    violations.add(
      const CommitViolation(
        'scope-empty',
        'the scope is empty; write a scope inside the parentheses or drop them',
      ),
    );
  }

  // Rule 5: a description MUST follow the colon and space.
  if (description.trim().isEmpty) {
    violations.add(
      const CommitViolation('description-empty', 'the description is empty'),
    );
  }

  return violations;
}

/// Produces the most specific explanation available for a header that does not
/// match the grammar, because "invalid commit message" alone rarely helps.
CommitViolation _explainMalformedHeader(String header) {
  final missingSpace = _missingSpace.firstMatch(header);
  if (missingSpace != null) {
    return const CommitViolation(
      'header-format',
      'the colon must be followed by a space, as in "fix: correct the offset"',
    );
  }

  if (!header.contains(':')) {
    return const CommitViolation(
      'header-format',
      'missing the required "type: description" prefix, as in "fix: correct the offset"',
    );
  }

  if (RegExp(r'^[A-Za-z]+\(\s*\)!?: ').hasMatch(header)) {
    return const CommitViolation(
      'scope-empty',
      'the scope is empty; write a scope inside the parentheses or drop them',
    );
  }

  return const CommitViolation(
    'header-format',
    'the text before the colon must be a type, optionally followed by a '
        '"(scope)" and "!", as in "feat(codec)!: drop the legacy reader"',
  );
}

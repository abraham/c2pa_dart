/// Parsing of Conventional Commits v1.0.0 messages.
///
/// https://www.conventionalcommits.org/en/v1.0.0/
///
/// This is deliberately a parser and nothing more. Enforcement belongs to
/// commitlint, configured in `commitlint.config.mjs`; duplicating the rules
/// here would create a second opinion that could drift from the one CI applies.
/// What the changelog generator needs is the structure of a message, not a
/// verdict on it.
///
/// Kept free of `dart:io` so it can be unit tested directly.
library;

/// The parsed parts of a conventional commit message.
class ConventionalCommit {
  const ConventionalCommit({
    required this.type,
    required this.scope,
    required this.description,
    required this.isBreaking,
  });

  /// The type, in the case it was written in.
  final String type;

  /// The scope inside the parentheses, or null when none was given.
  final String? scope;

  /// The summary that follows the colon.
  final String description;

  /// True when the header carries `!` or the body carries a `BREAKING CHANGE`
  /// footer, which the specification treats as equivalent.
  final bool isBreaking;

  @override
  String toString() =>
      'ConventionalCommit($type, $scope, $description, breaking: $isBreaking)';
}

/// `type(scope)!: description`, the prefix grammar of the specification.
///
/// The description group is optional so that `fix:` — what git leaves behind
/// after stripping the trailing space of `fix: ` — is still recognised as a
/// prefix rather than as unparseable text.
final RegExp _header = RegExp(r'^([A-Za-z]+)(?:\(([^()]*)\))?(!)?:(?: (.*))?$');

/// Parses [message], or returns null when the header does not match the
/// grammar.
///
/// Parsing accepts any type. Whether a type is allowed is a policy question,
/// and policy lives in the commitlint configuration.
ConventionalCommit? parseConventionalCommit(String message) {
  if (message.trim().isEmpty) {
    return null;
  }

  // Only trailing newlines are removed. Trimming all trailing whitespace would
  // turn "fix: " into "fix:" and lose the shape of an empty description.
  final lines = message
      .replaceAll('\r\n', '\n')
      .replaceFirst(RegExp(r'\n+$'), '')
      .split('\n');

  final match = _header.firstMatch(lines.first);
  if (match == null) {
    return null;
  }

  // Rules 12 and 16: the footer token must be uppercase to count, and
  // BREAKING-CHANGE is a synonym of BREAKING CHANGE.
  final breakingFooter = lines
      .skip(1)
      .any(
        (line) =>
            line.startsWith('BREAKING CHANGE: ') ||
            line.startsWith('BREAKING-CHANGE: '),
      );

  return ConventionalCommit(
    type: match.group(1)!,
    scope: match.group(2),
    description: (match.group(4) ?? '').trim(),
    isBreaking: match.group(3) != null || breakingFooter,
  );
}

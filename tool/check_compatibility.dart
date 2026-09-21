import 'dart:convert';
import 'dart:io';

const _allowedStatuses = <String>{'planned', 'partial', 'complete', 'deferred'};

void main() {
  final file = File('tool/compatibility.json');
  if (!file.existsSync()) {
    stderr.writeln('Missing tool/compatibility.json');
    exitCode = 1;
    return;
  }

  final Object? decoded;
  try {
    decoded = jsonDecode(file.readAsStringSync());
  } on FormatException catch (error) {
    stderr.writeln('Invalid compatibility JSON: $error');
    exitCode = 1;
    return;
  }

  if (decoded is! Map<String, Object?>) {
    stderr.writeln('Compatibility ledger must be a JSON object.');
    exitCode = 1;
    return;
  }

  final baseline = decoded['baseline'];
  final features = decoded['features'];
  if (baseline is! Map<String, Object?> || features is! Map<String, Object?>) {
    stderr.writeln('Compatibility ledger requires baseline and features.');
    exitCode = 1;
    return;
  }

  final requiredBaseline = <String>{
    'repository',
    'tag',
    'sdkVersion',
    'profiles',
  };
  final missing = requiredBaseline.difference(baseline.keys.toSet());
  if (missing.isNotEmpty) {
    stderr.writeln('Missing baseline fields: ${missing.join(', ')}');
    exitCode = 1;
    return;
  }

  final errors = <String>[];
  _validateStatuses(features, 'features', errors);
  if (errors.isNotEmpty) {
    stderr.writeln('Invalid compatibility ledger:');
    for (final error in errors) {
      stderr.writeln('  - $error');
    }
    exitCode = 1;
  }
}

void _validateStatuses(
  Map<String, Object?> entries,
  String path,
  List<String> errors,
) {
  for (final entry in entries.entries) {
    final entryPath = '$path.${entry.key}';
    final value = entry.value;
    if (value is Map<String, Object?>) {
      _validateStatuses(value, entryPath, errors);
    } else if (value is! String || !_allowedStatuses.contains(value)) {
      errors.add('$entryPath must be one of ${_allowedStatuses.join(', ')}');
    }
  }
}

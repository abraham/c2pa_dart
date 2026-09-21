import 'dart:convert';
import 'dart:io';

import '../campaign.dart';

/// Writes a mutation campaign report as VM-only JSON to absolute [path].
///
/// Creates parent directories as needed and throws [ArgumentError] for
/// relative paths; this uses `dart:io` and is not web-safe.
Future<void> writeMutationCampaignReport(
  String path,
  MutationCampaignReport report,
) async {
  final uri = Uri.file(path);
  if (!uri.isAbsolute) {
    throw ArgumentError.value(path, 'path', 'must be absolute');
  }
  final file = File.fromUri(uri);
  await file.parent.create(recursive: true);
  await file.writeAsString(
    const JsonEncoder.withIndent(' ').convert(report.toJson()),
    flush: true,
  );
}

/// Reads a VM-only mutation campaign report JSON file from absolute [path].
///
/// Throws [ArgumentError] for relative paths and [FormatException] when the
/// decoded root is not a JSON object.
Future<MutationCampaignReport> readMutationCampaignReport(String path) async {
  final uri = Uri.file(path);
  if (!uri.isAbsolute) {
    throw ArgumentError.value(path, 'path', 'must be absolute');
  }
  final decoded = jsonDecode(await File.fromUri(uri).readAsString());
  if (decoded is! Map<String, Object?>) {
    throw const FormatException('Campaign report must be a JSON object.');
  }
  return MutationCampaignReport.fromJson(decoded);
}

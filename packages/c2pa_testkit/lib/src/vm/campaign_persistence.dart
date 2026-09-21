import 'dart:convert';
import 'dart:io';

import '../campaign.dart';

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

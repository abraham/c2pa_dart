/// Corpus conformance gate: this SDK vs. a pinned `c2patool` reference build.
///
/// Reads every asset in a corpus with both implementations and fails if any
/// asset produces a semantically different validation report. See
/// `conformance_pins.json` for the pinned reference build and corpus commit,
/// and `../lib/src/oracle_report_comparison.dart` for what counts as a
/// difference.
///
/// Usage:
///   `dart run tool/conformance.dart --oracle <c2patool> --corpus <dir>`
library;

import 'dart:convert';
import 'dart:io';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_io/c2pa_io_vm.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';

const _assetExtensions = {
  '.avi',
  '.avif',
  '.c2pa',
  '.dng',
  '.flac',
  '.gif',
  '.heic',
  '.heif',
  '.jpeg',
  '.jpg',
  '.jxl',
  '.m4a',
  '.mov',
  '.mp3',
  '.mp4',
  '.pdf',
  '.png',
  '.svg',
  '.tif',
  '.tiff',
  '.wav',
  '.webp',
  '.zip',
};

const _oracleTimeout = Duration(seconds: 120);

Future<void> main(List<String> arguments) async {
  // Dart ignores a value returned from `main`, so the status has to be set
  // explicitly or a failing gate would exit 0 and pass CI.
  exitCode = await _run(arguments);
}

Future<int> _run(List<String> arguments) async {
  final options = _Options.parse(arguments);
  if (options == null) {
    stderr.writeln(
      'Usage: dart run tool/conformance.dart --oracle <c2patool> '
      '--corpus <name>=<dir> [--corpus <name>=<dir>...] [--pins <file>] '
      '[--json <file>] [--strict-trust]',
    );
    return 64;
  }

  if (!File(options.oracle).existsSync()) {
    stderr.writeln('Reference c2patool not found at ${options.oracle}');
    return 66;
  }

  final pins = _Pins.load(options.pinsPath);
  final assets = _collectAssets(options.corpora);
  if (assets.isEmpty) {
    stderr.writeln(
      'No assets found under: '
      '${options.corpora.map((corpus) => corpus.path).join(', ')}\n'
      'The corpus checkout is probably missing or empty.',
    );
    return 66;
  }

  stdout.writeln('Reference: ${options.oracle}');
  stdout.writeln('Assets:    ${assets.length}');
  if (options.strictTrust) {
    stdout.writeln('Scoring:   strict (trust-store statuses included)');
  }
  stdout.writeln('');

  final records = <Map<String, Object?>>[];
  final unexpected = <String, List<String>>{};
  final resolved = <String>[];
  var agreed = 0;
  var bothRejected = 0;

  for (var index = 0; index < assets.length; index++) {
    final asset = assets[index];
    final oracle = await _oracleReport(options.oracle, asset.path);
    final dart = await _dartReport(asset.path);
    final comparison = compareOracleReports(
      oracleReport: oracle,
      dartReport: dart,
      ignoreTrustConfiguration: !options.strictTrust,
    );

    final position = '[${index + 1}/${assets.length}]';
    final allowed = pins.knownDivergences[asset.key];
    final kinds = comparison.differences.map((d) => d.kind).toSet().toList()
      ..sort();

    if (comparison.agrees) {
      agreed++;
      if (comparison.bothRejected) bothRejected++;
      if (allowed != null) {
        resolved.add(asset.key);
        stdout.writeln('$position RESOLVED    ${asset.key}');
      } else {
        final tag = comparison.bothRejected ? 'both-reject' : 'ok';
        stdout.writeln('$position ${tag.padRight(11)} ${asset.key}');
      }
    } else if (allowed != null && _setEquals(allowed, kinds)) {
      agreed++;
      stdout.writeln('$position known-diff  ${asset.key}');
    } else {
      unexpected[asset.key] = kinds;
      stdout.writeln('$position DIFF        ${asset.key}');
      for (final difference in comparison.differences) {
        stdout.writeln('            - $difference');
      }
    }

    records.add({
      'asset': asset.key,
      'bothRejected': comparison.bothRejected,
      'differences': [
        for (final difference in comparison.differences)
          {
            'kind': difference.kind,
            if (difference.items.isNotEmpty) 'items': difference.items,
            if (difference.oracle != null) 'oracle': difference.oracle,
            if (difference.dart != null) 'dart': difference.dart,
          },
      ],
    });
  }

  stdout.writeln('');
  stdout.writeln(
    '=== $agreed/${assets.length} assets agree '
    '($bothRejected by both rejecting, '
    '${agreed - bothRejected} on full report) ===',
  );
  if (!options.strictTrust) {
    stdout.writeln(
      '    Trust-store-dependent statuses are excluded from scoring; '
      'pass --strict-trust to include them.',
    );
  }

  if (options.jsonPath != null) {
    File(options.jsonPath!).writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert(records)}\n',
    );
    stdout.writeln('    Wrote ${options.jsonPath}');
  }

  var failed = false;

  final drift = _corpusDrift(pins, options.corpora, assets);
  if (drift.isNotEmpty) {
    stderr.writeln(
      '\nCorpus drift:\n${drift.map((line) => '  $line').join('\n')}\n'
      'Every corpus named in ${options.pinsPath} must be supplied with the '
      'pinned number of assets.\nUpdate the pins file if a corpus moved on '
      'purpose.',
    );
    failed = true;
  }

  if (unexpected.isNotEmpty) {
    stderr.writeln('\n${unexpected.length} asset(s) diverge from c2pa-rs:');
    for (final entry in unexpected.entries) {
      stderr.writeln('  ${entry.key}');
      for (final kind in entry.value) {
        stderr.writeln('    - $kind');
      }
    }
    failed = true;
  }

  final assetKeys = {for (final asset in assets) asset.key};
  final unmatched =
      pins.knownDivergences.keys
          .where((key) => !assetKeys.contains(key))
          .toList()
        ..sort();
  if (unmatched.isNotEmpty) {
    stderr.writeln(
      '\n${unmatched.length} "knownDivergences" entr(ies) match no asset.\n'
      'A typo or a renamed asset would otherwise silently disable the '
      'exemption:',
    );
    for (final key in unmatched) {
      stderr.writeln('  $key');
    }
    failed = true;
  }

  if (resolved.isNotEmpty) {
    stderr.writeln(
      '\n${resolved.length} asset(s) listed in "knownDivergences" now agree.\n'
      'Remove them from ${options.pinsPath} so the gate keeps protecting them:',
    );
    for (final key in resolved) {
      stderr.writeln('  $key');
    }
    failed = true;
  }

  if (failed) return 1;
  stdout.writeln('\nConformance gate passed.');
  return 0;
}

/// Runs the reference implementation.
///
/// Returns `null` when it declines to produce a report, which is a legitimate
/// outcome for a malformed asset and is compared as such.
Future<Map<String, Object?>?> _oracleReport(String oracle, String path) async {
  try {
    final result = await Process.run(oracle, [path]).timeout(_oracleTimeout);
    return _decodeReport(result.stdout);
  } on Object {
    return null;
  }
}

/// Produces this SDK's report in-process.
///
/// Deliberately mirrors what `c2patool_dart inspect` does by default: no
/// network access and no configured trust anchors.
Future<Map<String, Object?>?> _dartReport(String path) async {
  FileByteSource? source;
  try {
    source = await FileByteSource.open(path);
    final reader = await C2paReader.fromSource(
      source: source,
      fileName: path,
      context: C2paContext(),
    );
    return reader.toSdkJson();
  } on Object {
    return null;
  } finally {
    await source?.close();
  }
}

Map<String, Object?>? _decodeReport(Object? stdoutValue) {
  final text = stdoutValue is String
      ? stdoutValue
      : utf8.decode(stdoutValue as List<int>, allowMalformed: true);
  final start = text.indexOf('{');
  if (start < 0) return null;
  try {
    final decoded = jsonDecode(text.substring(start));
    return decoded is Map<String, Object?> ? decoded : null;
  } on FormatException {
    return null;
  }
}

/// Reports each pinned corpus that is absent or no longer the pinned size.
///
/// Scoped per corpus so a missing one cannot hide behind another's assets.
List<String> _corpusDrift(
  _Pins pins,
  List<_Corpus> supplied,
  List<_Asset> assets,
) {
  final counts = <String, int>{};
  for (final asset in assets) {
    counts[asset.corpus] = (counts[asset.corpus] ?? 0) + 1;
  }
  final suppliedNames = {for (final corpus in supplied) corpus.name};
  final drift = <String>[];
  for (final entry in pins.expectedAssetCounts.entries) {
    if (!suppliedNames.contains(entry.key)) {
      drift.add('"${entry.key}" was not supplied with --corpus');
      continue;
    }
    final found = counts[entry.key] ?? 0;
    if (found != entry.value) {
      drift.add('"${entry.key}": expected ${entry.value} assets, found $found');
    }
  }
  for (final name in suppliedNames) {
    if (!pins.expectedAssetCounts.containsKey(name)) {
      drift.add('"$name" is not pinned in the pins file');
    }
  }
  return drift;
}

List<_Asset> _collectAssets(List<_Corpus> corpora) {
  final separator = Platform.pathSeparator;
  final assets = <_Asset>[];
  for (final corpus in corpora) {
    final root = Directory(corpus.path);
    if (!root.existsSync()) continue;
    final rootPath = root.absolute.path;
    for (final entry in root.listSync(recursive: true, followLinks: false)) {
      if (entry is! File) continue;
      final path = entry.absolute.path;
      if (path.contains('$separator.git$separator')) continue;
      final dot = path.lastIndexOf('.');
      if (dot < 0) continue;
      if (!_assetExtensions.contains(path.substring(dot).toLowerCase())) {
        continue;
      }
      final relative = path
          .substring(rootPath.length + 1)
          .replaceAll(separator, '/');
      assets.add(
        _Asset(
          path: path,
          corpus: corpus.name,
          key: '${corpus.name}/$relative',
        ),
      );
    }
  }
  assets.sort((left, right) => left.key.compareTo(right.key));
  return assets;
}

bool _setEquals(List<String> left, List<String> right) =>
    left.length == right.length && left.toSet().containsAll(right);

final class _Asset {
  const _Asset({required this.path, required this.corpus, required this.key});

  /// Absolute path on disk.
  final String path;

  /// Which pinned corpus this asset came from.
  final String corpus;

  /// `<corpus>/<relative path>`, stable enough to pin in
  /// `conformance_pins.json` and unambiguous when corpora overlap.
  final String key;
}

final class _Pins {
  const _Pins({
    required this.knownDivergences,
    required this.expectedAssetCounts,
  });

  factory _Pins.load(String path) {
    final file = File(path);
    if (!file.existsSync()) {
      return const _Pins(knownDivergences: {}, expectedAssetCounts: {});
    }
    final root = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
    final divergences = root['knownDivergences'] as Map<String, Object?>? ?? {};
    final corpora = root['corpora'] as Map<String, Object?>? ?? {};
    return _Pins(
      expectedAssetCounts: {
        for (final entry in corpora.entries)
          entry.key:
              (entry.value! as Map<String, Object?>)['expectedAssetCount']
                  as int,
      },
      knownDivergences: {
        for (final entry in divergences.entries)
          entry.key: [
            for (final kind in entry.value! as List<Object?>) kind.toString(),
          ],
      },
    );
  }

  /// `<corpus>/<relative path>` -> the difference kinds accepted for it.
  final Map<String, List<String>> knownDivergences;

  /// Corpus name -> how many assets it must contain.
  ///
  /// Catches both a checkout that silently produced nothing and a corpus pin
  /// that moved without anyone noticing.
  final Map<String, int> expectedAssetCounts;
}

/// A named corpus root, so findings and counts stay attributable when the
/// gate runs over more than one.
final class _Corpus {
  const _Corpus({required this.name, required this.path});

  final String name;
  final String path;
}

final class _Options {
  const _Options({
    required this.oracle,
    required this.corpora,
    required this.pinsPath,
    required this.jsonPath,
    required this.strictTrust,
  });

  static _Options? parse(List<String> arguments) {
    String? oracle;
    final corpora = <_Corpus>[];
    var pins = 'tool/conformance_pins.json';
    String? json;
    var strictTrust = false;

    for (var index = 0; index < arguments.length; index++) {
      final argument = arguments[index];
      String next() {
        if (index + 1 >= arguments.length) {
          throw FormatException('$argument requires a value');
        }
        return arguments[++index];
      }

      switch (argument) {
        case '--oracle':
          oracle = next();
        case '--corpus':
          final value = next();
          final split = value.indexOf('=');
          if (split <= 0) return null;
          corpora.add(
            _Corpus(
              name: value.substring(0, split),
              path: value.substring(split + 1),
            ),
          );
        case '--pins':
          pins = next();
        case '--json':
          json = next();
        case '--strict-trust':
          strictTrust = true;
        default:
          return null;
      }
    }

    if (oracle == null || corpora.isEmpty) return null;
    return _Options(
      oracle: oracle,
      corpora: corpora,
      pinsPath: pins,
      jsonPath: json,
      strictTrust: strictTrust,
    );
  }

  final String oracle;
  final List<_Corpus> corpora;
  final String pinsPath;
  final String? jsonPath;
  final bool strictTrust;
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';

import 'actions.dart';
import 'claim.dart';
import 'compressed_manifest.dart';
import 'ingredient.dart';
import 'reader.dart';
import 'validation.dart';

/// Controls how binary values are represented in reader reports.
enum C2paBinaryOutput {
  /// Emit binary values as RFC 4648 base64 strings.
  base64,

  /// Replace non-cryptographic binary payloads with their byte length.
  redact,
}

/// Stable JSON encoding options shared by all reader report projections.
final class C2paJsonOptions {
  /// Creates report JSON options.
  const C2paJsonOptions({
    this.pretty = false,
    this.binaryOutput = C2paBinaryOutput.redact,
  });

  /// Whether encoded JSON should use two-space indentation.
  final bool pretty;

  /// How binary values are represented in report projections.
  final C2paBinaryOutput binaryOutput;
}

/// Deterministic report projections for a parsed [C2paReader].
extension C2paReaderReports on C2paReader {
  /// Returns the public SDK-style manifest report.
  Map<String, Object?> toSdkJson({
    C2paJsonOptions options = const C2paJsonOptions(),
  }) => _ReportExporter(this, options).sdk();

  /// Returns a low-level report with claims, raw assertions, and unknown boxes.
  Map<String, Object?> toDetailedJson({
    C2paJsonOptions options = const C2paJsonOptions(),
  }) => _ReportExporter(this, options).detailed();

  /// Returns a crJSON 2.3.0 projection.
  Map<String, Object?> toCrJson({
    C2paJsonOptions options = const C2paJsonOptions(),
  }) => _ReportExporter(this, options).crJson();

  /// Encodes [toSdkJson] as a JSON string.
  String encodeSdkJson({C2paJsonOptions options = const C2paJsonOptions()}) =>
      _encodeReport(toSdkJson(options: options), options);

  /// Encodes [toDetailedJson] as a JSON string.
  String encodeDetailedJson({
    C2paJsonOptions options = const C2paJsonOptions(),
  }) => _encodeReport(toDetailedJson(options: options), options);

  /// Encodes [toCrJson] as a JSON string.
  String encodeCrJson({C2paJsonOptions options = const C2paJsonOptions()}) =>
      _encodeReport(toCrJson(options: options), options);
}

final class _ReportExporter {
  const _ReportExporter(this.reader, this.options);

  static const _crJsonVersion = '2.3.0';
  static const _generatorVersion = '0.1.0-dev.1';
  // c2pa-rs omits these hard bindings from a manifest's public assertion list
  // but deliberately keeps `c2pa.hash.bmff`, which stays visible to callers.
  static const _hardBindingLabels = {
    'c2pa.hash.boxes',
    'c2pa.hash.data',
    'c2pa.hash.collection.data',
  };

  final C2paReader reader;
  final C2paJsonOptions options;

  Map<String, Object?> sdk() {
    final manifests = <String, Object?>{};
    for (final entry in reader.manifests.entries) {
      manifests[entry.key] = _sdkManifest(entry.value);
    }
    return _immutable({
      if (reader.activeManifestLabel != null)
        'active_manifest': reader.activeManifestLabel,
      'manifests': manifests,
      if (reader.validationResults.state == ValidationState.invalid)
        'validation_status': reader.validationResults.issues
            .map((issue) => issue.toJson())
            .toList(growable: false),
      'validation_results': reader.validationResults.toJson(),
      'validation_state': _sdkValidationState(reader.validationResults.state),
    });
  }

  Map<String, Object?> detailed() {
    final manifests = <String, Object?>{};
    for (final entry in reader.manifests.entries) {
      manifests[entry.key] = _detailedManifest(entry.value);
    }
    return _immutable({
      if (reader.activeManifestLabel != null)
        'active_manifest': reader.activeManifestLabel,
      'manifests': manifests,
      'validation_results': reader.validationResults.toJson(),
      'validation_state': _sdkValidationState(reader.validationResults.state),
      'raw_manifest_store': _binary(reader.manifestBytes),
      'raw_manifest_entries': reader.rawManifestEntries
          .map(
            (box) => {
              'box_type': box.boxType,
              if (box.label != null) 'label': box.label,
              if (box.contentType != null) 'content_type': box.contentType,
              'raw': _binary(box.bytes),
            },
          )
          .toList(growable: false),
    });
  }

  Map<String, Object?> crJson() {
    final entries = reader.manifests.values.toList(growable: false);
    final active = reader.activeManifestLabel;
    final ordered = [
      ...entries.where((entry) => entry.label == active),
      ...entries.reversed.where((entry) => entry.label != active),
    ];
    return _immutable({
      '@context': {
        '@vocab': 'https://c2pa.org/crjson',
        'extras': 'https://c2pa.org/crjson/extras',
      },
      'manifests': ordered
          .map((entry) => _crJsonManifest(entry, entry.label == active))
          .toList(growable: false),
      'jsonGenerator': {'name': 'c2pa-dart', 'version': _generatorVersion},
    });
  }

  Map<String, Object?> _sdkManifest(C2paManifestEntry entry) {
    final claim = entry.claim;
    final resources = _resources(entry);
    final thumbnail = _sdkThumbnail(entry);
    final publicAssertions = <Object?>[];
    for (final assertion in _assertions(entry)) {
      if (assertion.label.startsWith(IngredientAssertion.label) ||
          _isThumbnail(assertion.label) ||
          _isHardBinding(assertion.label)) {
        continue;
      }
      final data = _sdkAssertionValue(
        assertion.label,
        _jsonValue(assertion.value),
      );
      publicAssertions.add({
        'label': _sdkAssertionLabel(assertion.label),
        if (_labelInstance(assertion.label) > 0)
          'instance': _labelInstance(assertion.label),
        'data': data,
        if (assertion.kind == 'json') 'kind': 'Json',
      });
    }
    return {
      if (claim != null) 'claim_version': claim.version.number,
      if (claim?.claimGenerator != null)
        'claim_generator': claim!.claimGenerator,
      if (claim != null)
        'claim_generator_info': claim.claimGeneratorInfo
            .map((info) => _jsonValue(info.toCborMap()))
            .toList(growable: false),
      if (claim?.title != null) 'title': claim!.title,
      if (claim?.format != null) 'format': claim!.format,
      if (claim != null) 'instance_id': claim.instanceId,
      'thumbnail': ?thumbnail,
      if (entry.ingredients.isNotEmpty)
        'ingredients': entry.ingredients
            .map((ingredient) => _sdkIngredient(entry, ingredient))
            .toList(growable: false),
      if (entry.identityAssertions.isNotEmpty)
        'identity_assertions': entry.identityAssertions
            .map((identity) => identity.toJson())
            .toList(growable: false),
      'assertions': publicAssertions,
      if (entry.signatureInfo != null)
        'signature_info': {
          ...entry.signatureInfo!.toJson(),
          'alg': _sdkAlgorithm(entry.signatureInfo!.algorithm),
        },
      if (resources.isNotEmpty) 'resources': resources,
      'compression': _compression(entry),
      'label': entry.label,
    };
  }

  Map<String, Object?> _detailedManifest(C2paManifestEntry entry) {
    final claim = entry.claim;
    final resources = _resources(entry);
    final assertionStore = <String, Object?>{};
    final assertionDetails = <Object?>[];
    for (final assertion in _assertions(entry)) {
      final key = _uniqueKey(assertionStore, assertion.label);
      assertionStore[key] = _jsonValue(assertion.value);
      assertionDetails.add({
        'label': assertion.label,
        'instance': assertion.instance,
        'kind': assertion.kind,
        'content_type': assertion.contentType,
        'value': _jsonValue(assertion.value),
        'raw': _binary(assertion.rawBytes),
      });
    }
    return {
      if (claim != null)
        'claim': {
          ...?_jsonValue(claim.toCborMap()) as Map<String, Object?>?,
          'claim_version': claim.version.number,
          'raw': _binary(claim.rawBytes),
        },
      'assertion_store': assertionStore,
      'assertions': assertionDetails,
      if (entry.signatureInfo != null)
        'signature': entry.signatureInfo!.toJson(),
      if (entry.signatureBytes != null)
        'raw_signature': _binary(entry.signatureBytes!),
      if (entry.identityAssertions.isNotEmpty)
        'identity_assertions': entry.identityAssertions
            .map((identity) => identity.toJson())
            .toList(growable: false),
      if (resources.isNotEmpty) 'resources': resources,
      'compression': _compression(entry),
      'unknown_boxes': entry.unknownBoxes
          .map(
            (box) => {
              'box_type': box.boxType,
              if (box.label != null) 'label': box.label,
              if (box.contentType != null) 'content_type': box.contentType,
              'raw': _binary(box.bytes),
            },
          )
          .toList(growable: false),
      'structural_issues': entry.structuralIssues
          .map((issue) => issue.toJson())
          .toList(growable: false),
      'cryptographic_issues': entry.cryptographicIssues
          .map((issue) => issue.toJson())
          .toList(growable: false),
    };
  }

  Map<String, Object?> _compression(C2paManifestEntry entry) => {
    'state': entry.compression.name,
    'stored_bytes': entry.storedSize,
    'logical_bytes': entry.logicalSize,
    'read_supported': C2paCapabilities.compressedManifests.canReadBrotli,
    'write_supported': C2paCapabilities.compressedManifests.canWriteBrotli,
  };

  Map<String, Object?> _crJsonManifest(C2paManifestEntry entry, bool isActive) {
    final claim = entry.claim;
    final assertions = <String, Object?>{};
    for (final assertion in _assertions(entry)) {
      assertions[_uniqueKey(assertions, assertion.label)] = _crJsonAssertion(
        entry,
        assertion,
      );
    }
    final statuses = _statusesFor(entry, isActive);
    final ingredientDeltas = _ingredientDeltasFor(entry);
    final claimJson = claim == null ? null : _crJsonClaim(claim);
    return {
      'label': entry.label,
      'assertions': assertions,
      if (claim is ClaimV1) 'claim': claimJson,
      if (claim is ClaimV2) 'claim.v2': claimJson,
      'signature': _crJsonSignature(entry),
      'validationResults': {
        ...statuses.toJson(),
        'specVersion': _crJsonVersion,
        'validationTime':
            (reader.validationResults.validationTime ??
                    DateTime.fromMillisecondsSinceEpoch(0, isUtc: true))
                .toUtc()
                .toIso8601String(),
      },
      if (ingredientDeltas.isNotEmpty)
        'ingredientDeltas': ingredientDeltas
            .map((delta) => delta.toJson())
            .toList(growable: false),
    };
  }

  StatusCodes _statusesFor(C2paManifestEntry entry, bool isActive) {
    if (isActive) {
      return reader.validationResults.activeManifest ?? StatusCodes();
    }
    for (final parent in reader.manifests.values) {
      final rawIngredients = parent.assertions
          .where(
            (assertion) =>
                assertion.label?.startsWith(IngredientAssertion.label) ?? false,
          )
          .toList(growable: false);
      for (
        var index = 0;
        index < parent.ingredients.length && index < rawIngredients.length;
        index++
      ) {
        final ingredient = parent.ingredients[index];
        final target = _manifestLabelFromUri(
          ingredient.activeManifest?.url ?? ingredient.c2paManifest?.url,
        );
        if (target != entry.label) continue;
        final assertionLabel = rawIngredients[index].label;
        for (final delta
            in reader.validationResults.ingredientDeltas ??
                const <IngredientDeltaValidationResult>[]) {
          if (_manifestLabelFromUri(delta.ingredientAssertionUri) ==
                  parent.label &&
              assertionLabel != null &&
              delta.ingredientAssertionUri.endsWith('/$assertionLabel')) {
            return delta.validationDeltas;
          }
        }
      }
    }
    return StatusCodes();
  }

  List<IngredientDeltaValidationResult> _ingredientDeltasFor(
    C2paManifestEntry entry,
  ) => [
    for (final delta
        in reader.validationResults.ingredientDeltas ??
            const <IngredientDeltaValidationResult>[])
      if (_manifestLabelFromUri(delta.ingredientAssertionUri) == entry.label)
        delta,
  ];

  Map<String, Object?> _crJsonClaim(Claim claim) {
    final common = <String, Object?>{
      'instanceID': claim.instanceId,
      'signature': _absoluteJumbfUrl(claim.label, claim.signatureUri),
      'claim_generator_info': claim is ClaimV1
          ? claim.claimGeneratorInfo
                .map((info) => _crJsonValue(info.toCborMap()))
                .toList(growable: false)
          : _crJsonValue(claim.claimGeneratorInfo.first.toCborMap()),
      if (claim.algorithm != null) 'alg': claim.algorithm,
      if (claim.softAlgorithm != null) 'alg_soft': claim.softAlgorithm,
      if (claim.title != null) 'dc:title': claim.title,
      if (claim.redactions.isNotEmpty) 'redacted_assertions': claim.redactions,
    };
    if (claim is ClaimV1) {
      common['claim_generator'] = claim.claimGenerator;
      common['dc:format'] = claim.format;
      common['assertions'] = claim.assertions
          .map((reference) => _crJsonReference(claim.label, reference, true))
          .toList(growable: false);
    } else {
      common['created_assertions'] = claim.createdAssertions
          .map((reference) => _crJsonReference(claim.label, reference, false))
          .toList(growable: false);
      if (claim.gatheredAssertions.isNotEmpty) {
        common['gathered_assertions'] = claim.gatheredAssertions
            .map((reference) => _crJsonReference(claim.label, reference, false))
            .toList(growable: false);
      }
    }
    final metadata = claim.unknownFields['metadata'];
    if (metadata != null) common['metadata'] = _crJsonValue(metadata);
    return common;
  }

  Map<String, Object?> _crJsonReference(
    String label,
    ClaimHashedUri reference,
    bool absolute,
  ) => {
    'url': absolute ? _absoluteJumbfUrl(label, reference.url) : reference.url,
    'hash': "b64'${base64.encode(reference.hash)}'",
    if (reference.algorithm != null) 'alg': reference.algorithm,
  };

  Object? _crJsonAssertion(
    C2paManifestEntry entry,
    _AssertionReport assertion,
  ) {
    if (assertion.kind == 'binary' || assertion.kind == 'uuid') {
      ClaimHashedUri? reference;
      for (final candidate
          in entry.claim?.assertions ?? const <ClaimHashedUri>[]) {
        if (candidate.url.endsWith('/${assertion.label}') ||
            candidate.url.endsWith('=${assertion.label}')) {
          reference = candidate;
          break;
        }
      }
      if (reference != null) {
        return {
          'format': assertion.contentType ?? 'application/octet-stream',
          'identifier': _assertionUri(entry.label, assertion.label),
          'hash': "b64'${base64.encode(reference.hash)}'",
        };
      }
    }
    return _crJsonValue(assertion.value);
  }

  Map<String, Object?> _crJsonSignature(C2paManifestEntry entry) {
    final info = entry.signatureInfo;
    final emptyTime = DateTime.fromMillisecondsSinceEpoch(
      0,
      isUtc: true,
    ).toIso8601String();
    final certificate = {
      'serialNumber': info?.serialNumber ?? '',
      'issuer': info?.issuer == null
          ? <String, Object?>{}
          : {'organizationName': info!.issuer},
      'subject': info?.commonName == null
          ? <String, Object?>{}
          : {'commonName': info!.commonName},
      'validity': {
        'notBefore': info?.notBefore.toUtc().toIso8601String() ?? emptyTime,
        'notAfter': info?.notAfter.toUtc().toIso8601String() ?? emptyTime,
      },
    };
    return {
      'algorithm': info?.algorithm ?? 'unknown',
      'certificateInfo': certificate,
    };
  }

  Map<String, Object?> _sdkIngredient(
    C2paManifestEntry entry,
    IngredientAssertion ingredient,
  ) => {
    ...?_jsonValue(ingredient.unknownFields) as Map<String, Object?>?,
    'label': ingredient.assertionLabel,
    if (ingredient.title != null) 'title': ingredient.title,
    if (ingredient.format != null) 'format': ingredient.format,
    if (ingredient.instanceId != null) 'instance_id': ingredient.instanceId,
    if (ingredient.documentId != null) 'document_id': ingredient.documentId,
    'relationship': ingredient.relationship.name,
    if (ingredient.thumbnail != null)
      'thumbnail':
          _sdkResourceReference(entry, ingredient.thumbnail!.url) ??
          _jsonValue(ingredient.thumbnail!.toCborMap()),
    if (ingredient.data != null)
      'data': _jsonValue(ingredient.data!.toCborMap()),
    if (ingredient.c2paManifest != null)
      'c2pa_manifest': _jsonValue(ingredient.c2paManifest!.toCborMap()),
    if (ingredient.activeManifest != null)
      'active_manifest': _jsonValue(ingredient.activeManifest!.toCborMap()),
    if (ingredient.claimSignature != null)
      'claim_signature': _jsonValue(ingredient.claimSignature!.toCborMap()),
    if (ingredient.validationStatus != null)
      'validation_status': ingredient.validationStatus!
          .map((status) => status.toJson())
          .toList(growable: false),
    if (ingredient.validationResults != null)
      'validation_results': ingredient.validationResults!.toJson(),
    if (ingredient.description != null) 'description': ingredient.description,
    if (ingredient.metadata.isNotEmpty) 'metadata': ingredient.metadata,
  };

  Map<String, Object?>? _sdkThumbnail(C2paManifestEntry entry) {
    for (final assertion in _assertions(entry)) {
      if (_isThumbnail(assertion.label)) {
        return {
          'format': assertion.contentType ?? 'application/octet-stream',
          'identifier': _assertionUri(entry.label, assertion.label),
        };
      }
    }
    return null;
  }

  Map<String, Object?>? _sdkResourceReference(
    C2paManifestEntry entry,
    String uri,
  ) {
    final label = uri.split('/').last;
    for (final assertion in _assertions(entry)) {
      if (assertion.label == label) {
        return {
          'format': assertion.contentType ?? 'application/octet-stream',
          'identifier': uri,
        };
      }
    }
    return null;
  }

  List<_AssertionReport> _assertions(C2paManifestEntry entry) {
    final reports = <_AssertionReport>[];
    final counts = <String, int>{};
    for (final box in entry.assertions) {
      final label = box.label ?? box.boxType;
      final instance = counts.update(
        label,
        (value) => value + 1,
        ifAbsent: () => 1,
      );
      reports.add(_decodeAssertion(box, label, instance));
    }
    return reports;
  }

  Map<String, Object?> _resources(C2paManifestEntry entry) {
    final resources = <String, Object?>{};
    for (final raw in entry.unknownBoxes) {
      if (raw.contentType != JumbfUuid.c2paDataBoxes) continue;
      try {
        final store = parseJumbf(raw.bytes);
        for (final child in store.children.whereType<JumbfSuperBoxNode>()) {
          final label = child.label;
          if (label == null) continue;
          final cbor = child.children.whereType<JumbfCborNode>().firstOrNull;
          if (cbor == null) continue;
          final value = _decodeReportCbor(cbor.payload);
          resources[_uniqueKey(resources, label)] = _jsonValue(value);
        }
      } on Object {
        resources[raw.label ?? 'c2pa.databoxes'] = {'raw': _binary(raw.bytes)};
      }
    }
    return resources;
  }

  _AssertionReport _decodeAssertion(
    C2paRawBox box,
    String label,
    int instance,
  ) {
    try {
      final node = parseJumbf(box.bytes);
      for (final child in node.children) {
        if (child is JumbfCborNode) {
          return _AssertionReport(
            label: label,
            instance: instance,
            kind: 'cbor',
            contentType: box.contentType,
            value: _decodeReportCbor(child.payload),
            rawBytes: box.bytes,
          );
        }
        if (child is JumbfJsonNode) {
          return _AssertionReport(
            label: label,
            instance: instance,
            kind: 'json',
            contentType: box.contentType,
            value: jsonDecode(utf8.decode(child.payload)),
            rawBytes: box.bytes,
          );
        }
        if (child is JumbfEmbeddedFileNode) {
          final description = node.children
              .whereType<JumbfEmbeddedFileDescriptionNode>()
              .firstOrNull;
          return _AssertionReport(
            label: label,
            instance: instance,
            kind: 'binary',
            contentType: description?.mediaType ?? box.contentType,
            value: {
              'format': description?.mediaType ?? 'application/octet-stream',
              'identifier': label,
              'data': child.payload,
            },
            rawBytes: box.bytes,
          );
        }
        if (child is JumbfUuidNode) {
          return _AssertionReport(
            label: label,
            instance: instance,
            kind: 'uuid',
            contentType: box.contentType,
            value: {'uuid': _hex(child.userType), 'data': child.payload},
            rawBytes: box.bytes,
          );
        }
      }
    } on Object {
      // Preserve undecodable assertions below.
    }
    return _AssertionReport(
      label: label,
      instance: instance,
      kind: 'binary',
      contentType: box.contentType,
      value: {'data': box.bytes},
      rawBytes: box.bytes,
    );
  }

  Object? _crJsonValue(Object? value, {String? key}) {
    if (value is Uint8List || value is List<int>) {
      final bytes = value is Uint8List
          ? value
          : Uint8List.fromList(value as List<int>);
      if (key == 'hash' || key == 'pad' || key == 'pad2') {
        return "b64'${base64.encode(bytes)}'";
      }
      return _binary(bytes);
    }
    if (value is Map) {
      final result = <String, Object?>{};
      for (final entry in value.entries) {
        final name = entry.key.toString();
        result[name] = _crJsonValue(entry.value, key: name);
      }
      if (result.containsKey('hash') && !result.containsKey('pad')) {
        result['pad'] = "b64''";
      }
      return result;
    }
    if (value is Iterable) {
      return value.map((item) => _crJsonValue(item, key: key)).toList();
    }
    return _jsonValue(value, key: key);
  }

  Object? _jsonValue(Object? value, {String? key}) {
    if (value == null || value is String || value is bool || value is int) {
      return value;
    }
    if (value is double) return value.isFinite ? value : value.toString();
    if (value is BigInt) return value.toString();
    if (value is DateTime) return value.toUtc().toIso8601String();
    if (value is Uint8List || value is List<int>) {
      final bytes = value is Uint8List
          ? value
          : Uint8List.fromList(value as List<int>);
      if (key == 'hash') return base64.encode(bytes);
      return _binary(bytes);
    }
    if (value is Map) {
      final result = <String, Object?>{};
      for (final entry in value.entries) {
        final name = entry.key.toString();
        result[name] = _jsonValue(entry.value, key: name);
      }
      return result;
    }
    if (value is Iterable) {
      return value.map((item) => _jsonValue(item, key: key)).toList();
    }
    return value.toString();
  }

  String _binary(List<int> bytes) =>
      options.binaryOutput == C2paBinaryOutput.base64
      ? base64.encode(bytes)
      : '<omitted> len = ${bytes.length}';

  Map<String, Object?> _immutable(Map<String, Object?> value) =>
      _frozenSorted(value) as Map<String, Object?>;

  static bool _isHardBinding(String label) =>
      _hardBindingLabels.any(label.startsWith);

  static bool _isThumbnail(String label) => label.startsWith('c2pa.thumbnail.');

  /// The instance number encoded in an assertion label's `__<n>` suffix.
  ///
  /// C2PA numbers repeated assertions from zero, so an unsuffixed label is
  /// instance 0 and `c2pa.soft-binding__1` is instance 1. This is a property
  /// of the label itself, not a count of how many times a label was seen.
  static int _labelInstance(String label) {
    final index = label.indexOf('__');
    if (index < 0) return 0;
    return int.tryParse(label.substring(index + 2)) ?? 0;
  }

  /// Maps an on-disk assertion label to the label c2pa-rs reports.
  ///
  /// c2pa-rs emits the typed assertion's declared version rather than the
  /// label carried in the JUMBF box, so an on-disk `c2pa.actions` surfaces as
  /// `c2pa.actions.v2` regardless of claim version or action contents. The
  /// `__<instance>` suffix is reported separately and is stripped here.
  static String _sdkAssertionLabel(String label) {
    final base = label.split('__').first;
    return base == ActionsAssertion.label
        ? ActionsAssertion.versionedLabel
        : base;
  }

  static Object? _sdkAssertionValue(String label, Object? value) {
    if (!label.startsWith('c2pa.actions') || value is! Map) return value;
    final actions = value['actions'];
    if (actions is! List) return value;
    return <String, Object?>{
      for (final entry in value.entries) entry.key.toString(): entry.value,
      'actions': [
        for (final item in actions)
          if (item is Map<Object?, Object?>)
            <String, Object?>{
              for (final entry in item.entries)
                if (entry.key != 'instanceId' && entry.key != 'instanceID')
                  entry.key.toString(): entry.value,
            }
          else
            item,
      ],
    };
  }
}

final class _AssertionReport {
  const _AssertionReport({
    required this.label,
    required this.instance,
    required this.kind,
    required this.contentType,
    required this.value,
    required this.rawBytes,
  });

  final String label;
  final int instance;
  final String kind;
  final String? contentType;
  final Object? value;
  final Uint8List rawBytes;
}

String _encodeReport(Map<String, Object?> value, C2paJsonOptions options) {
  final encoder = options.pretty
      ? const JsonEncoder.withIndent('  ')
      : const JsonEncoder();
  return encoder.convert(_sorted(value));
}

Object? _sorted(Object? value) {
  if (value is Map) {
    final keys = value.keys.map((key) => key.toString()).toList()..sort();
    return <String, Object?>{for (final key in keys) key: _sorted(value[key])};
  }
  if (value is Iterable) return value.map(_sorted).toList(growable: false);
  return value;
}

Object? _frozenSorted(Object? value) {
  if (value is Map) {
    final keys = value.keys.map((key) => key.toString()).toList()..sort();
    return Map<String, Object?>.unmodifiable({
      for (final key in keys) key: _frozenSorted(value[key]),
    });
  }
  if (value is Iterable) {
    return List<Object?>.unmodifiable(value.map(_frozenSorted));
  }
  return value;
}

String _uniqueKey(Map<String, Object?> values, String label) {
  if (!values.containsKey(label)) return label;
  var instance = 2;
  while (values.containsKey('${label}__$instance')) {
    instance++;
  }
  return '${label}__$instance';
}

/// c2pa-rs serialises `ValidationState` using its Rust variant names, so the
/// SDK-shaped report spells these capitalised rather than lower-case.
String _sdkValidationState(ValidationState state) => switch (state) {
  ValidationState.invalid => 'Invalid',
  ValidationState.valid => 'Valid',
  ValidationState.trusted => 'Trusted',
};

String _absoluteJumbfUrl(String manifestLabel, String value) {
  if (!value.startsWith('self#jumbf=')) return value;
  var path = value.substring('self#jumbf='.length);
  if (!path.startsWith('/')) path = '/$path';
  if (path.startsWith('/c2pa/')) return 'self#jumbf=$path';
  return 'self#jumbf=/c2pa/$manifestLabel$path';
}

String _assertionUri(String manifestLabel, String assertionLabel) =>
    'self#jumbf=/c2pa/$manifestLabel/c2pa.assertions/$assertionLabel';

String? _manifestLabelFromUri(String? value) {
  if (value == null) return null;
  final marker = value.indexOf('/c2pa/');
  if (marker < 0) return null;
  final start = marker + '/c2pa/'.length;
  final end = value.indexOf('/', start);
  return end < 0 ? value.substring(start) : value.substring(start, end);
}

String _sdkAlgorithm(String algorithm) {
  if (algorithm.isEmpty) return algorithm;
  return '${algorithm[0].toUpperCase()}${algorithm.substring(1).toLowerCase()}';
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Object? _decodeReportCbor(List<int> bytes) => decodeCbor(
  bytes,
  requireCanonicalMapOrder: false,
  allowIndefiniteLength: true,
);

import 'claim.dart';
import 'intent.dart';
import 'json_utils.dart';
import 'validation.dart';

enum IngredientAssertionVersion {
  v1(1),
  v2(2),
  v3(3);

  const IngredientAssertionVersion(this.number);
  final int number;
}

/// An asset type attached to an ingredient.
final class IngredientAssetType {
  IngredientAssetType({
    required this.type,
    this.version,
    Map<String, Object?> extra = const {},
  }) : extra = freezeJsonMap(extra);

  factory IngredientAssetType.fromCbor(Object? value) {
    final map = _stringMap(value, 'asset type');
    final type = map['type'];
    final version = map['version'];
    if (type is! String || (version != null && version is! String)) {
      throw const FormatException('Malformed ingredient asset type');
    }
    return IngredientAssetType(
      type: type,
      version: version as String?,
      extra: unknownFields(map, const {'type', 'version'}),
    );
  }

  final String type;
  final String? version;
  final Map<String, Object?> extra;

  Map<String, Object?> toCborMap() => {
    ...extra,
    'type': type,
    if (version != null) 'version': version,
  };

  @override
  bool operator ==(Object other) =>
      other is IngredientAssetType &&
      type == other.type &&
      version == other.version &&
      deepEquals(extra, other.extra);

  @override
  int get hashCode => Object.hash(type, version, deepHash(extra));
}

/// Typed ingredient assertion supporting specification versions 1, 2, and 3.
final class IngredientAssertion {
  IngredientAssertion({
    required this.version,
    required this.relationship,
    this.title,
    this.format,
    this.documentId,
    this.instanceId,
    this.thumbnail,
    this.data,
    this.c2paManifest,
    this.activeManifest,
    this.claimSignature,
    Iterable<ValidationIssue>? validationStatus,
    this.validationResults,
    this.description,
    this.informationalUri,
    Iterable<IngredientAssetType>? assetTypes,
    this.softBindingsMatched,
    Iterable<String>? softBindingAlgorithmsMatched,
    Map<String, Object?> metadata = const {},
    Map<String, Object?> unknownFields = const {},
  }) : validationStatus = validationStatus == null
           ? null
           : List<ValidationIssue>.unmodifiable(validationStatus),
       assetTypes = assetTypes == null
           ? null
           : List<IngredientAssetType>.unmodifiable(assetTypes),
       softBindingAlgorithmsMatched = softBindingAlgorithmsMatched == null
           ? null
           : List<String>.unmodifiable(softBindingAlgorithmsMatched),
       metadata = freezeJsonMap(metadata),
       unknownFields = freezeJsonMap(unknownFields) {
    if (version == IngredientAssertionVersion.v1 &&
        (title == null || format == null || instanceId == null)) {
      throw const FormatException(
        'Ingredient v1 requires title, format, and instanceID',
      );
    }
    if (version == IngredientAssertionVersion.v2 &&
        (title == null || format == null)) {
      throw const FormatException('Ingredient v2 requires title and format');
    }
    if (version == IngredientAssertionVersion.v3 &&
        activeManifest != null &&
        validationResults == null) {
      throw const FormatException(
        'Ingredient v3 activeManifest requires validationResults',
      );
    }
  }

  factory IngredientAssertion.fromCbor(
    Object? value, {
    required IngredientAssertionVersion version,
  }) {
    final map = _stringMap(value, 'ingredient');
    final relationship = _relationship(map['relationship']);
    final validationStatus = _optionalList(map['validationStatus'])
        ?.map((item) => ValidationIssue.fromJson(_stringMap(item, 'status')));
    final validationResults = map['validationResults'] == null
        ? null
        : ValidationResults.fromJson(
            _jsonMap(map['validationResults'], 'validationResults'),
          );
    final assetTypesValue = map['dataTypes'] ?? map['data_types'];
    return IngredientAssertion(
      version: version,
      relationship: relationship,
      title: _optionalString(map, 'dc:title'),
      format: _optionalString(map, 'dc:format'),
      documentId: _optionalString(map, 'documentID'),
      instanceId: _optionalString(map, 'instanceID'),
      thumbnail: _optionalHashedUri(map['thumbnail']),
      data: _optionalHashedUri(map['data']),
      c2paManifest: _optionalHashedUri(map['c2pa_manifest']),
      activeManifest: _optionalHashedUri(map['activeManifest']),
      claimSignature: _optionalHashedUri(map['claimSignature']),
      validationStatus: validationStatus,
      validationResults: validationResults,
      description: _optionalString(map, 'description'),
      informationalUri:
          _optionalString(map, 'informationalURI') ??
          _optionalString(map, 'informational_URI'),
      assetTypes: _optionalList(assetTypesValue)
          ?.map(IngredientAssetType.fromCbor),
      softBindingsMatched: map['softBindingsMatched'] as bool?,
      softBindingAlgorithmsMatched: _optionalList(
        map['softBindingAlgorithmsMatched'],
      )?.cast<String>(),
      metadata: map['metadata'] == null
          ? const {}
          : _stringMap(map['metadata'], 'metadata'),
      unknownFields: _unknown(map, _fieldsFor(version)),
    );
  }

  static const label = 'c2pa.ingredient';
  static const defaultVersion = IngredientAssertionVersion.v3;

  final IngredientAssertionVersion version;
  final Relationship relationship;
  final String? title;
  final String? format;
  final String? documentId;
  final String? instanceId;
  final ClaimHashedUri? thumbnail;
  final ClaimHashedUri? data;
  final ClaimHashedUri? c2paManifest;
  final ClaimHashedUri? activeManifest;
  final ClaimHashedUri? claimSignature;
  final List<ValidationIssue>? validationStatus;
  final ValidationResults? validationResults;
  final String? description;
  final String? informationalUri;
  final List<IngredientAssetType>? assetTypes;
  final bool? softBindingsMatched;
  final List<String>? softBindingAlgorithmsMatched;
  final Map<String, Object?> metadata;
  final Map<String, Object?> unknownFields;

  String get assertionLabel => version == IngredientAssertionVersion.v1
      ? label
      : '$label.v${version.number}';

  Map<String, Object?> toCborMap() {
    final map = <String, Object?>{
      ...unknownFields,
      'relationship': relationship.name,
    };
    if (version != IngredientAssertionVersion.v3) {
      map['dc:title'] = title;
      map['dc:format'] = format;
    } else {
      if (title != null) map['dc:title'] = title;
      if (format != null) map['dc:format'] = format;
    }
    if (documentId != null && version != IngredientAssertionVersion.v3) {
      map['documentID'] = documentId;
    }
    if (instanceId != null) map['instanceID'] = instanceId;
    if (thumbnail != null) map['thumbnail'] = thumbnail!.toCborMap();
    if (data != null) map['data'] = data!.toCborMap();
    if (c2paManifest != null && version != IngredientAssertionVersion.v3) {
      map['c2pa_manifest'] = c2paManifest!.toCborMap();
    }
    if (validationStatus != null && version != IngredientAssertionVersion.v3) {
      map['validationStatus'] = validationStatus!
          .map((status) => status.toJson())
          .toList(growable: false);
    }
    if (validationResults != null) {
      map['validationResults'] = validationResults!.toJson();
    }
    if (activeManifest != null) {
      map['activeManifest'] = activeManifest!.toCborMap();
    }
    if (claimSignature != null) {
      map['claimSignature'] = claimSignature!.toCborMap();
    }
    if (description != null) map['description'] = description;
    if (informationalUri != null) {
      map[version == IngredientAssertionVersion.v2
              ? 'informational_URI'
              : 'informationalURI'] =
          informationalUri;
    }
    if (assetTypes != null) {
      map[version == IngredientAssertionVersion.v2
          ? 'data_types'
          : 'dataTypes'] = assetTypes!
          .map((type) => type.toCborMap())
          .toList(growable: false);
    }
    if (softBindingsMatched != null) {
      map['softBindingsMatched'] = softBindingsMatched;
    }
    if (softBindingAlgorithmsMatched != null) {
      map['softBindingAlgorithmsMatched'] = softBindingAlgorithmsMatched;
    }
    if (metadata.isNotEmpty) map['metadata'] = metadata;
    return map;
  }

  @override
  bool operator ==(Object other) =>
      other is IngredientAssertion &&
      version == other.version &&
      relationship == other.relationship &&
      title == other.title &&
      format == other.format &&
      documentId == other.documentId &&
      instanceId == other.instanceId &&
      thumbnail == other.thumbnail &&
      data == other.data &&
      c2paManifest == other.c2paManifest &&
      activeManifest == other.activeManifest &&
      claimSignature == other.claimSignature &&
      deepEquals(validationStatus, other.validationStatus) &&
      validationResults == other.validationResults &&
      description == other.description &&
      informationalUri == other.informationalUri &&
      deepEquals(assetTypes, other.assetTypes) &&
      softBindingsMatched == other.softBindingsMatched &&
      deepEquals(
        softBindingAlgorithmsMatched,
        other.softBindingAlgorithmsMatched,
      ) &&
      deepEquals(metadata, other.metadata) &&
      deepEquals(unknownFields, other.unknownFields);

  @override
  int get hashCode => Object.hashAll([
    version,
    relationship,
    title,
    format,
    documentId,
    instanceId,
    thumbnail,
    data,
    c2paManifest,
    activeManifest,
    claimSignature,
    deepHash(validationStatus),
    validationResults,
    description,
    informationalUri,
    deepHash(assetTypes),
    softBindingsMatched,
    deepHash(softBindingAlgorithmsMatched),
    deepHash(metadata),
    deepHash(unknownFields),
  ]);
}

ClaimHashedUri? _optionalHashedUri(Object? value) =>
    value == null ? null : ClaimHashedUri.fromCbor(value);

Relationship _relationship(Object? value) {
  if (value is String) {
    for (final relationship in Relationship.values) {
      if (relationship.name == value) return relationship;
    }
  }
  throw const FormatException('Invalid ingredient relationship');
}

String? _optionalString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value != null && value is! String) {
    throw FormatException('$key must be a string');
  }
  return value as String?;
}

List<Object?>? _optionalList(Object? value) {
  if (value == null) return null;
  if (value is! List) throw const FormatException('Expected an array');
  return value.cast<Object?>();
}

Map<String, Object?> _stringMap(Object? value, String name) {
  if (value is! Map || value.keys.any((key) => key is! String)) {
    throw FormatException('$name must be a string-keyed map');
  }
  return value.cast<String, Object?>();
}

Map<String, Object?> _jsonMap(Object? value, String name) {
  Object? convert(Object? item) {
    if (item is Map) {
      if (item.keys.any((key) => key is! String)) {
        throw FormatException('$name must be a string-keyed map');
      }
      return <String, Object?>{
        for (final entry in item.entries)
          entry.key as String: convert(entry.value),
      };
    }
    if (item is List) return item.map(convert).toList(growable: false);
    return item;
  }

  return convert(value) as Map<String, Object?>;
}

Set<String> _fieldsFor(IngredientAssertionVersion version) => {
  'relationship',
  'dc:title',
  'dc:format',
  'documentID',
  'instanceID',
  'thumbnail',
  'data',
  'metadata',
  'description',
  if (version == IngredientAssertionVersion.v1 ||
      version == IngredientAssertionVersion.v2) ...{
    'c2pa_manifest',
    'validationStatus',
  },
  if (version == IngredientAssertionVersion.v2) ...{
    'data_types',
    'informational_URI',
  },
  if (version == IngredientAssertionVersion.v3) ...{
    'validationResults',
    'dataTypes',
    'activeManifest',
    'claimSignature',
    'informationalURI',
    'softBindingsMatched',
    'softBindingAlgorithmsMatched',
  },
};

Map<String, Object?> _unknown(Map<String, Object?> map, Set<String> known) =>
    unknownFields(map, known);

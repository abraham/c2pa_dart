part of '../standard_assertions.dart';

/// Single absolute URI entry in an asset-reference assertion.
final class C2paAssetReferenceEntry {
  /// Creates an asset reference entry.
  ///
  /// Throws FormatException when the URI is not absolute.
  C2paAssetReferenceEntry({
    required this.uri,
    this.description,
    Map<String, Object?> referenceUnknownFields = const {},
    Map<String, Object?> unknownFields = const {},
  }) : referenceUnknownFields = freezeJsonMap(referenceUnknownFields),
       unknownFields = freezeJsonMap(unknownFields) {
    final parsed = Uri.tryParse(uri);
    if (parsed == null || !parsed.hasScheme) {
      throw FormatException('Asset reference must be an absolute URI: $uri');
    }
  }

  /// Parses an asset reference entry from its CBOR map representation.
  factory C2paAssetReferenceEntry.fromCbor(Object? value) {
    final map = _map(value, 'asset reference');
    final reference = _map(map['reference'], 'asset reference URI');
    return C2paAssetReferenceEntry(
      uri: _requiredString(reference, 'uri'),
      description: _optionalString(map, 'description'),
      referenceUnknownFields: _unknown(reference, const {'uri'}),
      unknownFields: _unknown(map, const {'reference', 'description'}),
    );
  }

  /// Absolute referenced asset URI.
  final String uri;

  /// Optional human-readable reference description.
  final String? description;

  /// Extension fields preserved inside the nested `reference` map.
  final Map<String, Object?> referenceUnknownFields;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'reference': {...referenceUnknownFields, 'uri': uri},
    if (description != null) 'description': description,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paAssetReferenceEntry &&
      uri == other.uri &&
      description == other.description &&
      deepEquals(referenceUnknownFields, other.referenceUnknownFields) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    uri,
    description,
    deepHash(referenceUnknownFields),
    deepHash(unknownFields),
  );
}

/// CBOR assertion for the `c2pa.asset-ref` label.
final class C2paAssetReferenceAssertion implements C2paStandardAssertion {
  /// Creates an asset-reference assertion.
  ///
  /// Throws FormatException when no references are supplied.
  C2paAssetReferenceAssertion({
    required Iterable<C2paAssetReferenceEntry> references,
    Map<String, Object?> unknownFields = const {},
  }) : references = List<C2paAssetReferenceEntry>.unmodifiable(references),
       unknownFields = freezeJsonMap(unknownFields) {
    if (this.references.isEmpty) {
      throw const FormatException('Asset reference list cannot be empty');
    }
  }

  /// Parses an asset-reference assertion from a CBOR map.
  factory C2paAssetReferenceAssertion.fromCbor(Object? value) {
    final map = _map(value, 'asset reference assertion');
    return C2paAssetReferenceAssertion(
      references: _requiredList(
        map,
        'references',
      ).map(C2paAssetReferenceEntry.fromCbor),
      unknownFields: _unknown(map, const {'references'}),
    );
  }

  /// Parses an asset-reference assertion from a JSON-like map.
  factory C2paAssetReferenceAssertion.fromJson(Map<String, Object?> value) =>
      C2paAssetReferenceAssertion.fromCbor(value);

  /// Assertion label for C2PA asset-reference assertions.
  static const baseLabel = 'c2pa.asset-ref';

  /// Non-empty asset references serialized under `references`.
  final List<C2paAssetReferenceEntry> references;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  @override
  String get label => baseLabel;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.cbor;
  @override
  String? get contentType => 'application/cbor';
  @override
  Map<String, Object?> toAssertionData() => {
    ...unknownFields,
    'references': references.map((item) => item.toCborMap()).toList(),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();

  /// Encodes this assertion as a JSON-compatible map.
  Map<String, Object?> toJson() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paAssetReferenceAssertion &&
      deepEquals(references, other.references) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(deepHash(references), deepHash(unknownFields));
}

/// Asset type entry inside a `c2pa.asset-type.v1` assertion.
final class C2paAssetType {
  /// Creates an asset type entry.
  ///
  /// Throws FormatException when the type string is empty.
  C2paAssetType({
    required this.type,
    this.version,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (type.isEmpty) throw const FormatException('Asset type is empty');
  }

  /// Parses an asset type entry from its CBOR map representation.
  factory C2paAssetType.fromCbor(Object? value) {
    final map = _map(value, 'asset type');
    return C2paAssetType(
      type: _requiredString(map, 'type'),
      version: _optionalString(map, 'version'),
      unknownFields: _unknown(map, const {'type', 'version'}),
    );
  }

  /// Type discriminator serialized in the source map; must be non-empty.
  final String type;

  /// Optional asset type version string; null omits `version`.
  final String? version;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'type': type,
    if (version != null) 'version': version,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paAssetType &&
      type == other.type &&
      version == other.version &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(type, version, deepHash(unknownFields));
}

/// CBOR assertion for the `c2pa.asset-type.v1` label.
final class C2paAssetTypesAssertion implements C2paStandardAssertion {
  /// Creates an asset-types assertion with one or more type entries.
  ///
  /// Throws FormatException when version is not 1 or no types are supplied.
  C2paAssetTypesAssertion({
    required Iterable<C2paAssetType> types,
    this.metadata,
    this.version = 1,
    Map<String, Object?> unknownFields = const {},
  }) : types = List<C2paAssetType>.unmodifiable(types),
       unknownFields = freezeJsonMap(unknownFields) {
    if (version != 1 || this.types.isEmpty) {
      throw const FormatException(
        'Asset types v1 requires at least one asset type',
      );
    }
  }

  /// Parses an asset-types assertion from a CBOR map.
  factory C2paAssetTypesAssertion.fromCbor(Object? value, {int version = 1}) {
    final map = _map(value, 'asset types assertion');
    return C2paAssetTypesAssertion(
      types: _requiredList(map, 'types').map(C2paAssetType.fromCbor),
      metadata: map['metadata'] == null
          ? null
          : C2paAssertionMetadata.fromCbor(map['metadata']),
      version: version,
      unknownFields: _unknown(map, const {'types', 'metadata'}),
    );
  }

  /// Parses an asset-types assertion from a JSON-like map.
  factory C2paAssetTypesAssertion.fromJson(
    Map<String, Object?> value, {
    int version = 1,
  }) => C2paAssetTypesAssertion.fromCbor(value, version: version);

  /// Base assertion label used to form `c2pa.asset-type.v1`.
  static const baseLabel = 'c2pa.asset-type';

  /// Version suffix encoded in the assertion label; only version 1 is accepted.
  final int version;

  /// Non-empty asset type entries serialized under `types`.
  final List<C2paAssetType> types;

  /// Optional assertion metadata serialized under `metadata`.
  final C2paAssertionMetadata? metadata;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;
  @override
  String get label => version == 1 ? '$baseLabel.v1' : '$baseLabel.v$version';
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.cbor;
  @override
  String? get contentType => 'application/cbor';
  @override
  Map<String, Object?> toAssertionData() => {
    ...unknownFields,
    'types': types.map((item) => item.toCborMap()).toList(),
    if (metadata != null) 'metadata': metadata!.toAssertionData(),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();

  /// Encodes this assertion as a JSON-compatible map.
  Map<String, Object?> toJson() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paAssetTypesAssertion &&
      version == other.version &&
      deepEquals(types, other.types) &&
      metadata == other.metadata &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(version, deepHash(types), metadata, deepHash(unknownFields));
}

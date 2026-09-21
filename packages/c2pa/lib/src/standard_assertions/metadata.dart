part of '../standard_assertions.dart';

/// JSON metadata assertion for the `c2pa.metadata.v1` label.
final class C2paMetadataAssertion implements C2paStandardAssertion {
  /// Creates metadata from JSON-LD context entries and namespaced values.
  ///
  /// Throws FormatException if the version is unsupported, the context is
  /// empty or invalid, or a value key has no declared namespace.
  C2paMetadataAssertion({
    required Map<String, String> context,
    required Map<String, Object?> values,
    this.version = 1,
    Map<String, Object?> unknownFields = const {},
  }) : context = Map<String, String>.unmodifiable(context),
       values = freezeJsonMap(values),
       unknownFields = freezeJsonMap(unknownFields) {
    if (version != 1) {
      throw FormatException('Unsupported c2pa.metadata version: $version');
    }
    if (context.isEmpty ||
        context.entries.any(
          (entry) => entry.key.isEmpty || Uri.tryParse(entry.value) == null,
        )) {
      throw const FormatException('Metadata requires a valid @context');
    }
    for (final entry in context.entries) {
      final expected = _metadataContexts[entry.key];
      if (expected != null &&
          entry.value != expected &&
          !_metadataContextAliases[entry.key]!.contains(entry.value)) {
        throw FormatException(
          'Metadata context ${entry.key} has an unsupported URI',
        );
      }
    }
    for (final key in values.keys) {
      final separator = key.indexOf(':');
      if (separator <= 0 ||
          !_metadataContexts.containsKey(key.substring(0, separator)) ||
          !context.containsKey(key.substring(0, separator))) {
        throw FormatException('Metadata field has no context namespace: $key');
      }
    }
  }

  /// Parses a `c2pa.metadata` JSON object.
  factory C2paMetadataAssertion.fromJson(
    Map<String, Object?> json, {
    int version = 1,
  }) {
    final rawContext = _map(json['@context'], '@context');
    final context = <String, String>{};
    for (final entry in rawContext.entries) {
      if (entry.value is! String) {
        throw const FormatException('Metadata context values must be strings');
      }
      context[entry.key] = entry.value! as String;
    }
    return C2paMetadataAssertion(
      context: context,
      values: _unknown(json, const {'@context'}),
      version: version,
    );
  }

  /// Base assertion label used to form `c2pa.metadata.v1`.
  static const baseLabel = 'c2pa.metadata';

  /// Version suffix encoded in the assertion label; only version 1 is accepted.
  final int version;

  /// JSON-LD context map keyed by namespace prefix.
  final Map<String, String> context;

  /// Namespaced metadata values excluding `@context`.
  final Map<String, Object?> values;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  @override
  String get label => version == 1 ? '$baseLabel.v1' : '$baseLabel.v$version';
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.json;
  @override
  String? get contentType => 'application/json';
  @override
  Map<String, Object?> toAssertionData() => {
    '@context': context,
    ...values,
    ...unknownFields,
  };

  /// Encodes this assertion as a JSON-compatible map.
  Map<String, Object?> toJson() => toAssertionData();

  @override
  bool operator ==(Object other) =>
      other is C2paMetadataAssertion &&
      version == other.version &&
      deepEquals(context, other.context) &&
      deepEquals(values, other.values) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    version,
    deepHash(context),
    deepHash(values),
    deepHash(unknownFields),
  );
}

/// Review rating entry embedded in assertion metadata.
final class C2paReviewRating {
  /// Creates a review rating with a human explanation and score.
  ///
  /// Throws FormatException when the explanation is empty or the value is
  /// outside the inclusive range from 1 through 5.
  C2paReviewRating({
    required this.explanation,
    required this.value,
    this.code,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (explanation.isEmpty || value < 1 || value > 5) {
      throw const FormatException(
        'Review rating requires an explanation and value from 1 through 5',
      );
    }
  }

  /// Parses a review rating from the CBOR map representation.
  factory C2paReviewRating.fromCbor(Object? value) {
    final map = _map(value, 'review rating');
    return C2paReviewRating(
      explanation: _requiredString(map, 'explanation'),
      value: _requiredInt(map, 'value'),
      code: _optionalString(map, 'code'),
      unknownFields: _unknown(map, const {'explanation', 'value', 'code'}),
    );
  }

  /// Human-readable reason for the review score; must be non-empty.
  final String explanation;

  /// Review score in the inclusive range from 1 through 5.
  final int value;

  /// Optional machine-readable rating code; null omits `code`.
  final String? code;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'explanation': explanation,
    if (code != null) 'code': code,
    'value': value,
  };

  @override
  bool operator ==(Object other) =>
      other is C2paReviewRating &&
      explanation == other.explanation &&
      value == other.value &&
      code == other.code &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(explanation, value, code, deepHash(unknownFields));
}

/// Description of a source that supplied assertion metadata.
final class C2paDataSource {
  /// Creates a data source entry.
  ///
  /// Throws FormatException when the source type is empty.
  C2paDataSource({
    required this.type,
    this.details,
    Iterable<Map<String, Object?>>? actors,
    Map<String, Object?> unknownFields = const {},
  }) : actors = actors == null
           ? null
           : List<Map<String, Object?>>.unmodifiable(actors.map(freezeJsonMap)),
       unknownFields = freezeJsonMap(unknownFields) {
    if (type.isEmpty) throw const FormatException('Data source type is empty');
  }

  /// Parses a data source entry from its CBOR map representation.
  factory C2paDataSource.fromCbor(Object? value) {
    final map = _map(value, 'data source');
    return C2paDataSource(
      type: _requiredString(map, 'type'),
      details: _optionalString(map, 'details'),
      actors: _optionalList(map['actors'])
          ?.map((item) => _map(item, 'data source actor')),
      unknownFields: _unknown(map, const {'type', 'details', 'actors'}),
    );
  }

  /// Type discriminator serialized in the source map; must be non-empty.
  final String type;

  /// Optional human-readable source details; null omits `details`.
  final String? details;

  /// Optional actor records associated with this data source.
  final List<Map<String, Object?>>? actors;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'type': type,
    if (details != null) 'details': details,
    if (actors != null) 'actors': actors,
  };

  @override
  bool operator ==(Object other) =>
      other is C2paDataSource &&
      type == other.type &&
      details == other.details &&
      deepEquals(actors, other.actors) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(type, details, deepHash(actors), deepHash(unknownFields));
}

/// CBOR assertion metadata for the `c2pa.assertion.metadata.v1` label.
final class C2paAssertionMetadata implements C2paStandardAssertion {
  /// Creates assertion metadata from optional descriptive subrecords.
  ///
  /// Throws FormatException when version is not 1 or `dateTime` is not
  /// parseable as an ISO 8601 timestamp.
  C2paAssertionMetadata({
    Iterable<C2paReviewRating>? reviewRatings,
    this.dateTime,
    this.reference,
    this.dataSource,
    Iterable<Map<String, Object?>>? localizations,
    this.regionOfInterest,
    this.version = 1,
    Map<String, Object?> unknownFields = const {},
  }) : reviewRatings = reviewRatings == null
           ? null
           : List<C2paReviewRating>.unmodifiable(reviewRatings),
       localizations = localizations == null
           ? null
           : List<Map<String, Object?>>.unmodifiable(
               localizations.map(freezeJsonMap),
             ),
       unknownFields = freezeJsonMap(unknownFields) {
    if (version != 1) {
      throw FormatException(
        'Unsupported c2pa.assertion.metadata version: $version',
      );
    }
    if (dateTime != null && DateTime.tryParse(dateTime!) == null) {
      throw const FormatException('Metadata dateTime must be ISO 8601');
    }
  }

  /// Parses assertion metadata from a CBOR map.
  factory C2paAssertionMetadata.fromCbor(Object? value, {int version = 1}) {
    final map = _map(value, 'assertion metadata');
    return C2paAssertionMetadata(
      reviewRatings: _optionalList(map['reviewRatings'])
          ?.map(C2paReviewRating.fromCbor),
      dateTime: _optionalString(map, 'dateTime'),
      reference: map['reference'] == null
          ? null
          : ClaimHashedUri.fromCbor(map['reference']),
      dataSource: map['dataSource'] == null
          ? null
          : C2paDataSource.fromCbor(map['dataSource']),
      localizations: _optionalList(map['localizations'])
          ?.map((item) => _map(item, 'localization')),
      regionOfInterest: map['regionOfInterest'] == null
          ? null
          : C2paRegionOfInterest.fromCbor(map['regionOfInterest']),
      version: version,
      unknownFields: _unknown(map, const {
        'reviewRatings',
        'dateTime',
        'reference',
        'dataSource',
        'localizations',
        'regionOfInterest',
      }),
    );
  }

  /// Base assertion label used to form `c2pa.assertion.metadata.v1`.
  static const baseLabel = 'c2pa.assertion.metadata';

  /// Version suffix encoded in the assertion label; only version 1 is accepted.
  final int version;

  /// Optional review ratings associated with the assertion.
  final List<C2paReviewRating>? reviewRatings;

  /// Optional ISO 8601 timestamp string for this metadata record.
  final String? dateTime;

  /// Optional hashed URI identifying the assertion being described.
  final ClaimHashedUri? reference;

  /// Optional source information for the assertion data.
  final C2paDataSource? dataSource;

  /// Optional localization records preserved as JSON-like maps.
  final List<Map<String, Object?>>? localizations;

  /// Optional region to which this metadata applies.
  final C2paRegionOfInterest? regionOfInterest;

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
    if (reviewRatings != null)
      'reviewRatings': reviewRatings!
          .map((item) => item.toCborMap())
          .toList(growable: false),
    if (dateTime != null) 'dateTime': dateTime,
    if (reference != null) 'reference': reference!.toCborMap(),
    if (dataSource != null) 'dataSource': dataSource!.toCborMap(),
    if (localizations != null) 'localizations': localizations,
    if (regionOfInterest != null)
      'regionOfInterest': regionOfInterest!.toCborMap(),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();

  @override
  bool operator ==(Object other) =>
      other is C2paAssertionMetadata &&
      version == other.version &&
      deepEquals(reviewRatings, other.reviewRatings) &&
      dateTime == other.dateTime &&
      reference == other.reference &&
      dataSource == other.dataSource &&
      deepEquals(localizations, other.localizations) &&
      regionOfInterest == other.regionOfInterest &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    version,
    deepHash(reviewRatings),
    dateTime,
    reference,
    dataSource,
    deepHash(localizations),
    regionOfInterest,
    deepHash(unknownFields),
  );
}

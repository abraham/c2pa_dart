import 'dart:convert';
import 'dart:typed_data';

import 'claim.dart';
import 'json_utils.dart';

/// Wire encoding used for a standard C2PA assertion payload.
enum C2paStandardAssertionEncoding {
  /// CBOR payload encoded as `application/cbor`.
  cbor,

  /// JSON payload encoded as `application/json`.
  json,

  /// Opaque byte payload with an explicit content type.
  binary,
}

/// A standard C2PA assertion value that can be embedded in a claim.
abstract interface class C2paStandardAssertion {
  /// Assertion label as it appears in the manifest.
  String get label;

  /// Wire encoding used for the value returned by `toAssertionData`.
  C2paStandardAssertionEncoding get encoding;

  /// MIME type for the assertion payload; null when none is declared.
  String? get contentType;

  /// Converts this assertion to the payload model for its encoding.
  Object? toAssertionData();
}

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

/// Kind of region range payload in assertion metadata.
enum C2paRegionRangeType {
  /// Visual area described by a geometric shape.
  spatial,

  /// Time span range, currently limited to `npt` strings.
  temporal,

  /// Frame interval with non-negative integer bounds.
  frame,

  /// Text selector range with at least one selector.
  textual,

  /// Named item range with identifier and value fields.
  identified,
}

/// Geometric shape used by a spatial region range.
enum C2paShapeType {
  /// Rectangular shape using origin, width, and height.
  rectangle,

  /// Circular shape using origin and dimensions as supplied.
  circle,

  /// Polygon shape requiring at least three vertices.
  polygon,
}

/// Coordinate unit for a region shape.
enum C2paUnitType {
  /// Coordinates measured in asset pixels.
  pixel,

  /// Coordinates measured as percentages of the asset.
  percent,
}

/// Two-dimensional coordinate used by C2PA region shapes.
final class C2paCoordinate {
  /// Creates a coordinate from finite numeric axis values.
  const C2paCoordinate({required this.x, required this.y});

  /// Parses a coordinate from a CBOR map with finite `x` and `y`.
  factory C2paCoordinate.fromCbor(Object? value) {
    final map = _map(value, 'coordinate');
    return C2paCoordinate(
      x: _requiredNum(map, 'x').toDouble(),
      y: _requiredNum(map, 'y').toDouble(),
    );
  }

  /// Horizontal coordinate in the units declared by the enclosing shape.
  final double x;

  /// Vertical coordinate in the units declared by the enclosing shape.
  final double y;

  /// Encodes this coordinate as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => {'x': x, 'y': y};
  @override
  bool operator ==(Object other) =>
      other is C2paCoordinate && x == other.x && y == other.y;
  @override
  int get hashCode => Object.hash(x, y);
}

/// Spatial shape payload for a C2PA region range.
final class C2paRegionShape {
  /// Creates a region shape with validated dimensions and vertices.
  ///
  /// Throws FormatException for negative dimensions or polygon shapes with
  /// fewer than three vertices.
  C2paRegionShape({
    required this.type,
    required this.unit,
    required this.origin,
    this.width,
    this.height,
    this.inside,
    Iterable<C2paCoordinate>? vertices,
    Map<String, Object?> unknownFields = const {},
  }) : vertices = vertices == null
           ? null
           : List<C2paCoordinate>.unmodifiable(vertices),
       unknownFields = freezeJsonMap(unknownFields) {
    if (width != null && width! < 0 || height != null && height! < 0) {
      throw const FormatException('Region dimensions cannot be negative');
    }
    if (type == C2paShapeType.polygon &&
        (this.vertices == null || this.vertices!.length < 3)) {
      throw const FormatException('Polygon regions require three vertices');
    }
  }

  /// Parses a region shape from its CBOR map representation.
  factory C2paRegionShape.fromCbor(Object? value) {
    final map = _map(value, 'region shape');
    return C2paRegionShape(
      type: _enum(C2paShapeType.values, map['type'], 'shape type'),
      unit: _enum(C2paUnitType.values, map['unit'], 'shape unit'),
      origin: C2paCoordinate.fromCbor(map['origin']),
      width: _optionalNum(map, 'width')?.toDouble(),
      height: _optionalNum(map, 'height')?.toDouble(),
      inside: _optionalBool(map, 'inside'),
      vertices: _optionalList(map['vertices'])?.map(C2paCoordinate.fromCbor),
      unknownFields: _unknown(map, const {
        'type',
        'unit',
        'origin',
        'width',
        'height',
        'inside',
        'vertices',
      }),
    );
  }

  /// Shape kind that determines how dimensions and vertices are interpreted.
  final C2paShapeType type;

  /// Coordinate unit used by the origin, dimensions, and vertices.
  final C2paUnitType unit;

  /// Reference coordinate for the shape in the declared unit.
  final C2paCoordinate origin;

  /// Optional non-negative width; null omits `width`.
  final double? width;

  /// Optional non-negative height; null omits `height`.
  final double? height;

  /// Optional inclusion flag for whether the shape marks the inside area.
  final bool? inside;

  /// Optional polygon vertices; polygons require at least three.
  final List<C2paCoordinate>? vertices;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'type': type.name,
    'unit': unit.name,
    'origin': origin.toCborMap(),
    if (width != null) 'width': width,
    if (height != null) 'height': height,
    if (inside != null) 'inside': inside,
    if (vertices != null)
      'vertices': vertices!.map((item) => item.toCborMap()).toList(),
  };
  @override
  bool operator ==(Object other) =>
      other is C2paRegionShape &&
      type == other.type &&
      unit == other.unit &&
      origin == other.origin &&
      width == other.width &&
      height == other.height &&
      inside == other.inside &&
      deepEquals(vertices, other.vertices) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    type,
    unit,
    origin,
    width,
    height,
    inside,
    deepHash(vertices),
    deepHash(unknownFields),
  );
}

/// Typed range payload within a region of interest.
final class C2paRegionRange {
  /// Creates a region range with exactly one matching payload.
  ///
  /// Throws FormatException when the selected payload does not match `type`
  /// or when the payload violates its range-specific constraints.
  C2paRegionRange({
    required this.type,
    this.shape,
    Map<String, Object?>? time,
    Map<String, Object?>? frame,
    Map<String, Object?>? text,
    Map<String, Object?>? item,
    Map<String, Object?> unknownFields = const {},
  }) : time = time == null ? null : freezeJsonMap(time),
       frame = frame == null ? null : freezeJsonMap(frame),
       text = text == null ? null : freezeJsonMap(text),
       item = item == null ? null : freezeJsonMap(item),
       unknownFields = freezeJsonMap(unknownFields) {
    final selected = [
      shape,
      this.time,
      this.frame,
      this.text,
      this.item,
    ].where((value) => value != null).length;
    if (selected != 1 ||
        (type == C2paRegionRangeType.spatial) != (shape != null) ||
        (type == C2paRegionRangeType.temporal) != (this.time != null) ||
        (type == C2paRegionRangeType.frame) != (this.frame != null) ||
        (type == C2paRegionRangeType.textual) != (this.text != null) ||
        (type == C2paRegionRangeType.identified) != (this.item != null)) {
      throw const FormatException(
        'Region range type must match exactly one range payload',
      );
    }
    _validateRangePayload(type, this.time, this.frame, this.text, this.item);
  }

  /// Parses a region range from its CBOR map representation.
  factory C2paRegionRange.fromCbor(Object? value) {
    final map = _map(value, 'region range');
    final type = _enum(C2paRegionRangeType.values, map['type'], 'range type');
    return C2paRegionRange(
      type: type,
      shape: map['shape'] == null
          ? null
          : C2paRegionShape.fromCbor(map['shape']),
      time: map['time'] == null ? null : _map(map['time'], 'time range'),
      frame: map['frame'] == null ? null : _map(map['frame'], 'frame range'),
      text: map['text'] == null ? null : _map(map['text'], 'text range'),
      item: map['item'] == null ? null : _map(map['item'], 'identified range'),
      unknownFields: _unknown(map, const {
        'type',
        'shape',
        'time',
        'frame',
        'text',
        'item',
      }),
    );
  }

  /// Range kind that selects which payload field is present.
  final C2paRegionRangeType type;

  /// Spatial payload present only when `type` is spatial.
  final C2paRegionShape? shape;

  /// Temporal payload present only when `type` is temporal.
  final Map<String, Object?>? time;

  /// Frame payload present only when `type` is frame.
  final Map<String, Object?>? frame;

  /// Text selector payload present only when `type` is textual.
  final Map<String, Object?>? text;

  /// Identified-item payload present only when `type` is identified.
  final Map<String, Object?>? item;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'type': type.name,
    if (shape != null) 'shape': shape!.toCborMap(),
    if (time != null) 'time': time,
    if (frame != null) 'frame': frame,
    if (text != null) 'text': text,
    if (item != null) 'item': item,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paRegionRange &&
      type == other.type &&
      shape == other.shape &&
      deepEquals(time, other.time) &&
      deepEquals(frame, other.frame) &&
      deepEquals(text, other.text) &&
      deepEquals(item, other.item) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    type,
    shape,
    deepHash(time),
    deepHash(frame),
    deepHash(text),
    deepHash(item),
    deepHash(unknownFields),
  );
}

/// Collection of one or more ranges describing an asset region.
final class C2paRegionOfInterest {
  /// Creates a region of interest from one or more ranges.
  ///
  /// Throws FormatException when no ranges are supplied.
  C2paRegionOfInterest({
    required Iterable<C2paRegionRange> regions,
    this.name,
    this.identifier,
    this.type,
    this.role,
    this.description,
    Map<String, Object?>? metadata,
    Map<String, Object?> unknownFields = const {},
  }) : regions = List<C2paRegionRange>.unmodifiable(regions),
       metadata = metadata == null ? null : freezeJsonMap(metadata),
       unknownFields = freezeJsonMap(unknownFields) {
    if (this.regions.isEmpty) {
      throw const FormatException('A region of interest requires a range');
    }
  }

  /// Parses a region of interest from its CBOR map representation.
  factory C2paRegionOfInterest.fromCbor(Object? value) {
    final map = _map(value, 'region of interest');
    return C2paRegionOfInterest(
      regions: _requiredList(map, 'region').map(C2paRegionRange.fromCbor),
      name: _optionalString(map, 'name'),
      identifier: _optionalString(map, 'identifier'),
      type: _optionalString(map, 'type'),
      role: _optionalString(map, 'role'),
      description: _optionalString(map, 'description'),
      metadata: map['metadata'] == null
          ? null
          : _map(map['metadata'], 'region metadata'),
      unknownFields: _unknown(map, const {
        'region',
        'name',
        'identifier',
        'type',
        'role',
        'description',
        'metadata',
      }),
    );
  }

  /// Non-empty ranges stored under the C2PA `region` key.
  final List<C2paRegionRange> regions;

  /// Optional human-readable region name; null omits `name`.
  final String? name;

  /// Optional stable region identifier; null omits `identifier`.
  final String? identifier;

  /// Optional region type string; null omits `type`.
  final String? type;

  /// Optional role describing how this value is used.
  final String? role;

  /// Optional human-readable region description.
  final String? description;

  /// Optional extension metadata for the region.
  final Map<String, Object?>? metadata;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'region': regions.map((item) => item.toCborMap()).toList(),
    if (name != null) 'name': name,
    if (identifier != null) 'identifier': identifier,
    if (type != null) 'type': type,
    if (role != null) 'role': role,
    if (description != null) 'description': description,
    if (metadata != null) 'metadata': metadata,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paRegionOfInterest &&
      deepEquals(regions, other.regions) &&
      name == other.name &&
      identifier == other.identifier &&
      type == other.type &&
      role == other.role &&
      description == other.description &&
      deepEquals(metadata, other.metadata) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    deepHash(regions),
    name,
    identifier,
    type,
    role,
    description,
    deepHash(metadata),
    deepHash(unknownFields),
  );
}

/// Inclusive media time span used by a soft-binding scope.
final class C2paSoftBindingTimespan {
  /// Creates a non-negative time span whose end is not before its start.
  const C2paSoftBindingTimespan({required this.start, required this.end})
    : assert(start >= 0 && end >= start);

  /// Parses a soft-binding time span from a CBOR map.
  factory C2paSoftBindingTimespan.fromCbor(Object? value) {
    final map = _map(value, 'soft binding timespan');
    final start = _requiredInt(map, 'start');
    final end = _requiredInt(map, 'end');
    if (start < 0 || end < start) {
      throw const FormatException('Invalid soft binding timespan');
    }
    return C2paSoftBindingTimespan(start: start, end: end);
  }

  /// Inclusive start position; must be zero or greater.
  final int start;

  /// Inclusive end position; must be greater than or equal to start.
  final int end;

  /// Encodes this time span as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => {'start': start, 'end': end};
  @override
  bool operator ==(Object other) =>
      other is C2paSoftBindingTimespan &&
      start == other.start &&
      end == other.end;
  @override
  int get hashCode => Object.hash(start, end);
}

/// Scope that limits where a soft-binding block applies.
final class C2paSoftBindingScope {
  /// Creates a soft-binding scope with optional time, region, and extent data.
  C2paSoftBindingScope({
    this.timespan,
    this.region,
    this.extent,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields);

  /// Parses a soft-binding scope from its CBOR map representation.
  factory C2paSoftBindingScope.fromCbor(Object? value) {
    final map = _map(value, 'soft binding scope');
    return C2paSoftBindingScope(
      timespan: map['timespan'] == null
          ? null
          : C2paSoftBindingTimespan.fromCbor(map['timespan']),
      region: map['region'] == null
          ? null
          : C2paRegionOfInterest.fromCbor(map['region']),
      extent: _optionalString(map, 'extent'),
      unknownFields: _unknown(map, const {'timespan', 'region', 'extent'}),
    );
  }

  /// Optional time span covered by the soft binding.
  final C2paSoftBindingTimespan? timespan;

  /// Optional region covered by the soft binding.
  final C2paRegionOfInterest? region;

  /// Optional textual extent value; null omits `extent`.
  final String? extent;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    if (timespan != null) 'timespan': timespan!.toCborMap(),
    if (region != null) 'region': region!.toCborMap(),
    if (extent != null) 'extent': extent,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paSoftBindingScope &&
      timespan == other.timespan &&
      region == other.region &&
      extent == other.extent &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(timespan, region, extent, deepHash(unknownFields));
}

/// Single scoped value inside a soft-binding assertion.
final class C2paSoftBindingBlock {
  /// Creates a soft-binding block.
  ///
  /// Throws FormatException when the block value is empty.
  C2paSoftBindingBlock({
    required this.scope,
    required this.value,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (value.isEmpty) {
      throw const FormatException('Soft binding block value is empty');
    }
  }

  /// Parses a soft-binding block from its CBOR map representation.
  factory C2paSoftBindingBlock.fromCbor(Object? value) {
    final map = _map(value, 'soft binding block');
    return C2paSoftBindingBlock(
      scope: C2paSoftBindingScope.fromCbor(map['scope']),
      value: _requiredString(map, 'value'),
      unknownFields: _unknown(map, const {'scope', 'value'}),
    );
  }

  /// Scope that identifies where the block value applies.
  final C2paSoftBindingScope scope;

  /// Non-empty soft-binding value for the selected scope.
  final String value;

  /// Extension fields preserved from decoding and re-emitted unchanged.
  final Map<String, Object?> unknownFields;

  /// Encodes this value as the CBOR map shape used by C2PA.
  Map<String, Object?> toCborMap() => {
    ...unknownFields,
    'scope': scope.toCborMap(),
    'value': value,
  };
  @override
  bool operator ==(Object other) =>
      other is C2paSoftBindingBlock &&
      scope == other.scope &&
      value == other.value &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(scope, value, deepHash(unknownFields));
}

/// CBOR assertion for the `c2pa.soft-binding` label.
final class C2paSoftBindingAssertion implements C2paStandardAssertion {
  /// Creates a soft-binding assertion with one or more blocks.
  ///
  /// Throws FormatException when no blocks are supplied.
  C2paSoftBindingAssertion({
    required Iterable<C2paSoftBindingBlock> blocks,
    this.algorithm,
    this.name,
    this.algorithmParameters,
    Iterable<int> pad = const [],
    Iterable<int>? pad2,
    this.url,
    Map<String, Object?> unknownFields = const {},
  }) : blocks = List<C2paSoftBindingBlock>.unmodifiable(blocks),
       pad = Uint8List.fromList(pad.toList()).asUnmodifiableView(),
       pad2 = pad2 == null
           ? null
           : Uint8List.fromList(pad2.toList()).asUnmodifiableView(),
       unknownFields = freezeJsonMap(unknownFields) {
    if (this.blocks.isEmpty) {
      throw const FormatException('Soft binding requires at least one block');
    }
  }

  /// Parses a soft-binding assertion from a CBOR map.
  factory C2paSoftBindingAssertion.fromCbor(Object? value) {
    final map = _map(value, 'soft binding');
    return C2paSoftBindingAssertion(
      blocks: _requiredList(map, 'blocks').map(C2paSoftBindingBlock.fromCbor),
      algorithm: _optionalString(map, 'alg'),
      name: _optionalString(map, 'name'),
      algorithmParameters: _optionalString(map, 'alg-params'),
      pad: _optionalBytes(map, 'pad') ?? const [],
      pad2: _optionalBytes(map, 'pad2'),
      url: _optionalString(map, 'url'),
      unknownFields: _unknown(map, const {
        'alg',
        'blocks',
        'name',
        'alg-params',
        'pad',
        'pad2',
        'url',
      }),
    );
  }

  /// Assertion label for C2PA soft-binding assertions.
  static const baseLabel = 'c2pa.soft-binding';

  /// Optional algorithm identifier serialized as `alg`.
  final String? algorithm;

  /// Non-empty soft-binding blocks serialized under `blocks`.
  final List<C2paSoftBindingBlock> blocks;

  /// Optional human-readable region name; null omits `name`.
  final String? name;

  /// Optional algorithm parameter string serialized as `alg-params`.
  final String? algorithmParameters;

  /// Optional padding bytes serialized as `pad` when non-empty.
  final Uint8List pad;

  /// Optional second padding byte string serialized as `pad2`.
  final Uint8List? pad2;

  /// Optional external URL associated with the soft binding.
  final String? url;

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
    if (algorithm != null) 'alg': algorithm,
    'blocks': blocks.map((item) => item.toCborMap()).toList(),
    if (name != null) 'name': name,
    if (algorithmParameters != null) 'alg-params': algorithmParameters,
    if (pad.isNotEmpty) 'pad': Uint8List.fromList(pad),
    if (pad2 != null) 'pad2': Uint8List.fromList(pad2!),
    if (url != null) 'url': url,
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paSoftBindingAssertion &&
      algorithm == other.algorithm &&
      deepEquals(blocks, other.blocks) &&
      name == other.name &&
      algorithmParameters == other.algorithmParameters &&
      deepEquals(pad, other.pad) &&
      deepEquals(pad2, other.pad2) &&
      url == other.url &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode => Object.hash(
    algorithm,
    deepHash(blocks),
    name,
    algorithmParameters,
    deepHash(pad),
    deepHash(pad2),
    url,
    deepHash(unknownFields),
  );
}

/// Opaque binary assertion data with an explicit label and MIME type.
class C2paEmbeddedData implements C2paStandardAssertion {
  /// Creates an embedded binary assertion.
  ///
  /// Throws FormatException when the label or content type is empty.
  C2paEmbeddedData({
    required this.label,
    required this.contentType,
    required Iterable<int> bytes,
  }) : bytes = Uint8List.fromList(bytes.toList()).asUnmodifiableView() {
    if (label.isEmpty || contentType == null || contentType!.isEmpty) {
      throw const FormatException(
        'Embedded data requires a label and content type',
      );
    }
  }
  @override
  final String label;
  @override
  final String? contentType;

  /// Immutable assertion bytes copied from the constructor input.
  final Uint8List bytes;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.binary;
  @override
  Uint8List toAssertionData() => Uint8List.fromList(bytes);
  @override
  bool operator ==(Object other) =>
      other is C2paEmbeddedData &&
      label == other.label &&
      contentType == other.contentType &&
      deepEquals(bytes, other.bytes);
  @override
  int get hashCode => Object.hash(label, contentType, deepHash(bytes));
}

/// Thumbnail assertion target represented by a C2PA thumbnail label.
enum C2paThumbnailKind {
  /// Thumbnail for the claim asset.
  claim,

  /// Thumbnail for an ingredient asset.
  ingredient,
}

/// Embedded thumbnail assertion for a claim or ingredient.
final class C2paThumbnail extends C2paEmbeddedData {
  /// Creates a thumbnail and derives its C2PA label from the media type.
  ///
  /// Throws FormatException for unsupported thumbnail media types.
  C2paThumbnail({
    required this.kind,
    required String mediaType,
    required super.bytes,
  }) : super(label: _thumbnailLabel(kind, mediaType), contentType: mediaType);

  /// Interprets embedded data whose label uses a C2PA thumbnail prefix.
  factory C2paThumbnail.fromEmbedded(C2paEmbeddedData data) {
    final kind = data.label.startsWith('c2pa.thumbnail.ingredient')
        ? C2paThumbnailKind.ingredient
        : C2paThumbnailKind.claim;
    return C2paThumbnail._(
      kind: kind,
      label: data.label,
      mediaType: data.contentType!,
      bytes: data.bytes,
    );
  }
  C2paThumbnail._({
    required this.kind,
    required super.label,
    required String mediaType,
    required super.bytes,
  }) : super(contentType: mediaType);

  /// Thumbnail target represented by the derived label.
  final C2paThumbnailKind kind;
}

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

/// CBOR assertion for the `c2pa.time-stamp` label.
final class C2paTimestampAssertion implements C2paStandardAssertion {
  /// Creates a timestamp assertion from timestamp tokens keyed by identifier.
  ///
  /// Throws FormatException when any identifier or token is empty.
  C2paTimestampAssertion(Map<String, Uint8List> timestamps)
    : timestamps = Map<String, Uint8List>.unmodifiable(
        timestamps.map(
          (key, value) =>
              MapEntry(key, Uint8List.fromList(value).asUnmodifiableView()),
        ),
      ) {
    if (timestamps.entries.any(
      (entry) => entry.key.isEmpty || entry.value.isEmpty,
    )) {
      throw const FormatException(
        'Timestamp identifiers and tokens are required',
      );
    }
  }

  /// Parses a timestamp assertion from a CBOR map of byte strings.
  factory C2paTimestampAssertion.fromCbor(Object? value) {
    final map = _map(value, 'timestamp assertion');
    return C2paTimestampAssertion({
      for (final entry in map.entries)
        entry.key: _bytes(entry.value, 'timestamp token'),
    });
  }

  /// Assertion label for C2PA timestamp assertions.
  static const baseLabel = 'c2pa.time-stamp';

  /// Timestamp tokens keyed by non-empty timestamp identifier.
  final Map<String, Uint8List> timestamps;
  @override
  String get label => baseLabel;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.cbor;
  @override
  String? get contentType => 'application/cbor';
  @override
  Map<String, Object?> toAssertionData() => {
    for (final entry in timestamps.entries)
      entry.key: Uint8List.fromList(entry.value),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paTimestampAssertion &&
      deepEquals(timestamps, other.timestamps);
  @override
  int get hashCode => deepHash(timestamps);
}

/// CBOR assertion for the `c2pa.certificate-status` label.
final class C2paCertificateStatusAssertion implements C2paStandardAssertion {
  /// Creates a certificate-status assertion from OCSP response values.
  C2paCertificateStatusAssertion({
    required Iterable<Uint8List> ocspValues,
    Map<String, Object?> unknownFields = const {},
  }) : ocspValues = List<Uint8List>.unmodifiable(
         ocspValues.map(
           (value) => Uint8List.fromList(value).asUnmodifiableView(),
         ),
       ),
       unknownFields = freezeJsonMap(unknownFields);

  /// Parses certificate status from CBOR `ocspVals` byte strings.
  factory C2paCertificateStatusAssertion.fromCbor(Object? value) {
    final map = _map(value, 'certificate status assertion');
    return C2paCertificateStatusAssertion(
      ocspValues: _requiredList(
        map,
        'ocspVals',
      ).map((item) => _bytes(item, 'OCSP value')),
      unknownFields: _unknown(map, const {'ocspVals'}),
    );
  }

  /// Parses certificate status from JSON base64 `ocspVals` strings.
  factory C2paCertificateStatusAssertion.fromJson(Map<String, Object?> json) =>
      C2paCertificateStatusAssertion(
        ocspValues: _requiredList(json, 'ocspVals').map((item) {
          if (item is! String) {
            throw const FormatException(
              'JSON OCSP values must be base64 strings',
            );
          }
          try {
            return Uint8List.fromList(base64.decode(item));
          } on FormatException {
            throw const FormatException('Invalid base64 OCSP value');
          }
        }),
        unknownFields: _unknown(json, const {'ocspVals'}),
      );

  /// Assertion label for C2PA certificate-status assertions.
  static const baseLabel = 'c2pa.certificate-status';

  /// OCSP response values serialized under `ocspVals`.
  final List<Uint8List> ocspValues;

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
    'ocspVals': ocspValues.map(Uint8List.fromList).toList(),
  };

  /// Encodes this assertion as a CBOR-compatible map.
  Map<String, Object?> toCborMap() => toAssertionData();

  /// Encodes this assertion as JSON with OCSP values base64 encoded.
  Map<String, Object?> toJson() => {
    ...unknownFields,
    'ocspVals': ocspValues.map(base64.encode).toList(),
  };
  @override
  bool operator ==(Object other) =>
      other is C2paCertificateStatusAssertion &&
      deepEquals(ocspValues, other.ocspValues) &&
      deepEquals(unknownFields, other.unknownFields);
  @override
  int get hashCode =>
      Object.hash(deepHash(ocspValues), deepHash(unknownFields));
}

/// Legacy JSON assertion namespace represented by the assertion label.
enum C2paLegacyAssertionKind {
  /// Legacy `stds.exif` metadata assertion.
  exif,

  /// Legacy Schema.org CreativeWork assertion.
  creativeWork,

  /// Legacy generic `schema.org` assertion.
  schemaOrg,
}

/// Legacy JSON assertion using historical C2PA or Schema.org labels.
final class C2paLegacyJsonAssertion implements C2paStandardAssertion {
  /// Creates a legacy JSON assertion with validation for known kinds.
  ///
  /// Throws FormatException when the label is empty or required `@type`
  /// values are missing for CreativeWork or Schema.org assertions.
  C2paLegacyJsonAssertion({
    required this.kind,
    required Map<String, Object?> value,
    String? label,
  }) : value = freezeJsonMap(value),
       label = label ?? _legacyLabel(kind) {
    if (this.label.isEmpty) {
      throw const FormatException('Legacy assertion label is empty');
    }
    if (kind == C2paLegacyAssertionKind.creativeWork &&
        value['@type'] != 'CreativeWork') {
      throw const FormatException('CreativeWork requires @type CreativeWork');
    }
    if (kind == C2paLegacyAssertionKind.schemaOrg &&
        value['@type'] is! String) {
      throw const FormatException('Schema.org assertion requires @type');
    }
  }

  /// Parses a legacy JSON assertion and infers its kind from the label.
  factory C2paLegacyJsonAssertion.fromJson({
    required String label,
    required Map<String, Object?> value,
  }) => C2paLegacyJsonAssertion(
    kind: label == 'stds.exif'
        ? C2paLegacyAssertionKind.exif
        : label == 'stds.schema-org.CreativeWork'
        ? C2paLegacyAssertionKind.creativeWork
        : C2paLegacyAssertionKind.schemaOrg,
    value: value,
    label: label,
  );

  /// Legacy namespace selected for this JSON assertion.
  final C2paLegacyAssertionKind kind;
  @override
  final String label;

  /// JSON payload emitted unchanged for this legacy assertion.
  final Map<String, Object?> value;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.json;
  @override
  String? get contentType => 'application/json';
  @override
  Map<String, Object?> toAssertionData() => value;

  /// Encodes this legacy assertion as a JSON-compatible map.
  Map<String, Object?> toJson() => value;
  @override
  bool operator ==(Object other) =>
      other is C2paLegacyJsonAssertion &&
      kind == other.kind &&
      label == other.label &&
      deepEquals(value, other.value);
  @override
  int get hashCode => Object.hash(kind, label, deepHash(value));
}

void _validateRangePayload(
  C2paRegionRangeType type,
  Map<String, Object?>? time,
  Map<String, Object?>? frame,
  Map<String, Object?>? text,
  Map<String, Object?>? item,
) {
  if (type == C2paRegionRangeType.temporal && time != null) {
    final kind = time['type'];
    if (kind != null && kind != 'npt') {
      throw const FormatException('Only npt temporal ranges are supported');
    }
    for (final field in const ['start', 'end']) {
      if (time[field] != null && time[field] is! String) {
        throw FormatException('Temporal $field must be a string');
      }
    }
  }
  if (type == C2paRegionRangeType.frame && frame != null) {
    for (final field in const ['start', 'end']) {
      if (frame[field] != null &&
          (frame[field] is! int || (frame[field] as int) < 0)) {
        throw FormatException('Frame $field must be a non-negative integer');
      }
    }
  }
  if (type == C2paRegionRangeType.textual && text != null) {
    final selectors = text['selectors'];
    if (selectors is! List || selectors.isEmpty) {
      throw const FormatException('Textual ranges require selectors');
    }
  }
  if (type == C2paRegionRangeType.identified && item != null) {
    _requiredString(item, 'identifier');
    _requiredString(item, 'value');
  }
}

String _thumbnailLabel(C2paThumbnailKind kind, String mediaType) {
  final extension = switch (mediaType.toLowerCase()) {
    'image/jpeg' || 'image/jpg' => 'jpeg',
    'image/png' => 'png',
    'image/svg+xml' => 'svg',
    'image/gif' => 'gif',
    'image/webp' => 'webp',
    'image/tiff' => 'tiff',
    _ => throw FormatException('Unsupported thumbnail media type: $mediaType'),
  };
  return 'c2pa.thumbnail.${kind.name}.$extension';
}

String _legacyLabel(C2paLegacyAssertionKind kind) => switch (kind) {
  C2paLegacyAssertionKind.exif => 'stds.exif',
  C2paLegacyAssertionKind.creativeWork => 'stds.schema-org.CreativeWork',
  C2paLegacyAssertionKind.schemaOrg => 'schema.org',
};

const _metadataContexts = <String, String>{
  'xmp': 'http://ns.adobe.com/xap/1.0/',
  'xmpMM': 'http://ns.adobe.com/xap/1.0/mm/',
  'xmpTPg': 'http://ns.adobe.com/xap/1.0/t/pg/',
  'crs': 'http://ns.adobe.com/camera-raw-settings/1.0/',
  'pdf': 'http://ns.adobe.com/pdf/1.3/',
  'dc': 'http://purl.org/dc/elements/1.1/',
  'Iptc4xmpExt': 'http://iptc.org/std/Iptc4xmpExt/2008-02-29/',
  'exif': 'http://ns.adobe.com/exif/1.0/',
  'exifEX': 'http://cipa.jp/exif/1.0/',
  'photoshop': 'http://ns.adobe.com/photoshop/1.0/',
  'tiff': 'http://ns.adobe.com/tiff/1.0/',
  'xmpDM': 'http://ns.adobe.com/xmp/1.0/DynamicMedia/',
  'plus': 'http://ns.useplus.org/ldf/xmp/1.0/',
};

const _metadataContextAliases = <String, Set<String>>{
  'xmp': {},
  'xmpMM': {},
  'xmpTPg': {},
  'crs': {},
  'pdf': {},
  'dc': {},
  'Iptc4xmpExt': {},
  'exif': {},
  'exifEX': {'http://cipa.jp/exif/1.0/exifEX', 'http://cipa.jp/exif/2.32/'},
  'photoshop': {},
  'tiff': {},
  'xmpDM': {},
  'plus': {},
};

Map<String, Object?> _map(Object? value, String name) {
  if (value is! Map) throw FormatException('$name must be a map');
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw FormatException('$name keys must be strings');
    }
    result[entry.key! as String] = entry.value;
  }
  return result;
}

List<Object?> _requiredList(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! List) throw FormatException('$key must be an array');
  return value.cast<Object?>();
}

List<Object?>? _optionalList(Object? value) {
  if (value == null) return null;
  if (value is! List) throw const FormatException('Expected an array');
  return value.cast<Object?>();
}

String _requiredString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! String || value.isEmpty) {
    throw FormatException('$key must be a non-empty string');
  }
  return value;
}

String? _optionalString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! String) throw FormatException('$key must be a string');
  return value;
}

int _requiredInt(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! int) throw FormatException('$key must be an integer');
  return value;
}

num _requiredNum(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! num || !value.isFinite) {
    throw FormatException('$key must be a finite number');
  }
  return value;
}

num? _optionalNum(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! num || !value.isFinite) {
    throw FormatException('$key must be a finite number');
  }
  return value;
}

bool? _optionalBool(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null) return null;
  if (value is! bool) throw FormatException('$key must be a boolean');
  return value;
}

Uint8List _bytes(Object? value, String name) {
  if (value is Uint8List) return Uint8List.fromList(value);
  if (value is List<int>) return Uint8List.fromList(value);
  throw FormatException('$name must be a byte string');
}

Uint8List? _optionalBytes(Map<String, Object?> map, String key) =>
    map[key] == null ? null : _bytes(map[key], key);

T _enum<T extends Enum>(List<T> values, Object? value, String name) {
  if (value is String) {
    for (final candidate in values) {
      if (candidate.name == value) return candidate;
    }
  }
  throw FormatException('Unsupported $name: $value');
}

Map<String, Object?> _unknown(
  Map<String, Object?> value,
  Set<String> knownKeys,
) => unknownFields(value, knownKeys);

part of '../standard_assertions.dart';

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

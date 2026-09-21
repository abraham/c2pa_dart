import 'dart:convert';
import 'dart:typed_data';

import 'claim.dart';
import 'json_utils.dart';

enum C2paStandardAssertionEncoding { cbor, json, binary }

abstract interface class C2paStandardAssertion {
  String get label;
  C2paStandardAssertionEncoding get encoding;
  String? get contentType;
  Object? toAssertionData();
}

final class C2paMetadataAssertion implements C2paStandardAssertion {
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

  static const baseLabel = 'c2pa.metadata';
  final int version;
  final Map<String, String> context;
  final Map<String, Object?> values;
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

final class C2paReviewRating {
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

  factory C2paReviewRating.fromCbor(Object? value) {
    final map = _map(value, 'review rating');
    return C2paReviewRating(
      explanation: _requiredString(map, 'explanation'),
      value: _requiredInt(map, 'value'),
      code: _optionalString(map, 'code'),
      unknownFields: _unknown(map, const {'explanation', 'value', 'code'}),
    );
  }

  final String explanation;
  final int value;
  final String? code;
  final Map<String, Object?> unknownFields;

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

final class C2paDataSource {
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

  final String type;
  final String? details;
  final List<Map<String, Object?>>? actors;
  final Map<String, Object?> unknownFields;

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

final class C2paAssertionMetadata implements C2paStandardAssertion {
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

  static const baseLabel = 'c2pa.assertion.metadata';
  final int version;
  final List<C2paReviewRating>? reviewRatings;
  final String? dateTime;
  final ClaimHashedUri? reference;
  final C2paDataSource? dataSource;
  final List<Map<String, Object?>>? localizations;
  final C2paRegionOfInterest? regionOfInterest;
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

enum C2paRegionRangeType { spatial, temporal, frame, textual, identified }

enum C2paShapeType { rectangle, circle, polygon }

enum C2paUnitType { pixel, percent }

final class C2paCoordinate {
  const C2paCoordinate({required this.x, required this.y});
  factory C2paCoordinate.fromCbor(Object? value) {
    final map = _map(value, 'coordinate');
    return C2paCoordinate(
      x: _requiredNum(map, 'x').toDouble(),
      y: _requiredNum(map, 'y').toDouble(),
    );
  }
  final double x;
  final double y;
  Map<String, Object?> toCborMap() => {'x': x, 'y': y};
  @override
  bool operator ==(Object other) =>
      other is C2paCoordinate && x == other.x && y == other.y;
  @override
  int get hashCode => Object.hash(x, y);
}

final class C2paRegionShape {
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

  final C2paShapeType type;
  final C2paUnitType unit;
  final C2paCoordinate origin;
  final double? width;
  final double? height;
  final bool? inside;
  final List<C2paCoordinate>? vertices;
  final Map<String, Object?> unknownFields;
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

final class C2paRegionRange {
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

  final C2paRegionRangeType type;
  final C2paRegionShape? shape;
  final Map<String, Object?>? time;
  final Map<String, Object?>? frame;
  final Map<String, Object?>? text;
  final Map<String, Object?>? item;
  final Map<String, Object?> unknownFields;
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

final class C2paRegionOfInterest {
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

  final List<C2paRegionRange> regions;
  final String? name;
  final String? identifier;
  final String? type;
  final String? role;
  final String? description;
  final Map<String, Object?>? metadata;
  final Map<String, Object?> unknownFields;
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

final class C2paSoftBindingTimespan {
  const C2paSoftBindingTimespan({required this.start, required this.end})
    : assert(start >= 0 && end >= start);
  factory C2paSoftBindingTimespan.fromCbor(Object? value) {
    final map = _map(value, 'soft binding timespan');
    final start = _requiredInt(map, 'start');
    final end = _requiredInt(map, 'end');
    if (start < 0 || end < start) {
      throw const FormatException('Invalid soft binding timespan');
    }
    return C2paSoftBindingTimespan(start: start, end: end);
  }
  final int start;
  final int end;
  Map<String, Object?> toCborMap() => {'start': start, 'end': end};
  @override
  bool operator ==(Object other) =>
      other is C2paSoftBindingTimespan &&
      start == other.start &&
      end == other.end;
  @override
  int get hashCode => Object.hash(start, end);
}

final class C2paSoftBindingScope {
  C2paSoftBindingScope({
    this.timespan,
    this.region,
    this.extent,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields);
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
  final C2paSoftBindingTimespan? timespan;
  final C2paRegionOfInterest? region;
  final String? extent;
  final Map<String, Object?> unknownFields;
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

final class C2paSoftBindingBlock {
  C2paSoftBindingBlock({
    required this.scope,
    required this.value,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (value.isEmpty) {
      throw const FormatException('Soft binding block value is empty');
    }
  }
  factory C2paSoftBindingBlock.fromCbor(Object? value) {
    final map = _map(value, 'soft binding block');
    return C2paSoftBindingBlock(
      scope: C2paSoftBindingScope.fromCbor(map['scope']),
      value: _requiredString(map, 'value'),
      unknownFields: _unknown(map, const {'scope', 'value'}),
    );
  }
  final C2paSoftBindingScope scope;
  final String value;
  final Map<String, Object?> unknownFields;
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

final class C2paSoftBindingAssertion implements C2paStandardAssertion {
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

  static const baseLabel = 'c2pa.soft-binding';
  final String? algorithm;
  final List<C2paSoftBindingBlock> blocks;
  final String? name;
  final String? algorithmParameters;
  final Uint8List pad;
  final Uint8List? pad2;
  final String? url;
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

class C2paEmbeddedData implements C2paStandardAssertion {
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

enum C2paThumbnailKind { claim, ingredient }

final class C2paThumbnail extends C2paEmbeddedData {
  C2paThumbnail({
    required this.kind,
    required String mediaType,
    required super.bytes,
  }) : super(label: _thumbnailLabel(kind, mediaType), contentType: mediaType);
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
  final C2paThumbnailKind kind;
}

final class C2paAssetReferenceEntry {
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
  final String uri;
  final String? description;
  final Map<String, Object?> referenceUnknownFields;
  final Map<String, Object?> unknownFields;
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

final class C2paAssetReferenceAssertion implements C2paStandardAssertion {
  C2paAssetReferenceAssertion({
    required Iterable<C2paAssetReferenceEntry> references,
    Map<String, Object?> unknownFields = const {},
  }) : references = List<C2paAssetReferenceEntry>.unmodifiable(references),
       unknownFields = freezeJsonMap(unknownFields) {
    if (this.references.isEmpty) {
      throw const FormatException('Asset reference list cannot be empty');
    }
  }
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
  factory C2paAssetReferenceAssertion.fromJson(Map<String, Object?> value) =>
      C2paAssetReferenceAssertion.fromCbor(value);
  static const baseLabel = 'c2pa.asset-ref';
  final List<C2paAssetReferenceEntry> references;
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
  Map<String, Object?> toCborMap() => toAssertionData();
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

final class C2paAssetType {
  C2paAssetType({
    required this.type,
    this.version,
    Map<String, Object?> unknownFields = const {},
  }) : unknownFields = freezeJsonMap(unknownFields) {
    if (type.isEmpty) throw const FormatException('Asset type is empty');
  }
  factory C2paAssetType.fromCbor(Object? value) {
    final map = _map(value, 'asset type');
    return C2paAssetType(
      type: _requiredString(map, 'type'),
      version: _optionalString(map, 'version'),
      unknownFields: _unknown(map, const {'type', 'version'}),
    );
  }
  final String type;
  final String? version;
  final Map<String, Object?> unknownFields;
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

final class C2paAssetTypesAssertion implements C2paStandardAssertion {
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
  factory C2paAssetTypesAssertion.fromJson(
    Map<String, Object?> value, {
    int version = 1,
  }) => C2paAssetTypesAssertion.fromCbor(value, version: version);
  static const baseLabel = 'c2pa.asset-type';
  final int version;
  final List<C2paAssetType> types;
  final C2paAssertionMetadata? metadata;
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
  Map<String, Object?> toCborMap() => toAssertionData();
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

final class C2paTimestampAssertion implements C2paStandardAssertion {
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
  factory C2paTimestampAssertion.fromCbor(Object? value) {
    final map = _map(value, 'timestamp assertion');
    return C2paTimestampAssertion({
      for (final entry in map.entries)
        entry.key: _bytes(entry.value, 'timestamp token'),
    });
  }
  static const baseLabel = 'c2pa.time-stamp';
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
  Map<String, Object?> toCborMap() => toAssertionData();
  @override
  bool operator ==(Object other) =>
      other is C2paTimestampAssertion &&
      deepEquals(timestamps, other.timestamps);
  @override
  int get hashCode => deepHash(timestamps);
}

final class C2paCertificateStatusAssertion implements C2paStandardAssertion {
  C2paCertificateStatusAssertion({
    required Iterable<Uint8List> ocspValues,
    Map<String, Object?> unknownFields = const {},
  }) : ocspValues = List<Uint8List>.unmodifiable(
         ocspValues.map(
           (value) => Uint8List.fromList(value).asUnmodifiableView(),
         ),
       ),
       unknownFields = freezeJsonMap(unknownFields);
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
  static const baseLabel = 'c2pa.certificate-status';
  final List<Uint8List> ocspValues;
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
  Map<String, Object?> toCborMap() => toAssertionData();
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

enum C2paLegacyAssertionKind { exif, creativeWork, schemaOrg }

final class C2paLegacyJsonAssertion implements C2paStandardAssertion {
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
  final C2paLegacyAssertionKind kind;
  @override
  final String label;
  final Map<String, Object?> value;
  @override
  C2paStandardAssertionEncoding get encoding =>
      C2paStandardAssertionEncoding.json;
  @override
  String? get contentType => 'application/json';
  @override
  Map<String, Object?> toAssertionData() => value;
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

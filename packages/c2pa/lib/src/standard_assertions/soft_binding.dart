part of '../standard_assertions.dart';

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

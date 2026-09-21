import 'dart:typed_data';

import 'json_utils.dart';

/// One excluded byte range in a DataHash v1 assertion.
final class DataHashExclusionRange {
  const DataHashExclusionRange({required this.start, required this.length})
    : assert(start >= 0),
      assert(length >= 0);

  factory DataHashExclusionRange.fromCbor(Object? value) {
    if (value is! Map ||
        value['start'] is! int ||
        value['length'] is! int ||
        (value['start'] as int) < 0 ||
        (value['length'] as int) < 0) {
      throw const FormatException('Malformed DataHash exclusion range');
    }
    return DataHashExclusionRange(
      start: value['start'] as int,
      length: value['length'] as int,
    );
  }

  final int start;
  final int length;

  int get end => start + length;

  Map<String, Object?> toCborMap() => {'start': start, 'length': length};

  @override
  bool operator ==(Object other) =>
      other is DataHashExclusionRange &&
      start == other.start &&
      length == other.length;

  @override
  int get hashCode => Object.hash(start, length);
}

/// Typed representation of the v1 `c2pa.hash.data` assertion.
final class DataHashAssertion {
  DataHashAssertion({
    Iterable<DataHashExclusionRange>? exclusions,
    this.name,
    this.algorithm,
    required List<int> hash,
    List<int> pad = const [],
    List<int>? pad2,
  }) : exclusions = exclusions == null
           ? null
           : List<DataHashExclusionRange>.unmodifiable(exclusions),
       hash = Uint8List.fromList(hash).asUnmodifiableView(),
       pad = Uint8List.fromList(pad).asUnmodifiableView(),
       pad2 = pad2 == null
           ? null
           : Uint8List.fromList(pad2).asUnmodifiableView();

  factory DataHashAssertion.fromCbor(Object? value) {
    if (value is! Map) {
      throw const FormatException('A DataHash assertion must be a map');
    }
    final exclusions = value['exclusions'];
    final name = value['name'];
    final algorithm = value['alg'];
    final hash = value['hash'];
    final pad = value['pad'];
    final pad2 = value['pad2'];
    if ((exclusions != null && exclusions is! List) ||
        (name != null && name is! String) ||
        (algorithm != null && algorithm is! String) ||
        hash is! Uint8List ||
        pad is! Uint8List ||
        (pad2 != null && pad2 is! Uint8List)) {
      throw const FormatException('Malformed DataHash assertion');
    }
    final exclusionList = exclusions as List?;
    return DataHashAssertion(
      exclusions: exclusionList?.map(DataHashExclusionRange.fromCbor),
      name: name as String?,
      algorithm: algorithm as String?,
      hash: hash,
      pad: pad,
      pad2: pad2 as Uint8List?,
    );
  }

  static const label = 'c2pa.hash.data';
  static const version = 1;

  final List<DataHashExclusionRange>? exclusions;
  final String? name;
  final String? algorithm;
  final Uint8List hash;
  final Uint8List pad;
  final Uint8List? pad2;

  Map<String, Object?> toCborMap() => {
    if (exclusions != null)
      'exclusions': exclusions!
          .map((range) => range.toCborMap())
          .toList(growable: false),
    if (name != null) 'name': name,
    if (algorithm != null) 'alg': algorithm,
    'hash': hash,
    'pad': pad,
    if (pad2 != null) 'pad2': pad2,
  };

  @override
  bool operator ==(Object other) =>
      other is DataHashAssertion &&
      deepEquals(exclusions, other.exclusions) &&
      name == other.name &&
      algorithm == other.algorithm &&
      deepEquals(hash, other.hash) &&
      deepEquals(pad, other.pad) &&
      deepEquals(pad2, other.pad2);

  @override
  int get hashCode => Object.hash(
    deepHash(exclusions),
    name,
    algorithm,
    deepHash(hash),
    deepHash(pad),
    deepHash(pad2),
  );
}

import 'dart:typed_data';

import 'json_utils.dart';

/// One excluded byte range in a DataHash v1 assertion.
final class DataHashExclusionRange {
  /// Creates a non-negative excluded byte range.
  const DataHashExclusionRange({required this.start, required this.length})
    : assert(start >= 0),
      assert(length >= 0);

  /// Decodes an excluded byte range from a CBOR map.
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

  /// Zero-based starting byte offset of the excluded range.
  final int start;

  /// Excluded range length in bytes.
  final int length;

  /// Exclusive ending byte offset of the excluded range.
  int get end => start + length;

  /// Encodes this range as a CBOR-compatible map.
  /// Encodes this assertion as a CBOR-compatible map.
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
  /// Creates a v1 `c2pa.hash.data` hard-binding assertion.
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

  /// Decodes a `c2pa.hash.data` assertion from a CBOR map.
  factory DataHashAssertion.fromCbor(Object? value) {
    if (value is! Map) {
      throw const FormatException('A DataHash assertion must be a map');
    }
    final exclusions = value['exclusions'];
    final name = value['name'];
    final algorithm = value['alg'];
    final hash = cborBytes(value['hash']);
    final pad = cborBytes(value['pad']);
    final rawPad2 = value['pad2'];
    final pad2 = cborBytes(rawPad2);
    if ((exclusions != null && exclusions is! List) ||
        (name != null && name is! String) ||
        (algorithm != null && algorithm is! String) ||
        hash == null ||
        pad == null ||
        (rawPad2 != null && pad2 == null)) {
      throw const FormatException('Malformed DataHash assertion');
    }
    final exclusionList = exclusions as List?;
    return DataHashAssertion(
      exclusions: exclusionList?.map(DataHashExclusionRange.fromCbor),
      name: name as String?,
      algorithm: algorithm as String?,
      hash: hash,
      pad: pad,
      pad2: pad2,
    );
  }

  /// Assertion label for DataHash hard bindings.
  static const label = 'c2pa.hash.data';

  /// C2PA DataHash assertion version supported by this type.
  static const version = 1;

  /// Excluded byte ranges, or `null` when the whole asset is hashed.
  final List<DataHashExclusionRange>? exclusions;

  /// Optional DataHash name from the assertion.
  final String? name;

  /// Optional digest algorithm name stored in `alg`.
  final String? algorithm;

  /// Digest bytes for the non-excluded asset data.
  final Uint8List hash;

  /// Padding bytes stored with the DataHash assertion.
  final Uint8List pad;

  /// Optional second padding byte string for placeholder workflows.
  final Uint8List? pad2;

  /// Encodes this assertion as a CBOR-compatible map.
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

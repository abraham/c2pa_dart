import 'dart:typed_data';

import 'json_utils.dart';

final class BmffHashDataReplacement {
  BmffHashDataReplacement({required this.offset, required List<int> value})
    : value = Uint8List.fromList(value).asUnmodifiableView() {
    if (offset < 0 || this.value.isEmpty) {
      throw const FormatException('Invalid BMFF exclusion data replacement');
    }
  }

  factory BmffHashDataReplacement.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'offset',
      'value',
    }, 'data replacement');
    final replacement = cborBytes(map['value']);
    if (map['offset'] is! int || replacement == null) {
      throw const FormatException('Malformed BMFF data replacement');
    }
    return BmffHashDataReplacement(
      offset: map['offset'] as int,
      value: replacement,
    );
  }

  final int offset;
  final Uint8List value;

  Map<String, Object?> toCborMap() => {'offset': offset, 'value': value};

  @override
  bool operator ==(Object other) =>
      other is BmffHashDataReplacement &&
      offset == other.offset &&
      deepEquals(value, other.value);

  @override
  int get hashCode => Object.hash(offset, deepHash(value));
}

final class BmffHashSubset {
  const BmffHashSubset({required this.offset, this.length = 0})
    : assert(offset >= 0),
      assert(length >= 0);

  factory BmffHashSubset.fromCbor(Object? value) {
    final map = _strictMap(value, const {'offset', 'length'}, 'subset');
    if (map['offset'] is! int ||
        map['length'] is! int ||
        (map['offset'] as int) < 0 ||
        (map['length'] as int) < 0) {
      throw const FormatException('Malformed BMFF exclusion subset');
    }
    return BmffHashSubset(
      offset: map['offset'] as int,
      length: map['length'] as int,
    );
  }

  final int offset;

  /// Zero means through the end of the matched box.
  final int length;

  Map<String, Object?> toCborMap() => {'offset': offset, 'length': length};

  @override
  bool operator ==(Object other) =>
      other is BmffHashSubset &&
      offset == other.offset &&
      length == other.length;

  @override
  int get hashCode => Object.hash(offset, length);
}

final class BmffHashExclusion {
  BmffHashExclusion({
    required this.xpath,
    this.length,
    Iterable<BmffHashDataReplacement> data = const [],
    Iterable<BmffHashSubset> subsets = const [],
    this.version,
    List<int>? flags,
    this.exact,
  }) : data = List<BmffHashDataReplacement>.unmodifiable(data),
       subsets = List<BmffHashSubset>.unmodifiable(subsets),
       flags = flags == null
           ? null
           : Uint8List.fromList(flags).asUnmodifiableView() {
    if (!xpath.startsWith('/') || xpath.length < 2) {
      throw const FormatException(
        'A BMFF exclusion requires an absolute xpath',
      );
    }
    if (length != null && length! < 0) {
      throw const FormatException('A BMFF exclusion length cannot be negative');
    }
    if (version != null && (version! < 0 || version! > 0xff)) {
      throw const FormatException('A BMFF exclusion version must be uint8');
    }
    if (this.flags != null && this.flags!.length != 3) {
      throw const FormatException(
        'BMFF exclusion flags must contain exactly three bytes',
      );
    }
    var previousEnd = 0;
    for (final subset in this.subsets) {
      if (subset.offset < previousEnd) {
        throw const FormatException(
          'BMFF exclusion subsets must be ordered and non-overlapping',
        );
      }
      previousEnd = subset.offset + subset.length;
    }
  }

  factory BmffHashExclusion.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'xpath',
      'length',
      'data',
      'subset',
      'version',
      'flags',
      'exact',
    }, 'exclusion');
    if (map['xpath'] is! String ||
        (map['length'] != null && map['length'] is! int) ||
        (map['data'] != null && map['data'] is! List) ||
        (map['subset'] != null && map['subset'] is! List) ||
        (map['version'] != null && map['version'] is! int) ||
        (map['flags'] != null && cborBytes(map['flags']) == null) ||
        (map['exact'] != null && map['exact'] is! bool)) {
      throw const FormatException('Malformed BMFF exclusion');
    }
    return BmffHashExclusion(
      xpath: map['xpath'] as String,
      length: map['length'] as int?,
      data: (map['data'] as List<Object?>? ?? const []).map(
        BmffHashDataReplacement.fromCbor,
      ),
      subsets: (map['subset'] as List<Object?>? ?? const []).map(
        BmffHashSubset.fromCbor,
      ),
      version: map['version'] as int?,
      flags: cborBytes(map['flags']),
      exact: map['exact'] as bool?,
    );
  }

  final String xpath;
  final int? length;
  final List<BmffHashDataReplacement> data;
  final List<BmffHashSubset> subsets;
  final int? version;
  final Uint8List? flags;
  final bool? exact;

  Map<String, Object?> toCborMap() => {
    'xpath': xpath,
    if (length != null) 'length': length,
    if (data.isNotEmpty)
      'data': data.map((item) => item.toCborMap()).toList(growable: false),
    if (subsets.isNotEmpty)
      'subset': subsets.map((item) => item.toCborMap()).toList(growable: false),
    if (version != null) 'version': version,
    if (flags != null) 'flags': flags,
    if (exact != null) 'exact': exact,
  };

  @override
  bool operator ==(Object other) =>
      other is BmffHashExclusion &&
      xpath == other.xpath &&
      length == other.length &&
      deepEquals(data, other.data) &&
      deepEquals(subsets, other.subsets) &&
      version == other.version &&
      deepEquals(flags, other.flags) &&
      exact == other.exact;

  @override
  int get hashCode => Object.hash(
    xpath,
    length,
    deepHash(data),
    deepHash(subsets),
    version,
    deepHash(flags),
    exact,
  );
}

/// One v3 BMFF Merkle map.
final class MerkleMap {
  MerkleMap({
    required this.uniqueId,
    required this.localId,
    required this.count,
    this.algorithm,
    List<int>? initHash,
    required Iterable<List<int>> hashes,
    this.fixedBlockSize,
    Iterable<int>? variableBlockSizes,
  }) : initHash = initHash == null
           ? null
           : Uint8List.fromList(initHash).asUnmodifiableView(),
       hashes = List<Uint8List>.unmodifiable(
         hashes.map((hash) => Uint8List.fromList(hash).asUnmodifiableView()),
       ),
       variableBlockSizes = variableBlockSizes == null
           ? null
           : List<int>.unmodifiable(variableBlockSizes) {
    if (uniqueId < 0 || localId < 0 || count <= 0) {
      throw const FormatException('Invalid BMFF Merkle identifiers or count');
    }
    if (algorithm != null && algorithm!.trim().isEmpty) {
      throw const FormatException('BMFF Merkle algorithm must not be empty');
    }
    if (this.hashes.isEmpty || this.hashes.any((hash) => hash.isEmpty)) {
      throw const FormatException('BMFF Merkle hashes must not be empty');
    }
    if (!_merkleLayerSizes(count).contains(this.hashes.length)) {
      throw const FormatException(
        'BMFF Merkle hashes must contain one complete tree row',
      );
    }
    if (fixedBlockSize != null && fixedBlockSize! <= 0) {
      throw const FormatException(
        'BMFF Merkle fixed block size must be positive',
      );
    }
    if (fixedBlockSize != null && this.variableBlockSizes != null) {
      throw const FormatException(
        'BMFF Merkle fixed and variable block sizes are mutually exclusive',
      );
    }
    final sizes = this.variableBlockSizes;
    if (sizes != null &&
        (sizes.length != count || sizes.any((size) => size <= 0))) {
      throw const FormatException(
        'BMFF Merkle variable block sizes must match count and be positive',
      );
    }
    final digestLength = _digestLength(algorithm);
    if (algorithm != null && digestLength == null) {
      throw const FormatException('Unsupported BMFF Merkle algorithm');
    }
    if (digestLength != null &&
        ((this.initHash != null && this.initHash!.length != digestLength) ||
            this.hashes.any((hash) => hash.length != digestLength))) {
      throw const FormatException(
        'BMFF Merkle hashes do not match the declared algorithm',
      );
    }
  }

  factory MerkleMap.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'uniqueId',
      'localId',
      'count',
      'alg',
      'initHash',
      'hashes',
      'fixedBlockSize',
      'variableBlockSizes',
    }, 'Merkle map');
    if (map['uniqueId'] is! int ||
        map['localId'] is! int ||
        map['count'] is! int ||
        (map['alg'] != null && map['alg'] is! String) ||
        (map['initHash'] != null && cborBytes(map['initHash']) == null) ||
        map['hashes'] is! List ||
        (map['fixedBlockSize'] != null && map['fixedBlockSize'] is! int) ||
        (map['variableBlockSizes'] != null &&
            map['variableBlockSizes'] is! List)) {
      throw const FormatException('Malformed BMFF Merkle map');
    }
    final hashes = map['hashes'] as List<Object?>;
    final sizes = map['variableBlockSizes'] as List<Object?>?;
    final hashValues = hashes.map(cborBytes).toList();
    if (hashValues.any((hash) => hash == null) ||
        (sizes != null && sizes.any((size) => size is! int))) {
      throw const FormatException('Malformed BMFF Merkle map values');
    }
    return MerkleMap(
      uniqueId: map['uniqueId'] as int,
      localId: map['localId'] as int,
      count: map['count'] as int,
      algorithm: map['alg'] as String?,
      initHash: cborBytes(map['initHash']),
      hashes: hashValues.cast<Uint8List>(),
      fixedBlockSize: map['fixedBlockSize'] as int?,
      variableBlockSizes: sizes?.cast<int>(),
    );
  }

  final int uniqueId;
  final int localId;
  final int count;
  final String? algorithm;
  final Uint8List? initHash;
  final List<Uint8List> hashes;
  final int? fixedBlockSize;
  final List<int>? variableBlockSizes;

  Map<String, Object?> toCborMap() => {
    'uniqueId': uniqueId,
    'localId': localId,
    'count': count,
    if (algorithm != null) 'alg': algorithm,
    if (initHash != null) 'initHash': initHash,
    'hashes': hashes,
    if (fixedBlockSize != null) 'fixedBlockSize': fixedBlockSize,
    if (variableBlockSizes != null) 'variableBlockSizes': variableBlockSizes,
  };

  @override
  bool operator ==(Object other) =>
      other is MerkleMap &&
      uniqueId == other.uniqueId &&
      localId == other.localId &&
      count == other.count &&
      algorithm == other.algorithm &&
      deepEquals(initHash, other.initHash) &&
      deepEquals(hashes, other.hashes) &&
      fixedBlockSize == other.fixedBlockSize &&
      deepEquals(variableBlockSizes, other.variableBlockSizes);

  @override
  int get hashCode => Object.hash(
    uniqueId,
    localId,
    count,
    algorithm,
    deepHash(initHash),
    deepHash(hashes),
    fixedBlockSize,
    deepHash(variableBlockSizes),
  );
}

/// Per-fragment proof stored in a C2PA `merkle` UUID box.
final class BmffMerkleProof {
  BmffMerkleProof({
    required this.uniqueId,
    required this.localId,
    required this.location,
    Iterable<List<int>>? hashes,
  }) : hashes = hashes == null
           ? null
           : List<Uint8List>.unmodifiable(
               hashes.map(
                 (hash) => Uint8List.fromList(hash).asUnmodifiableView(),
               ),
             ) {
    if (uniqueId < 0 ||
        localId < 0 ||
        location < 0 ||
        (this.hashes?.any((hash) => hash.isEmpty) ?? false)) {
      throw const FormatException('Invalid BMFF Merkle proof');
    }
  }

  factory BmffMerkleProof.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'uniqueId',
      'localId',
      'location',
      'hashes',
    }, 'Merkle proof');
    if (map['uniqueId'] is! int ||
        map['localId'] is! int ||
        map['location'] is! int ||
        (map['hashes'] != null && map['hashes'] is! List)) {
      throw const FormatException('Malformed BMFF Merkle proof');
    }
    final hashes = map['hashes'] as List<Object?>?;
    final proofHashes = hashes?.map(cborBytes).toList();
    if (proofHashes?.any((hash) => hash == null) ?? false) {
      throw const FormatException('Malformed BMFF Merkle proof hashes');
    }
    return BmffMerkleProof(
      uniqueId: map['uniqueId'] as int,
      localId: map['localId'] as int,
      location: map['location'] as int,
      hashes: proofHashes?.cast<Uint8List>(),
    );
  }

  final int uniqueId;
  final int localId;
  final int location;
  final List<Uint8List>? hashes;

  Map<String, Object?> toCborMap() => {
    'uniqueId': uniqueId,
    'localId': localId,
    'location': location,
    if (hashes != null) 'hashes': hashes,
  };

  @override
  bool operator ==(Object other) =>
      other is BmffMerkleProof &&
      uniqueId == other.uniqueId &&
      localId == other.localId &&
      location == other.location &&
      deepEquals(hashes, other.hashes);

  @override
  int get hashCode =>
      Object.hash(uniqueId, localId, location, deepHash(hashes));
}

/// Typed v3 `c2pa.hash.bmff` hard-binding assertion.
final class BmffHashAssertion {
  BmffHashAssertion({
    required Iterable<BmffHashExclusion> exclusions,
    this.algorithm,
    List<int>? hash,
    Iterable<MerkleMap>? merkle,
    this.name,
  }) : exclusions = List<BmffHashExclusion>.unmodifiable(exclusions),
       hash = hash == null
           ? null
           : Uint8List.fromList(hash).asUnmodifiableView(),
       merkle = merkle == null ? null : List<MerkleMap>.unmodifiable(merkle) {
    if (this.exclusions.isEmpty ||
        (algorithm != null && algorithm!.trim().isEmpty)) {
      throw const FormatException('BMFF hash requires valid exclusions');
    }
    if (this.hash != null && this.merkle != null) {
      throw const FormatException(
        'BMFF hash and Merkle bindings are mutually exclusive',
      );
    }
    if (this.merkle?.isEmpty ?? false) {
      throw const FormatException('BMFF Merkle maps must not be empty');
    }
  }

  factory BmffHashAssertion.fromCbor(Object? value) {
    final map = _strictMap(value, const {
      'exclusions',
      'alg',
      'hash',
      'name',
      'merkle',
    }, 'assertion');
    if (map['exclusions'] is! List ||
        (map['alg'] != null && map['alg'] is! String) ||
        (map['hash'] != null && cborBytes(map['hash']) == null) ||
        (map['merkle'] != null && map['merkle'] is! List) ||
        (map['name'] != null && map['name'] is! String)) {
      throw const FormatException('Malformed BMFF hash assertion');
    }
    return BmffHashAssertion(
      exclusions: (map['exclusions'] as List<Object?>).map(
        BmffHashExclusion.fromCbor,
      ),
      algorithm: map['alg'] as String?,
      hash: cborBytes(map['hash']),
      merkle: (map['merkle'] as List<Object?>?)?.map(MerkleMap.fromCbor),
      name: map['name'] as String?,
    );
  }

  static const label = 'c2pa.hash.bmff.v3';
  static const baseLabel = 'c2pa.hash.bmff';
  static const version = 3;

  /// Whether [label] names a BMFF hard binding of any assertion version.
  ///
  /// Producers in the wild emit `c2pa.hash.bmff` (v1), `c2pa.hash.bmff.v2`, or
  /// `c2pa.hash.bmff.v3`, any of which may carry a `__<instance>` suffix.
  /// Matching only the newest label silently demotes v1 and v2 bindings to
  /// unknown assertions, which surfaces as a spurious
  /// `claim.hardBindings.missing` failure.
  static bool matchesLabel(String label) => versionFromLabel(label) != null;

  /// The assertion version encoded in [label], or `null` if [label] is not a
  /// BMFF hard binding. An unsuffixed label is version 1.
  static int? versionFromLabel(String label) {
    final base = label.split('__').first;
    if (base == baseLabel) return 1;
    if (!base.startsWith('$baseLabel.v')) return null;
    final suffix = base.substring(baseLabel.length + 2);
    if (suffix.isEmpty) return null;
    return int.tryParse(suffix);
  }

  final List<BmffHashExclusion> exclusions;
  final String? algorithm;
  final Uint8List? hash;
  final List<MerkleMap>? merkle;
  final String? name;

  Map<String, Object?> toCborMap() => {
    'exclusions': exclusions
        .map((item) => item.toCborMap())
        .toList(growable: false),
    if (algorithm != null) 'alg': algorithm,
    if (hash != null) 'hash': hash,
    if (merkle != null)
      'merkle': merkle!.map((item) => item.toCborMap()).toList(growable: false),
    if (name != null) 'name': name,
  };

  @override
  bool operator ==(Object other) =>
      other is BmffHashAssertion &&
      deepEquals(exclusions, other.exclusions) &&
      algorithm == other.algorithm &&
      deepEquals(hash, other.hash) &&
      deepEquals(merkle, other.merkle) &&
      name == other.name;

  @override
  int get hashCode => Object.hash(
    deepHash(exclusions),
    algorithm,
    deepHash(hash),
    deepHash(merkle),
    name,
  );
}

Map<String, Object?> _strictMap(
  Object? value,
  Set<String> allowed,
  String name,
) {
  if (value is! Map || value.keys.any((key) => key is! String)) {
    throw FormatException('BMFF hash $name must be a string-keyed map');
  }
  final map = value.cast<String, Object?>();
  if (map.keys.any((key) => !allowed.contains(key))) {
    throw FormatException('BMFF hash $name contains unknown fields');
  }
  return map;
}

Set<int> _merkleLayerSizes(int count) {
  final result = <int>{count};
  var size = count;
  while (size > 1) {
    size = (size + 1) ~/ 2;
    result.add(size);
  }
  return result;
}

int? _digestLength(String? algorithm) {
  final normalized = algorithm?.toLowerCase().replaceAll(RegExp(r'[-_]'), '');
  return switch (normalized) {
    'sha256' => 32,
    'sha384' => 48,
    'sha512' => 64,
    _ => null,
  };
}

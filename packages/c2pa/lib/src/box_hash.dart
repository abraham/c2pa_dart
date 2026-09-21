import 'dart:typed_data';

import 'json_utils.dart';

/// One physical asset range described by a BoxHash v1 assertion.
final class BoxHashBox {
  BoxHashBox({
    required Iterable<String> names,
    required List<int> hash,
    this.algorithm,
    this.excluded = false,
    List<int> pad = const [],
  }) : names = List<String>.unmodifiable(names),
       hash = Uint8List.fromList(hash).asUnmodifiableView(),
       pad = Uint8List.fromList(pad).asUnmodifiableView();

  factory BoxHashBox.fromCbor(Object? value) {
    if (value is! Map) {
      throw const FormatException('A BoxHash box entry must be a map');
    }
    final names = value['names'];
    final hash = cborBytes(value['hash']);
    final pad = cborBytes(value['pad']);
    final algorithm = value['alg'];
    final excluded = value['excluded'];
    if (names is! List ||
        !names.every((name) => name is String) ||
        hash == null ||
        pad == null ||
        (algorithm != null && algorithm is! String) ||
        (excluded != null && excluded is! bool)) {
      throw const FormatException('Malformed BoxHash box entry');
    }
    return BoxHashBox(
      names: names.cast<String>(),
      algorithm: algorithm as String?,
      hash: hash,
      excluded: excluded as bool? ?? false,
      pad: pad,
    );
  }

  final List<String> names;
  final String? algorithm;
  final Uint8List hash;
  final bool excluded;
  final Uint8List pad;

  Map<String, Object?> toCborMap() => {
    'names': names,
    if (algorithm != null) 'alg': algorithm,
    'hash': hash,
    if (excluded) 'excluded': true,
    'pad': pad,
  };

  @override
  bool operator ==(Object other) =>
      other is BoxHashBox &&
      deepEquals(names, other.names) &&
      algorithm == other.algorithm &&
      deepEquals(hash, other.hash) &&
      excluded == other.excluded &&
      deepEquals(pad, other.pad);

  @override
  int get hashCode => Object.hash(
    deepHash(names),
    algorithm,
    deepHash(hash),
    excluded,
    deepHash(pad),
  );
}

/// Typed representation of the v1 `c2pa.hash.boxes` assertion.
final class BoxHashAssertion {
  BoxHashAssertion({required Iterable<BoxHashBox> boxes})
    : boxes = List<BoxHashBox>.unmodifiable(boxes);

  factory BoxHashAssertion.fromCbor(Object? value) {
    if (value is! Map || value['boxes'] is! List) {
      throw const FormatException('Malformed BoxHash assertion');
    }
    final boxes = (value['boxes'] as List)
        .map(BoxHashBox.fromCbor)
        .toList(growable: false);
    if (boxes.isEmpty) {
      throw const FormatException('A BoxHash assertion must contain boxes');
    }
    return BoxHashAssertion(boxes: boxes);
  }

  static const label = 'c2pa.hash.boxes';
  static const version = 1;

  final List<BoxHashBox> boxes;

  Map<String, Object?> toCborMap() => {
    'boxes': boxes.map((box) => box.toCborMap()).toList(growable: false),
  };

  @override
  bool operator ==(Object other) =>
      other is BoxHashAssertion && deepEquals(boxes, other.boxes);

  @override
  int get hashCode => deepHash(boxes);
}

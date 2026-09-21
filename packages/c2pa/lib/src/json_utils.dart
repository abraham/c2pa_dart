import 'dart:collection';
import 'dart:typed_data';

typedef JsonMap = Map<String, Object?>;

Object? freezeJson(Object? value) {
  return switch (value) {
    final Uint8List bytes => Uint8List.fromList(bytes).asUnmodifiableView(),
    final Map<String, Object?> map => UnmodifiableMapView(
      map.map((key, value) => MapEntry(key, freezeJson(value))),
    ),
    final List<Object?> list => List<Object?>.unmodifiable(
      list.map(freezeJson),
    ),
    _ => value,
  };
}

JsonMap freezeJsonMap(Map<String, Object?> value) =>
    freezeJson(value)! as JsonMap;

JsonMap unknownFields(Map<String, Object?> json, Set<String> knownKeys) =>
    freezeJsonMap(
      Map<String, Object?>.fromEntries(
        json.entries.where((entry) => !knownKeys.contains(entry.key)),
      ),
    );

bool deepEquals(Object? left, Object? right) {
  if (identical(left, right)) return true;
  if (left is List && right is List) {
    return left.length == right.length &&
        Iterable<int>.generate(left.length)
            .every((index) => deepEquals(left[index], right[index]));
  }
  if (left is Map && right is Map) {
    return left.length == right.length &&
        left.keys.every(
          (key) => right.containsKey(key) && deepEquals(left[key], right[key]),
        );
  }
  return left == right;
}

int deepHash(Object? value) {
  if (value is List) return Object.hashAll(value.map(deepHash));
  if (value is Map) {
    final entries = value.entries.toList()
      ..sort((left, right) => '${left.key}'.compareTo('${right.key}'));
    return Object.hashAll(
      entries.map((entry) => Object.hash(entry.key, deepHash(entry.value))),
    );
  }
  return value.hashCode;
}

T? enumByName<T extends Enum>(Iterable<T> values, Object? name) {
  if (name is! String) return null;
  for (final value in values) {
    if (value.name == name) return value;
  }
  return null;
}

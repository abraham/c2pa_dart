import 'dart:collection';
import 'dart:typed_data';

/// String-keyed JSON-like map used by public model objects.
typedef JsonMap = Map<String, Object?>;

/// Recursively freezes JSON-like maps, lists, and byte arrays.
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

/// Freezes [value] and returns it as an immutable [JsonMap].
JsonMap freezeJsonMap(Map<String, Object?> value) =>
    freezeJson(value)! as JsonMap;

/// Copies fields whose keys are not in [knownKeys].
JsonMap unknownFields(Map<String, Object?> json, Set<String> knownKeys) =>
    freezeJsonMap(
      Map<String, Object?>.fromEntries(
        json.entries.where((entry) => !knownKeys.contains(entry.key)),
      ),
    );

/// Compares JSON-like lists and maps by deep value.
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

/// Computes a stable deep hash for JSON-like values.
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

/// Finds an enum value whose `name` matches [name].
T? enumByName<T extends Enum>(Iterable<T> values, Object? name) {
  if (name is! String) return null;
  for (final value in values) {
    if (value.name == name) return value;
  }
  return null;
}

/// Coerces a CBOR value that should hold a byte string.
///
/// c2pa-rs annotates every such field with `#[serde(with = "serde_bytes")]`,
/// and that visitor accepts a CBOR array of integers in addition to a real
/// byte string. Producers in the wild — notably the 2022-era Adobe assets in
/// the public test corpus — emit the array form, so rejecting it turns valid
/// assets into validation failures.
///
/// Returns `null` when [value] is not a byte string or an array of bytes.
Uint8List? cborBytes(Object? value) {
  if (value is Uint8List) return value;
  if (value is List) {
    final bytes = Uint8List(value.length);
    for (var i = 0; i < value.length; i++) {
      final item = value[i];
      if (item is! int || item < 0 || item > 255) return null;
      bytes[i] = item;
    }
    return bytes;
  }
  return null;
}

import 'dart:collection';
import 'dart:typed_data';

/// An asset fixture that owns its bytes and descriptive metadata.
///
/// Inputs are copied on construction, and [bytes] returns a copy, so callers
/// cannot accidentally make a shared fixture nondeterministic.
final class FixtureAsset {
  /// Creates a fixture asset and copies [bytes] and [metadata].
  FixtureAsset({
    required this.name,
    required List<int> bytes,
    this.mediaType,
    Map<String, Object?> metadata = const {},
  }) : _bytes = Uint8List.fromList(bytes),
       metadata = UnmodifiableMapView(Map<String, Object?>.of(metadata));

  /// Creates deterministic pseudo-random fixture bytes.
  ///
  /// This is intentionally not cryptographically secure. The same [seed] and
  /// [length] always produce the same bytes on every Dart platform.
  factory FixtureAsset.deterministic({
    required String name,
    required int length,
    int seed = 0,
    String? mediaType,
    Map<String, Object?> metadata = const {},
  }) {
    RangeError.checkNotNegative(length, 'length');
    RangeError.checkValueInInterval(seed, 0, 0xffffffff, 'seed');

    var state = seed;
    final bytes = Uint8List(length);
    for (var index = 0; index < length; index++) {
      state = (1664525 * state + 1013904223) & 0xffffffff;
      bytes[index] = state >>> 24;
    }
    return FixtureAsset(
      name: name,
      bytes: bytes,
      mediaType: mediaType,
      metadata: metadata,
    );
  }

  /// Test-facing file name or logical asset name.
  final String name;

  /// Optional MIME type used by tests that need format hints.
  final String? mediaType;
  final Uint8List _bytes;

  /// Immutable JSON-compatible metadata carried with the fixture.
  final Map<String, Object?> metadata;

  /// The owned byte length of this fixture.
  int get length => _bytes.length;

  /// A defensive copy of the fixture bytes.
  Uint8List get bytes => Uint8List.fromList(_bytes);

  /// Creates a modified fixture while preserving omitted fields.
  ///
  /// Passing `null` leaves the corresponding value unchanged.
  FixtureAsset copyWith({
    String? name,
    List<int>? bytes,
    String? mediaType,
    Map<String, Object?>? metadata,
  }) => FixtureAsset(
    name: name ?? this.name,
    bytes: bytes ?? _bytes,
    mediaType: mediaType ?? this.mediaType,
    metadata: metadata ?? this.metadata,
  );
}

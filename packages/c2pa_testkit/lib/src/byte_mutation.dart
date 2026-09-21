import 'dart:typed_data';

/// Deterministic, non-mutating byte fixture transformations.
abstract final class ByteMutation {
  /// Copies the first [length] bytes of [input].
  ///
  /// Throws [RangeError] when [length] is outside `0..input.length`.
  static Uint8List truncate(List<int> input, int length) {
    RangeError.checkValueInInterval(length, 0, input.length, 'length');
    return Uint8List.fromList(input.take(length).toList(growable: false));
  }

  /// Flips bits in the byte at [offset] using [mask].
  ///
  /// [mask] must fit in one byte; [input] is copied before mutation.
  static Uint8List flip(List<int> input, int offset, {int mask = 0xff}) {
    RangeError.checkValidIndex(offset, input, 'offset');
    RangeError.checkValueInInterval(mask, 0, 0xff, 'mask');
    final result = Uint8List.fromList(input);
    result[offset] ^= mask;
    return result;
  }

  /// Inserts [inserted] bytes at [offset] in a copied [input].
  ///
  /// Throws [RangeError] when [offset] is outside `0..input.length` or any
  /// inserted value is not a byte.
  static Uint8List insert(List<int> input, int offset, List<int> inserted) {
    RangeError.checkValueInInterval(offset, 0, input.length, 'offset');
    _checkBytes(inserted, 'inserted');
    return Uint8List.fromList([
      ...input.take(offset),
      ...inserted,
      ...input.skip(offset),
    ]);
  }

  /// Replaces the half-open byte range `start..end` with [replacement].
  ///
  /// The [start] and [end] bounds are validated against [input], and every
  /// replacement value must be in the byte range.
  static Uint8List replaceRange(
    List<int> input,
    int start,
    int end,
    List<int> replacement,
  ) {
    RangeError.checkValueInInterval(start, 0, input.length, 'start');
    RangeError.checkValueInInterval(end, start, input.length, 'end');
    _checkBytes(replacement, 'replacement');
    return Uint8List.fromList([
      ...input.take(start),
      ...replacement,
      ...input.skip(end),
    ]);
  }

  static void _checkBytes(List<int> bytes, String name) {
    for (var index = 0; index < bytes.length; index++) {
      RangeError.checkValueInInterval(bytes[index], 0, 0xff, '$name[$index]');
    }
  }
}

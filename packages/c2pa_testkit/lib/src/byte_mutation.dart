import 'dart:typed_data';

/// Deterministic, non-mutating byte fixture transformations.
abstract final class ByteMutation {
  static Uint8List truncate(List<int> input, int length) {
    RangeError.checkValueInInterval(length, 0, input.length, 'length');
    return Uint8List.fromList(input.take(length).toList(growable: false));
  }

  static Uint8List flip(List<int> input, int offset, {int mask = 0xff}) {
    RangeError.checkValidIndex(offset, input, 'offset');
    RangeError.checkValueInInterval(mask, 0, 0xff, 'mask');
    final result = Uint8List.fromList(input);
    result[offset] ^= mask;
    return result;
  }

  static Uint8List insert(List<int> input, int offset, List<int> inserted) {
    RangeError.checkValueInInterval(offset, 0, input.length, 'offset');
    _checkBytes(inserted, 'inserted');
    return Uint8List.fromList([
      ...input.take(offset),
      ...inserted,
      ...input.skip(offset),
    ]);
  }

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

/// Shared byte comparison helpers for this package.
///
/// Two equality helpers exist because the choice is security relevant.
/// Use [constantTimeBytesEqual] whenever a mismatch position could leak
/// something an attacker does not already know, and [bytesEqual] for
/// comparisons against values that are public by construction, such as
/// object identifiers, DER-encoded names, and container magic bytes.
library;

/// Compares [left] and [right] without a data-dependent early exit.
///
/// The loop always runs for the longer of the two inputs, so neither the
/// position of the first differing byte nor the length of a common prefix
/// is observable through timing. A length mismatch is folded into the same
/// accumulator rather than short-circuiting.
bool constantTimeBytesEqual(List<int> left, List<int> right) {
  var difference = left.length ^ right.length;
  final length = left.length > right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final leftByte = index < left.length ? left[index] : 0;
    final rightByte = index < right.length ? right[index] : 0;
    difference |= leftByte ^ rightByte;
  }
  return difference == 0;
}

/// Compares [left] and [right], returning at the first differing byte.
///
/// This is the faster comparison but its timing reveals the length of the
/// common prefix. Only use it for values that are public by construction.
bool bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

/// Orders [left] and [right] lexicographically by unsigned byte value.
///
/// Returns a negative value when [left] sorts first, a positive value when
/// [right] sorts first, and zero when the two are equal. A shorter input
/// that is a prefix of the other sorts first. Only the sign is meaningful.
int compareBytes(List<int> left, List<int> right) {
  final length = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < length; index++) {
    final comparison = left[index].compareTo(right[index]);
    if (comparison != 0) {
      return comparison;
    }
  }
  return left.length.compareTo(right.length);
}

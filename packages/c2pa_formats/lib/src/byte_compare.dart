/// Shared byte comparison helpers for asset format handlers.
///
/// Format handlers match container magic bytes, chunk identifiers, and box
/// types, all of which are public by construction. These helpers therefore
/// return at the first differing byte. Do not use them for comparisons
/// where the position of a mismatch should stay unobservable.
library;

/// Whether [left] and [right] have the same length and the same bytes.
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

/// Whether [bytes] contains [expected] starting at [offset].
///
/// Returns `false` rather than throwing when [offset] is negative or when
/// [expected] would extend past the end of [bytes], so callers can probe a
/// possibly truncated buffer without a bounds check of their own.
bool bytesEqualAt(List<int> bytes, int offset, List<int> expected) {
  if (offset < 0 || offset + expected.length > bytes.length) {
    return false;
  }
  for (var index = 0; index < expected.length; index++) {
    if (bytes[offset + index] != expected[index]) {
      return false;
    }
  }
  return true;
}

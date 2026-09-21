import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:test/test.dart';

void main() {
  test('mutations return expected independent bytes', () {
    final input = [0x10, 0x20, 0x30, 0x40];

    expect(ByteMutation.truncate(input, 2), [0x10, 0x20]);
    expect(ByteMutation.flip(input, 1), [0x10, 0xdf, 0x30, 0x40]);
    expect(ByteMutation.flip(input, 2, mask: 0x0f), [0x10, 0x20, 0x3f, 0x40]);
    expect(ByteMutation.insert(input, 2, [0xaa, 0xbb]), [
      0x10,
      0x20,
      0xaa,
      0xbb,
      0x30,
      0x40,
    ]);
    expect(ByteMutation.replaceRange(input, 1, 3, [0xee]), [0x10, 0xee, 0x40]);
    expect(input, [0x10, 0x20, 0x30, 0x40]);
  });

  test('supports boundary operations', () {
    expect(ByteMutation.truncate([1], 0), isEmpty);
    expect(ByteMutation.insert([1], 0, [2]), [2, 1]);
    expect(ByteMutation.insert([1], 1, [2]), [1, 2]);
    expect(ByteMutation.replaceRange([1, 2], 0, 2, []), isEmpty);
    expect(ByteMutation.replaceRange([1], 1, 1, [2]), [1, 2]);
  });

  test('rejects invalid bounds, masks, and byte values', () {
    expect(() => ByteMutation.truncate([1], -1), throwsRangeError);
    expect(() => ByteMutation.truncate([1], 2), throwsRangeError);
    expect(() => ByteMutation.flip([1], 1), throwsRangeError);
    expect(() => ByteMutation.flip([1], 0, mask: 256), throwsRangeError);
    expect(() => ByteMutation.insert([1], 2, []), throwsRangeError);
    expect(() => ByteMutation.insert([1], 0, [-1]), throwsRangeError);
    expect(() => ByteMutation.replaceRange([1], 1, 0, []), throwsRangeError);
    expect(() => ByteMutation.replaceRange([1], 0, 2, []), throwsRangeError);
    expect(() => ByteMutation.replaceRange([1], 0, 1, [300]), throwsRangeError);
  });
}

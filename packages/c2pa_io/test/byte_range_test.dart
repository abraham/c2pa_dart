import 'package:c2pa_io/c2pa_io.dart';
import 'package:test/test.dart';

void main() {
  group('ByteRange', () {
    test('uses half-open boundaries', () {
      final range = ByteRange(2, 5);

      expect(range.length, 3);
      expect(range.containsOffset(2), isTrue);
      expect(range.containsOffset(4), isTrue);
      expect(range.containsOffset(5), isFalse);
      expect(range.containsRange(ByteRange(2, 5)), isTrue);
      expect(range.containsRange(ByteRange(5, 5)), isTrue);
    });

    test('supports the largest cross-platform coordinate', () {
      final range = ByteRange(ByteRange.maxCoordinate, ByteRange.maxCoordinate);

      expect(range.isEmpty, isTrue);
      expect(ByteRange.checkedAdd(ByteRange.maxCoordinate, 0), range.end);
    });

    test('rejects negative and reversed ranges', () {
      expect(() => ByteRange(-1, 0), throwsA(isA<InvalidByteRangeException>()));
      expect(() => ByteRange(2, 1), throwsA(isA<InvalidByteRangeException>()));
      expect(
        () => ByteRange.fromStartAndLength(0, -1),
        throwsA(isA<InvalidByteRangeException>()),
      );
    });

    test('detects cross-platform arithmetic overflow', () {
      expect(
        () =>
            ByteRange(ByteRange.maxCoordinate + 1, ByteRange.maxCoordinate + 1),
        throwsA(isA<ByteRangeOverflowException>()),
      );
      expect(
        () => ByteRange.fromStartAndLength(ByteRange.maxCoordinate, 1),
        throwsA(isA<ByteRangeOverflowException>()),
      );
      expect(
        () => ByteRange(1, 2).shift(ByteRange.maxCoordinate),
        throwsA(isA<ByteRangeOverflowException>()),
      );
    });

    test('computes intersections', () {
      expect(ByteRange(1, 5).intersection(ByteRange(3, 8)), ByteRange(3, 5));
      expect(ByteRange(1, 5).intersection(ByteRange(1, 5)), ByteRange(1, 5));
      expect(ByteRange(1, 3).intersection(ByteRange(3, 5)), isNull);
      expect(ByteRange(2, 2).intersection(ByteRange(2, 2)), isNull);
      expect(ByteRange(1, 5).overlaps(ByteRange(4, 6)), isTrue);
      expect(ByteRange(1, 5).overlaps(ByteRange(5, 6)), isFalse);
    });
  });

  group('mergeByteRanges', () {
    test('sorts and merges overlaps, nesting, and adjacency', () {
      final merged = mergeByteRanges([
        ByteRange(8, 10),
        ByteRange(2, 5),
        ByteRange(4, 7),
        ByteRange(1, 3),
        ByteRange(7, 8),
        ByteRange(20, 21),
      ]);

      expect(merged, [ByteRange(1, 10), ByteRange(20, 21)]);
    });

    test('drops empty ranges and returns an immutable result', () {
      final merged = mergeByteRanges([ByteRange(2, 2)]);

      expect(merged, isEmpty);
      expect(() => merged.add(ByteRange(1, 2)), throwsUnsupportedError);
    });
  });

  group('complementByteRanges', () {
    test('returns gaps around normalized exclusions', () {
      final complement = complementByteRanges(ByteRange(10, 30), [
        ByteRange(20, 25),
        ByteRange(12, 15),
        ByteRange(14, 18),
        ByteRange(25, 27),
        ByteRange(10, 10),
      ]);

      expect(complement, [
        ByteRange(10, 12),
        ByteRange(18, 20),
        ByteRange(27, 30),
      ]);
    });

    test('handles no exclusions and full exclusion', () {
      expect(complementByteRanges(ByteRange(3, 7), []), [ByteRange(3, 7)]);
      expect(complementByteRanges(ByteRange(3, 7), [ByteRange(3, 7)]), isEmpty);
      expect(complementByteRanges(ByteRange(3, 3), []), isEmpty);
      expect(complementByteRanges(ByteRange(3, 7), [ByteRange(100, 100)]), [
        ByteRange(3, 7),
      ]);
    });

    test('rejects exclusions outside the container', () {
      expect(
        () => complementByteRanges(ByteRange(3, 7), [ByteRange(2, 4)]),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
      expect(
        () => complementByteRanges(ByteRange(3, 7), [ByteRange(7, 8)]),
        throwsA(isA<ByteRangeOutOfBoundsException>()),
      );
    });
  });
}

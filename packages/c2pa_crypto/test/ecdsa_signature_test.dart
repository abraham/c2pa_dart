import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('ECDSA DER and P1363 conversion', () {
    test('converts and pads a valid signature', () {
      final der = [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x01, 0x02];
      final p1363 = ecdsaDerToP1363(der, componentLength: 4);

      expect(p1363, [0, 0, 0, 0x80, 0, 0, 1, 2]);
      expect(ecdsaP1363ToDer(p1363, componentLength: 4), der);
    });

    test('round trips P-256, P-384, and P-521 widths', () {
      for (final width in [32, 48, 66]) {
        final p1363 = [
          ...List<int>.generate(width, (index) => index == 0 ? 0x80 : index),
          ...List<int>.generate(width, (index) => index + 1),
        ];
        final der = ecdsaP1363ToDer(p1363, componentLength: width);
        expect(ecdsaDerToP1363(der, componentLength: width), p1363);
      }
    });

    test('uses minimal long-form sequence length', () {
      final p1363 = List<int>.filled(132, 1);
      final der = ecdsaP1363ToDer(p1363, componentLength: 66);

      expect(der.take(3), [0x30, 0x81, 0x88]);
      expect(ecdsaDerToP1363(der, componentLength: 66), p1363);
    });

    test('rejects invalid component widths and P1363 lengths', () {
      expect(
        () => ecdsaDerToP1363([], componentLength: 0),
        throwsArgumentError,
      );
      expect(
        () => ecdsaP1363ToDer([1, 2], componentLength: -1),
        throwsArgumentError,
      );
      expect(
        () => ecdsaP1363ToDer([1, 2, 3], componentLength: 2),
        throwsArgumentError,
      );
    });

    test('rejects zero P1363 integers', () {
      expect(
        () => ecdsaP1363ToDer([0, 0, 0, 1], componentLength: 2),
        throwsFormatException,
      );
      expect(
        () => ecdsaP1363ToDer([0, 1, 0, 0], componentLength: 2),
        throwsFormatException,
      );
    });

    final malformed = <String, List<int>>{
      'empty input': [],
      'wrong sequence tag': [0x31, 0],
      'truncated sequence length': [0x30],
      'indefinite sequence length': [0x30, 0x80],
      'oversized length-of-length': [0x30, 0x85, 0, 0, 0, 0, 0],
      'truncated long-form length': [0x30, 0x82, 0x01],
      'non-minimal long-form length': [
        0x30,
        0x81,
        0x06,
        0x02,
        1,
        1,
        0x02,
        1,
        1,
      ],
      'leading-zero long-form length': [0x30, 0x82, 0, 0x80],
      'sequence length too short': [0x30, 0x05, 0x02, 1, 1, 0x02, 1, 1],
      'sequence length too long': [0x30, 0x07, 0x02, 1, 1, 0x02, 1, 1],
      'missing first integer': [0x30, 0],
      'wrong integer tag': [0x30, 6, 0x03, 1, 1, 0x02, 1, 1],
      'empty integer': [0x30, 5, 0x02, 0, 0x02, 1, 1],
      'negative integer': [0x30, 6, 0x02, 1, 0x80, 0x02, 1, 1],
      'redundant integer zero': [0x30, 7, 0x02, 2, 0, 1, 0x02, 1, 1],
      'zero integer': [0x30, 6, 0x02, 1, 0, 0x02, 1, 1],
      'missing second integer': [0x30, 3, 0x02, 1, 1],
      'integer crosses sequence': [0x30, 6, 0x02, 4, 1, 2, 3, 4],
      'extra sequence member': [0x30, 9, 0x02, 1, 1, 0x02, 1, 1, 0x02, 1, 1],
      'trailing data': [0x30, 6, 0x02, 1, 1, 0x02, 1, 1, 0],
      'non-byte input': [0x30, 6, 0x02, 1, 256, 0x02, 1, 1],
    };

    for (final entry in malformed.entries) {
      test('rejects ${entry.key}', () {
        expect(
          () => ecdsaDerToP1363(entry.value, componentLength: 32),
          throwsFormatException,
        );
      });
    }

    test('rejects an integer wider than the component', () {
      expect(
        () => ecdsaDerToP1363([
          0x30,
          8,
          0x02,
          3,
          1,
          2,
          3,
          0x02,
          1,
          1,
        ], componentLength: 2),
        throwsFormatException,
      );
    });
  });
}

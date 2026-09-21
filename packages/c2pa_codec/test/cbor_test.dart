import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('CBOR encoding', () {
    test('encodes primitive values and minimal integers', () {
      expect(encodeCbor(null), [0xf6]);
      expect(encodeCbor(false), [0xf4]);
      expect(encodeCbor(true), [0xf5]);
      expect(encodeCbor(23), [0x17]);
      expect(encodeCbor(24), [0x18, 0x18]);
      expect(encodeCbor(255), [0x18, 0xff]);
      expect(encodeCbor(256), [0x19, 0x01, 0x00]);
      expect(encodeCbor(-1), [0x20]);
      expect(encodeCbor(-25), [0x38, 0x18]);
    });

    test('encodes the full CBOR integer range with BigInt', () {
      final uint32Max = BigInt.parse('4294967295');
      final uint32Next = BigInt.parse('4294967296');
      final safeMax = BigInt.parse('9007199254740991');
      final safeNext = BigInt.parse('9007199254740992');
      final uint64Max = BigInt.parse('18446744073709551615');
      final nint64Min = BigInt.parse('-18446744073709551616');

      expect(encodeCbor(uint32Max), [0x1a, 0xff, 0xff, 0xff, 0xff]);
      expect(encodeCbor(uint32Next), [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
      expect(encodeCbor(safeMax), [
        0x1b,
        0,
        0x1f,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
      ]);
      expect(encodeCbor(safeNext), [0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0]);
      expect(encodeCbor(uint64Max), [0x1b, ...List<int>.filled(8, 0xff)]);
      expect(encodeCbor(nint64Min), [0x3b, ...List<int>.filled(8, 0xff)]);

      expect(decodeCbor(encodeCbor(uint32Max)), uint32Max.toInt());
      expect(decodeCbor(encodeCbor(uint32Next)), uint32Next.toInt());
      expect(decodeCbor(encodeCbor(safeMax)), safeMax.toInt());
      expect(decodeCbor(encodeCbor(safeNext)), safeNext);
      expect(decodeCbor(encodeCbor(uint64Max)), uint64Max);
      expect(decodeCbor(encodeCbor(nint64Min)), nint64Min);
      expect(
        decodeCbor(encodeCbor(BigInt.parse('-9007199254740992'))),
        BigInt.parse('-9007199254740992'),
      );
    });

    test('rejects integers outside uint64 and nint64', () {
      expect(
        () => encodeCbor(BigInt.parse('18446744073709551616')),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.integerOutOfRange,
          ),
        ),
      );
      expect(
        () => encodeCbor(BigInt.parse('-18446744073709551617')),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.integerOutOfRange,
          ),
        ),
      );
      expect(
        () => encodeCbor(int.parse('9007199254740992')),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.integerOutOfRange,
          ),
        ),
      );
    });

    test('encodes strings, arrays, maps, and finite doubles', () {
      expect(encodeCbor(Uint8List.fromList([1, 2, 3])), [0x43, 1, 2, 3]);
      expect(encodeCbor('IETF'), [0x64, 0x49, 0x45, 0x54, 0x46]);
      expect(encodeCbor([1, 'a']), [0x82, 0x01, 0x61, 0x61]);
      expect(encodeCbor(1.5), [0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]);
    });

    test('sorts map keys by encoded length then lexicographically', () {
      final encoded = encodeCbor(<Object, Object>{'a': 3, 24: 2, -1: 1});
      expect(encoded, [0xa3, 0x20, 0x01, 0x18, 0x18, 0x02, 0x61, 0x61, 0x03]);
    });

    test('rejects unsupported and non-finite values', () {
      expect(
        () => encodeCbor(double.infinity),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.nonFiniteDouble,
          ),
        ),
      );
      expect(
        () => encodeCbor(DateTime(2020)),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.unsupportedType,
          ),
        ),
      );
    });

    test('enforces the nesting limit', () {
      expect(
        () => encodeCbor([
          [0],
        ], maxNestingDepth: 1),
        throwsA(
          isA<CborEncodingException>().having(
            (error) => error.code,
            'code',
            CborEncodingErrorCode.excessiveNesting,
          ),
        ),
      );
    });
  });

  group('CBOR decoding', () {
    test('round trips supported values', () {
      final value = <Object, Object?>{
        'bytes': Uint8List.fromList([0, 1, 255]),
        'values': <Object?>[null, true, false, -1000, 1000, 2.5],
      };
      final decoded = decodeCbor(encodeCbor(value))! as Map<Object?, Object?>;
      expect(decoded['bytes'], [0, 1, 255]);
      expect(decoded['values'], <Object?>[null, true, false, -1000, 1000, 2.5]);
    });

    test('decodes finite half and single precision floats', () {
      expect(decodeCbor([0xf9, 0x3e, 0x00]), 1.5);
      expect(decodeCbor([0xfa, 0x3f, 0xc0, 0, 0]), 1.5);
    });

    test('rejects malformed inputs with typed errors', () {
      final cases = <(List<int>, CborDecodingErrorCode)>[
        ([0x00, 0x00], CborDecodingErrorCode.trailingData),
        ([0x5f, 0xff], CborDecodingErrorCode.indefiniteLength),
        ([0x62, 0xc3, 0x28], CborDecodingErrorCode.invalidUtf8),
        ([0x18, 0x17], CborDecodingErrorCode.nonMinimalInteger),
        ([0x1a, 0, 0, 0, 1], CborDecodingErrorCode.nonMinimalInteger),
        ([0x43, 1], CborDecodingErrorCode.truncated),
        ([0xc0, 0x00], CborDecodingErrorCode.unsupportedTag),
        ([0xf0], CborDecodingErrorCode.unsupportedSimpleValue),
        ([0xf8, 0x20], CborDecodingErrorCode.unsupportedSimpleValue),
        ([0xf9, 0x7c, 0x00], CborDecodingErrorCode.nonFiniteDouble),
        (
          [0x5b, ...List<int>.filled(8, 0xff)],
          CborDecodingErrorCode.integerOutOfRange,
        ),
      ];

      for (final (bytes, code) in cases) {
        expect(
          () => decodeCbor(bytes),
          throwsA(
            isA<CborDecodingException>().having(
              (error) => error.code,
              'code',
              code,
            ),
          ),
          reason: 'bytes: $bytes',
        );
      }
    });

    test('rejects duplicate and non-canonically ordered map keys', () {
      expect(
        () => decodeCbor([0xa2, 0x01, 0x00, 0x01, 0x01]),
        throwsA(
          isA<CborDecodingException>().having(
            (error) => error.code,
            'code',
            CborDecodingErrorCode.duplicateMapKey,
          ),
        ),
      );
      expect(
        () => decodeCbor([0xa2, 0x02, 0x00, 0x01, 0x01]),
        throwsA(
          isA<CborDecodingException>().having(
            (error) => error.code,
            'code',
            CborDecodingErrorCode.nonCanonicalMapOrder,
          ),
        ),
      );
      expect(
        () => decodeCbor([
          0xa2,
          0x01,
          0x00,
          0xfb,
          0x3f,
          0xf0,
          0,
          0,
          0,
          0,
          0,
          0,
          0x01,
        ]),
        throwsA(
          isA<CborDecodingException>().having(
            (error) => error.code,
            'code',
            CborDecodingErrorCode.duplicateMapKey,
          ),
        ),
      );
    });

    test('can decode maps whose keys are not canonically ordered', () {
      final value = decodeCbor([
        0xa2,
        0x61,
        0x62,
        0x01,
        0x61,
        0x61,
        0x02,
      ], requireCanonicalMapOrder: false);

      expect(value, {'b': 1, 'a': 2});
    });

    test('can decode preserving indefinite-length containers', () {
      final value = decodeCbor(
        [
          0xbf,
          0x61,
          0x62,
          0x9f,
          0x01,
          0x02,
          0xff,
          0x61,
          0x61,
          0x7f,
          0x61,
          0x78,
          0x61,
          0x79,
          0xff,
          0xff,
        ],
        requireCanonicalMapOrder: false,
        allowIndefiniteLength: true,
      );

      expect(value, {
        'b': [1, 2],
        'a': 'xy',
      });
    });

    test('enforces the nesting limit', () {
      expect(
        () => decodeCbor([0x81, 0x81, 0x00], maxNestingDepth: 1),
        throwsA(
          isA<CborDecodingException>().having(
            (error) => error.code,
            'code',
            CborDecodingErrorCode.excessiveNesting,
          ),
        ),
      );
    });
  });
}

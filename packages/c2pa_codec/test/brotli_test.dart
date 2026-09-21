import 'dart:convert';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('Brotli decoding', () {
    test('decodes a generic text vector', () {
      final decoded = decodeBrotli(
        _hex(
          '21a8000454686520717569636b2062726f776e20666f78206a756d7073206f76'
          '657220746865206c617a7920646f6703',
        ),
        maxOutputBytes: 43,
      );
      expect(
        utf8.decode(decoded),
        'The quick brown fox jumps over the lazy dog',
      );
    });

    test('decodes the upstream dictionary-word vector', () {
      // From tiagohm/brotli at the vendored commit; see vectors/README.md.
      final decoded = decodeBrotli([
        0x1b,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x80,
        0xe3,
        0xb4,
        0x0d,
        0x00,
        0x00,
        0x07,
        0x5b,
        0x26,
        0x31,
        0x40,
        0x02,
        0x00,
        0xe0,
        0x4e,
        0x1b,
        0x41,
        0x02,
      ], maxOutputBytes: 4);
      expect(ascii.decode(decoded), 'time');
    });

    test('handles empty output at a zero-byte limit', () {
      expect(decodeBrotli([6], maxOutputBytes: 0), isEmpty);
    });

    test('enforces the output limit during decompression', () {
      final compressedBomb = _hex('81fa340cfc1241f1582090e51700');
      expect(
        () => decodeBrotli(compressedBomb, maxOutputBytes: 100),
        _brotliError(BrotliDecodingErrorCode.outputLimitExceeded),
      );
      expect(
        decodeBrotli(compressedBomb, maxOutputBytes: 100000),
        hasLength(100000),
      );
    });

    test('distinguishes invalid limits, truncation, and malformed data', () {
      expect(
        () => decodeBrotli([6], maxOutputBytes: -1),
        _brotliError(BrotliDecodingErrorCode.invalidLimit),
      );
      final valid = _hex(
        '21a8000454686520717569636b2062726f776e20666f78206a756d7073206f76'
        '657220746865206c617a7920646f6703',
      );
      expect(
        () => decodeBrotli(
          valid.sublist(0, valid.length - 2),
          maxOutputBytes: 100,
        ),
        _brotliError(BrotliDecodingErrorCode.truncated),
      );
      expect(
        () => decodeBrotli([0xff, 0xff, 0xff, 0xff], maxOutputBytes: 100),
        _brotliError(BrotliDecodingErrorCode.malformed),
      );
      expect(
        () => decodeBrotli([256], maxOutputBytes: 100),
        _brotliError(BrotliDecodingErrorCode.malformed),
      );
    });
  });
}

List<int> _hex(String value) => List<int>.generate(
  value.length ~/ 2,
  (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
  growable: false,
);

Matcher _brotliError(BrotliDecodingErrorCode code) => throwsA(
  isA<BrotliDecodingException>().having((error) => error.code, 'code', code),
);

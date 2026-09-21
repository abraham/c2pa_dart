import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('COSE headers', () {
    test('provides typed standard and custom labels', () {
      expect(CoseHeaderLabel.algorithm.value, 1);
      expect(CoseHeaderLabel.contentType.value, 3);
      expect(CoseHeaderLabel.keyId.value, 4);
      expect(CoseHeaderLabel.x509Chain.value, 33);
      expect(
        CoseHeaderLabel.custom(42, name: 'custom'),
        CoseHeaderLabel.custom(42),
      );
    });

    test('validates standard header value types', () {
      expect(
        () => CoseHeaders({CoseHeaderLabel.algorithm: 'ES256'}),
        _coseError(CoseErrorCode.invalidHeaderValue),
      );
      expect(
        () => CoseHeaders({CoseHeaderLabel.keyId: 'key'}),
        _coseError(CoseErrorCode.invalidHeaderValue),
      );
      expect(
        () => CoseHeaders({CoseHeaderLabel.x509Chain: <Object?>[]}),
        _coseError(CoseErrorCode.invalidHeaderValue),
      );
    });
  });

  group('COSE_Sign1', () {
    test('encodes and parses tagged messages deterministically', () {
      final message = CoseSign1(
        protectedHeaders: CoseHeaders({
          CoseHeaderLabel.algorithm: -7,
          CoseHeaderLabel.contentType: 'application/c2pa',
        }),
        unprotectedHeaders: CoseHeaders({
          CoseHeaderLabel.keyId: Uint8List.fromList([1, 2]),
          CoseHeaderLabel.custom(100): 'preserved',
        }),
        payload: Uint8List.fromList([0xa1, 0x01, 0x02]),
        signature: Uint8List.fromList([3, 4, 5]),
      );

      final encoded = message.encode();
      expect(encoded.first, 0xd2);
      final parsed = CoseSign1.parse(encoded);
      expect(parsed.tagged, isTrue);
      expect(parsed.protectedHeaders[CoseHeaderLabel.algorithm], -7);
      expect(
        parsed.protectedHeaders[CoseHeaderLabel.contentType],
        'application/c2pa',
      );
      expect(parsed.unprotectedHeaders[CoseHeaderLabel.keyId], [1, 2]);
      expect(
        parsed.unprotectedHeaders[CoseHeaderLabel.custom(100)],
        'preserved',
      );
      expect(parsed.payload, [0xa1, 0x01, 0x02]);
      expect(parsed.signature, [3, 4, 5]);
      expect(parsed.encode(), encoded);
    });

    test('supports untagged messages and tag policy', () {
      final message = _message(tagged: false);
      final encoded = message.encode();
      expect(encoded.first, 0x84);
      expect(CoseSign1.parse(encoded).tagged, isFalse);
      expect(
        () => CoseSign1.parse(encoded, allowUntagged: false),
        _coseError(CoseErrorCode.tagRequired),
      );
      expect(
        () => CoseSign1.parse([0xd2, ...encoded], allowTagged: false),
        _coseError(CoseErrorCode.tagForbidden),
      );
      expect(
        () => CoseSign1.parse([0xd3, ...encoded]),
        _coseError(CoseErrorCode.unsupportedTag),
      );
      expect(
        () => CoseSign1.parse([0xd8, 0x12, ...encoded]),
        _coseError(CoseErrorCode.unsupportedTag),
      );
    });

    test('requires alg in protected headers', () {
      expect(
        () => CoseSign1(
          protectedHeaders: CoseHeaders(),
          unprotectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -7}),
          payload: Uint8List(0),
          signature: Uint8List(0),
        ),
        _coseError(CoseErrorCode.missingProtectedAlgorithm),
      );
      final encoded = encodeCbor([
        Uint8List(0),
        <int, Object?>{1: -7},
        Uint8List(0),
        Uint8List(0),
      ]);
      expect(
        () => CoseSign1.parse(encoded),
        _coseError(CoseErrorCode.missingProtectedAlgorithm),
      );
    });

    test('rejects semantic duplicates across header buckets', () {
      expect(
        () => CoseSign1(
          protectedHeaders: CoseHeaders({
            CoseHeaderLabel.algorithm: -7,
            CoseHeaderLabel.keyId: Uint8List.fromList([1]),
          }),
          unprotectedHeaders: CoseHeaders({
            CoseHeaderLabel.custom(4): Uint8List.fromList([2]),
          }),
          payload: Uint8List(0),
          signature: Uint8List(0),
        ),
        _coseError(CoseErrorCode.duplicateHeader),
      );
    });

    test('preserves exact protected bytes when rebuilding', () {
      final protected = Uint8List.fromList([
        0xa2,
        0x01,
        0x26,
        0x18,
        0x64,
        0xf9,
        0x3e,
        0x00,
      ]);
      final encoded = encodeCbor([
        protected,
        <int, Object?>{},
        Uint8List.fromList([1]),
        Uint8List.fromList([2]),
      ]);
      final parsed = CoseSign1.parse(encoded);
      expect(parsed.protectedBytes, protected);
      expect(parsed.encode(tagged: false), encoded);
    });

    test('builds the RFC 8152 Signature1 structure vector', () {
      final message = CoseSign1(
        protectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -7}),
        payload: Uint8List.fromList('This is the content.'.codeUnits),
        signature: Uint8List(64),
        tagged: false,
      );
      expect(
        _hex(message.signatureStructure()),
        '846a5369676e61747572653143a101264054546869732069732074686520636f6e74656e742e',
      );
    });

    test('builds detached Sig_structure with external AAD', () {
      final message = CoseSign1(
        protectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -7}),
        signature: Uint8List.fromList([1]),
      );
      final structure = message.signatureStructure(
        externalAad: Uint8List.fromList([2, 3]),
        detachedPayload: Uint8List.fromList([4, 5]),
      );
      expect(decodeCbor(structure), [
        'Signature1',
        message.protectedBytes,
        [2, 3],
        [4, 5],
      ]);
      expect(
        () => message.signatureStructure(),
        _coseError(CoseErrorCode.detachedPayloadRequired),
      );
      expect(
        () => _message().signatureStructure(
          detachedPayload: Uint8List.fromList([1]),
        ),
        _coseError(CoseErrorCode.conflictingPayload),
      );
    });

    test('rejects malformed element types and structure', () {
      final validProtected = encodeCbor(<int, Object?>{1: -7});
      final cases = <(List<int>, CoseErrorCode)>[
        (
          encodeCbor([validProtected, <int, Object?>{}, Uint8List(0)]),
          CoseErrorCode.invalidStructure,
        ),
        (
          encodeCbor([
            <int, Object?>{1: -7},
            <int, Object?>{},
            null,
            Uint8List(0),
          ]),
          CoseErrorCode.invalidType,
        ),
        (
          encodeCbor([encodeCbor(1), <int, Object?>{}, null, Uint8List(0)]),
          CoseErrorCode.invalidType,
        ),
        (
          encodeCbor([validProtected, <Object?>[], null, Uint8List(0)]),
          CoseErrorCode.invalidType,
        ),
        (
          encodeCbor([
            validProtected,
            <int, Object?>{},
            'payload',
            Uint8List(0),
          ]),
          CoseErrorCode.invalidType,
        ),
        (
          encodeCbor([validProtected, <int, Object?>{}, null, null]),
          CoseErrorCode.invalidType,
        ),
      ];
      for (final (bytes, code) in cases) {
        expect(() => CoseSign1.parse(bytes), _coseError(code));
      }
    });

    test('rejects noninteger labels, trailing data, and truncation', () {
      final protectedWithTextLabel = encodeCbor(<Object, Object?>{'alg': -7});
      expect(
        () => CoseSign1.parse(
          encodeCbor([
            protectedWithTextLabel,
            <int, Object?>{},
            null,
            Uint8List(0),
          ]),
        ),
        _coseError(CoseErrorCode.invalidHeaderLabel),
      );

      final encoded = _message().encode();
      expect(
        () => CoseSign1.parse([...encoded, 0]),
        _coseError(CoseErrorCode.trailingData),
      );
      expect(
        () => CoseSign1.parse(encoded.sublist(0, encoded.length - 1)),
        _coseError(CoseErrorCode.truncated),
      );
    });
  });
}

CoseSign1 _message({bool tagged = true}) => CoseSign1(
  protectedHeaders: CoseHeaders({CoseHeaderLabel.algorithm: -7}),
  payload: Uint8List.fromList([1, 2, 3]),
  signature: Uint8List.fromList([4, 5]),
  tagged: tagged,
);

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

Matcher _coseError(CoseErrorCode code) =>
    throwsA(isA<CoseException>().having((error) => error.code, 'code', code));

import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('JUMBF identifiers', () {
    test('publishes profile fourcc and UUID constants', () {
      expect(JumbfFourcc.superBox, 'jumb');
      expect(JumbfFourcc.description, 'jumd');
      expect(JumbfFourcc.embeddedFileDescription, 'bfdb');
      expect(JumbfFourcc.embeddedFileData, 'bidb');
      expect(
        JumbfUuid.hex(JumbfUuid.bytes(JumbfUuid.c2paManifestStore)),
        JumbfUuid.c2paManifestStore,
      );
      expect(JumbfUuid.json, '6a736f6e00110010800000aa00389b71');
      expect(JumbfUuid.cbor, '63626f7200110010800000aa00389b71');
    });
  });

  group('JUMBF description', () {
    test('writes and parses labels, id, and hash', () {
      final hash = Uint8List.fromList(List<int>.generate(32, (index) => index));
      final description = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: 'urn:c2pa:test',
        id: 42,
        hash: hash,
      );
      final encoded = description.encode();
      expect(utf8.decode(encoded.sublist(4, 8)), 'jumd');
      expect(encoded[24], 0x0f);

      hash[0] = 255;
      final parsed = JumbfDescription.parse(encoded);
      expect(parsed.contentTypeHex, JumbfUuid.c2paManifest);
      expect(parsed.requestable, isTrue);
      expect(parsed.label, 'urn:c2pa:test');
      expect(parsed.id, 42);
      expect(parsed.hash, List<int>.generate(32, (index) => index));
      expect(parsed.encode(), encoded);
    });

    test('preserves a parsed large-size description header', () {
      final standard = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ).encode();
      final payload = standard.sublist(8);
      final header = IsoBoxHeader.create(
        type: 'jumd',
        payloadSize: payload.length,
        forceLargeSize: true,
      ).encode();
      final encoded = Uint8List.fromList([...header, ...payload]);
      expect(JumbfDescription.parse(encoded).encode(), encoded);
    });

    test('supports an unlabeled, non-requestable baseline description', () {
      final description = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.json,
        requestable: false,
      );
      final parsed = JumbfDescription.parse(description.encode());
      expect(parsed.label, isNull);
      expect(parsed.requestable, isFalse);
    });

    test('writes and parses private salt boxes', () {
      final salt = Uint8List.fromList(List<int>.generate(16, (index) => index));
      final description = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: 'salted',
        salt: salt,
      );

      final encoded = description.encode();
      expect(encoded[24], 0x13);
      final parsed = JumbfDescription.parse(encoded);
      expect(parsed.salt, salt);
      expect(parsed.encode(), encoded);
    });

    test('rejects unsupported toggles and malformed labels', () {
      final unsupported = _box('jumd', [...Uint8List(16), 0x20]);
      expect(
        () => JumbfDescription.parse(unsupported),
        _jumbfError(JumbfErrorCode.unsupportedDescriptionFeature),
      );

      final unterminated = _box('jumd', [
        ...Uint8List(16),
        0x03,
        ...utf8.encode('label'),
      ]);
      expect(
        () => JumbfDescription.parse(unterminated),
        _jumbfError(JumbfErrorCode.invalidDescription),
      );

      final malformedUtf8 = _box('jumd', [
        ...Uint8List(16),
        0x03,
        0xc3,
        0x28,
        0,
      ]);
      expect(
        () => JumbfDescription.parse(malformedUtf8),
        _jumbfError(JumbfErrorCode.invalidUtf8),
      );
    });
  });

  group('JUMBF trees', () {
    test('round trips typed payloads while preserving exact bytes', () {
      final tree = _fixtureTree();
      final encoded = tree.encode();
      final parsed = parseJumbf(encoded);

      expect(parsed.label, 'c2pa');
      expect(parsed.children, hasLength(1));
      final manifest = parsed.children.single as JumbfSuperBoxNode;
      expect(manifest.label, 'manifest');
      expect(manifest.children[0], isA<JumbfCborNode>());
      expect(manifest.children[1], isA<JumbfJsonNode>());

      final embeddedDescription =
          manifest.children[2] as JumbfEmbeddedFileDescriptionNode;
      expect(embeddedDescription.mediaType, 'image/jpeg');
      expect(embeddedDescription.fileName, 'preview.jpg');
      expect(manifest.children[3], isA<JumbfEmbeddedFileNode>());

      final uuid = manifest.children[4] as JumbfUuidNode;
      expect(uuid.userType, List<int>.generate(16, (index) => index));
      expect(uuid.payload, [9, 8, 7]);

      final unknown = manifest.children[5] as JumbfUnknownNode;
      expect(unknown.boxType, 'test');
      expect(unknown.payload, [4, 5, 6]);
      expect(parsed.encode(), encoded);
      expect(parsed.rawBytes, encoded);
    });

    test('finds nodes by paths and JUMBF URIs', () {
      final parsed = parseJumbf(_fixtureTree().encode());
      expect(parsed.find('/c2pa/manifest')?.label, 'manifest');
      expect(parsed.find('c2pa/manifest')?.label, 'manifest');
      expect(parsed.find('self#jumbf=/c2pa/manifest')?.label, 'manifest');
      expect(
        parsed.find('self#jumbf=/c2pa/manifest?hl=abc')?.label,
        'manifest',
      );
      expect(parsed.find('/c2pa/missing'), isNull);
    });

    test('preserves non-default ISO header encodings', () {
      final description = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ).encode();
      final payload = [
        ...description,
        ..._box('test', [1, 2]),
      ];
      final largeHeader = IsoBoxHeader.create(
        type: 'jumb',
        payloadSize: payload.length,
        forceLargeSize: true,
      ).encode();
      final bytes = Uint8List.fromList([...largeHeader, ...payload]);
      expect(parseJumbf(bytes).encode(), bytes);
    });

    test('rejects duplicate sibling labels', () {
      final child = JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.json,
          label: 'same',
        ),
      ).encode();
      final rootDescription = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ).encode();
      final duplicateFixture = _box('jumb', [
        ...rootDescription,
        ...child,
        ...child,
      ]);

      expect(
        () => parseJumbf(duplicateFixture),
        _jumbfError(JumbfErrorCode.duplicateLabel),
      );
    });

    test('rejects malformed child bounds and trailing data', () {
      final rootDescription = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ).encode();
      final invalidChild = <int>[0, 0, 0, 20, ...'json'.codeUnits, 1];
      expect(
        () => parseJumbf(_box('jumb', [...rootDescription, ...invalidChild])),
        _jumbfError(JumbfErrorCode.invalidBox),
      );
      expect(
        () => parseJumbf([..._fixtureTree().encode(), 0]),
        _jumbfError(JumbfErrorCode.trailingData),
      );
    });

    test('enforces nesting and box-count limits', () {
      JumbfSuperBoxNode nested(String label, int remaining) {
        return JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paManifest,
            label: label,
          ),
          children: remaining == 0
              ? const []
              : [nested('level$remaining', remaining - 1)],
        );
      }

      final bytes = nested('root', 3).encode();
      expect(
        () => parseJumbf(bytes, maxNestingDepth: 2),
        _jumbfError(JumbfErrorCode.excessiveNesting),
      );
      expect(
        () => parseJumbf(_fixtureTree().encode(), maxBoxCount: 3),
        _jumbfError(JumbfErrorCode.excessiveBoxCount),
      );
    });
  });

  group('compressed C2PA manifests', () {
    test('recognizes brob and expands one c2ma manifest', () {
      final outer = _compressedOuter(_validCompressedManifest);
      final parsedOuter = parseJumbf(outer);
      expect(parsedOuter.isCompressedManifest, isTrue);
      expect(parsedOuter.children.single, isA<JumbfBrotliNode>());

      final decoded = decodeCompressedJumbf(outer, maxOutputBytes: 1024);
      expect(decoded.manifest.label, 'manifest');
      expect(
        decoded.manifest.description.contentTypeHex,
        JumbfUuid.c2paManifest,
      );
      expect(decoded.originalBytes, outer);
      expect([
        ...decoded.outerDescriptionBytes,
        ...decoded.brotliBoxBytes,
      ], outer.sublist(8));
      expect(decoded.compressedPayload, _validCompressedManifest);

      final mutable = decoded.originalBytes;
      mutable[0] = 0;
      expect(decoded.originalBytes, outer);
    });

    test('accepts c2um update manifests', () {
      final decoded = decodeCompressedJumbf(
        _compressedOuter(_compressedUpdateManifest),
        maxOutputBytes: 1024,
      );
      expect(
        decoded.manifest.description.contentTypeHex,
        JumbfUuid.c2paUpdateManifest,
      );
    });

    test('rejects wrong outer shape, inner type, and label mismatch', () {
      final notCompressed = JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.c2paManifest,
          label: 'manifest',
        ),
      ).encode();
      expect(
        () => decodeCompressedJumbf(notCompressed, maxOutputBytes: 1024),
        _jumbfError(JumbfErrorCode.invalidCompressedManifest),
      );

      final missingBrob = JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.c2paCompressedManifest,
          label: 'manifest',
        ),
      ).encode();
      expect(
        () => decodeCompressedJumbf(missingBrob, maxOutputBytes: 1024),
        _jumbfError(JumbfErrorCode.invalidCompressedManifest),
      );
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(_compressedWrongInnerType),
          maxOutputBytes: 1024,
        ),
        _jumbfError(JumbfErrorCode.invalidCompressedManifest),
      );
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(_validCompressedManifest, label: 'other'),
          maxOutputBytes: 1024,
        ),
        _jumbfError(JumbfErrorCode.compressedManifestLabelMismatch),
      );
    });

    test('rejects trailing expanded data and malformed Brotli', () {
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(_compressedManifestWithTrailingByte),
          maxOutputBytes: 1024,
        ),
        _jumbfError(JumbfErrorCode.trailingData),
      );
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(Uint8List.fromList([0xff, 0xff, 0xff])),
          maxOutputBytes: 1024,
        ),
        throwsA(isA<BrotliDecodingException>()),
      );
    });

    test('enforces decompressed-size limits before expansion completes', () {
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(_validCompressedManifest),
          maxOutputBytes: 16,
        ),
        throwsA(
          isA<BrotliDecodingException>().having(
            (error) => error.code,
            'code',
            BrotliDecodingErrorCode.outputLimitExceeded,
          ),
        ),
      );
      expect(
        () => decodeCompressedJumbf(
          _compressedOuter(_compressedBomb),
          maxOutputBytes: 100,
        ),
        throwsA(
          isA<BrotliDecodingException>().having(
            (error) => error.code,
            'code',
            BrotliDecodingErrorCode.outputLimitExceeded,
          ),
        ),
      );
    });
  });
}

JumbfSuperBoxNode _fixtureTree() => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paManifestStore,
    label: 'c2pa',
  ),
  children: [
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: 'manifest',
      ),
      children: [
        JumbfCborNode(Uint8List.fromList([0xa1, 0x61, 0x61, 0x01])),
        JumbfJsonNode(Uint8List.fromList(utf8.encode('{"a":1}'))),
        JumbfEmbeddedFileDescriptionNode(
          mediaType: 'image/jpeg',
          fileName: 'preview.jpg',
        ),
        JumbfEmbeddedFileNode(Uint8List.fromList([1, 2, 3])),
        JumbfUuidNode(
          userType: Uint8List.fromList(
            List<int>.generate(16, (index) => index),
          ),
          payload: Uint8List.fromList([9, 8, 7]),
        ),
        JumbfUnknownNode(
          boxType: 'test',
          payload: Uint8List.fromList([4, 5, 6]),
        ),
      ],
    ),
  ],
);

Uint8List _box(String type, List<int> payload) {
  final header = IsoBoxHeader.create(
    type: type,
    payloadSize: payload.length,
  ).encode();
  return Uint8List.fromList([...header, ...payload]);
}

Matcher _jumbfError(JumbfErrorCode code) =>
    throwsA(isA<JumbfException>().having((error) => error.code, 'code', code));

Uint8List _compressedOuter(Uint8List compressed, {String label = 'manifest'}) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paCompressedManifest,
        label: label,
      ),
      children: [JumbfBrotliNode(compressed)],
    ).encode();

Uint8List get _validCompressedManifest => _hex(
  '21a400040000002a6a756d62000000226a756d6463326d6100110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List get _compressedUpdateManifest => _hex(
  '21a400040000002a6a756d62000000226a756d646332756d00110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List get _compressedWrongInnerType => _hex(
  '21a400040000002a6a756d62000000226a756d646332706100110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List get _compressedManifestWithTrailingByte => _hex(
  '21a800040000002a6a756d62000000226a756d6463326d6100110010800000aa'
  '00389b71036d616e6966657374000003',
);

Uint8List get _compressedBomb => _hex('81fa340cfc1241f1582090e51700');

Uint8List _hex(String value) => Uint8List.fromList(
  List<int>.generate(
    value.length ~/ 2,
    (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
    growable: false,
  ),
);

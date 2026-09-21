import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('C2paReader', () {
    test('reads standalone v1 and preserves raw and unknown data', () async {
      final claimMap = _v1Claim();
      claimMap['future_claim_field'] = {
        'nested': [1, 2],
      };
      claimMap['claim_generator_hints'] = {'user_agent': 'test'};
      claimMap['metadata'] = [
        {'dateTime': '2026-01-01T00:00:00Z'},
      ];
      final claimBytes = encodeCbor(claimMap);
      final tree = _store([
        _manifest(
          'urn:uuid:v1',
          claimBytes: claimBytes,
          unknownBoxes: [
            JumbfSuperBoxNode(
              description: JumbfDescription.fromUuidHex(
                contentType: JumbfUuid.json,
                label: 'vendor.box',
              ),
              children: [
                JumbfJsonNode(Uint8List.fromList([0x7b, 0x7d])),
              ],
            ),
          ],
        ),
      ]);

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(tree.encode()),
        mimeType: 'application/c2pa',
      );

      expect(reader.activeManifestLabel, 'urn:uuid:v1');
      expect(reader.manifests.keys, ['urn:uuid:v1']);
      expect(() => reader.manifests.clear(), throwsUnsupportedError);
      expect(() => reader.manifestBytes[0] = 0, throwsUnsupportedError);
      expect(reader.rawManifestEntries, hasLength(2));
      expect(reader.validationResults.state, ValidationState.invalid);
      expect(
        reader.validationResults.errors.map((issue) => issue.code),
        containsAll({
          ValidationCode.assertionHashedUriMismatch.value,
          ValidationCode.claimSignatureMismatch.value,
        }),
      );
      expect(reader.activeManifest!.unknownBoxes.single.label, 'vendor.box');

      final claim = reader.activeClaim as ClaimV1;
      expect(claim.claimGenerator, 'test/1.0');
      expect(claim.format, 'image/jpeg');
      expect(claim.instanceId, 'xmp:iid:v1');
      expect(claim.signatureUri, 'self#jumbf=c2pa.signature');
      expect(claim.assertions.single.algorithm, 'sha256');
      expect(claim.assertions.single.hash, [1, 2, 3]);
      expect(claim.rawBytes, claimBytes);
      expect(claim.unknownFields, contains('future_claim_field'));
      expect(claim.unknownFields, contains('claim_generator_hints'));
      expect(claim.unknownFields, contains('metadata'));
      expect(
        () =>
            (claim.unknownFields['future_claim_field']!
                    as Map<Object?, Object?>)['changed'] =
                true,
        throwsUnsupportedError,
      );
      expect(() => claim.rawBytes[0] = 0, throwsUnsupportedError);
    });

    test('reads v2 claim and selects the last manifest as active', () async {
      final old = _manifest(
        'urn:c2pa:old',
        claimBytes: encodeCbor(_v1Claim(instanceId: 'old')),
      );
      final currentMap = _v2Claim();
      currentMap['future'] = 'kept';
      final current = _manifest(
        'urn:c2pa:current',
        claimBytes: encodeCbor(currentMap),
      );

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_store([old, current]).encode()),
        fileName: 'asset.c2pa',
      );

      expect(reader.activeManifestLabel, 'urn:c2pa:current');
      expect(reader.manifests.keys, ['urn:c2pa:old', 'urn:c2pa:current']);
      final claim = reader.activeClaim as ClaimV2;
      expect(claim.generatorInfo.name, 'generator');
      expect(claim.generatorInfo.version, '2.0');
      expect(claim.createdAssertions, hasLength(1));
      expect(claim.gatheredAssertions, hasLength(1));
      expect(claim.assertions, hasLength(2));
      expect(claim.redactions, ['self#jumbf=c2pa.assertions/redacted']);
      expect(claim.algorithm, 'sha256');
      expect(claim.softAlgorithm, 'sha384');
      expect(claim.unknownFields['future'], 'kept');
    });

    test('extracts and reads a constructed JPEG', () async {
      final store = _store([
        _manifest('urn:c2pa:jpeg', claimBytes: encodeCbor(_v2Claim())),
      ]).encode();
      final jpeg = _jpegWithManifest(store);

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(jpeg),
        fileName: 'photo.JPG',
      );

      expect(reader.activeManifestLabel, 'urn:c2pa:jpeg');
      expect(reader.activeClaim, isA<ClaimV2>());
      expect(reader.manifestBytes, store);
    });

    test('emits structural failures for missing and multiple boxes', () async {
      final malformed = _manifest(
        'urn:c2pa:broken',
        claimBoxes: [
          _claimBox('c2pa.claim', encodeCbor(_v1Claim())),
          _claimBox('c2pa.claim.v2', encodeCbor(_v2Claim())),
        ],
        includeSignature: false,
        includeAssertionStore: false,
      );

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_store([malformed]).encode()),
      );
      final codes = reader.validationResults.errors
          .map((status) => status.code)
          .toSet();

      expect(codes, contains(ValidationCode.claimMultiple.value));
      expect(codes, contains(ValidationCode.claimSignatureMissing.value));
      expect(codes, contains(ValidationCode.assertionMissing.value));
      expect(reader.activeClaim, isNull);
      expect(reader.validationResults.state, ValidationState.invalid);
    });

    test(
      'reports missing claim and multiple signature and assertion stores',
      () async {
        final malformed = _manifest(
          'urn:c2pa:bad-layout',
          claimBoxes: const [],
          signatureBoxes: [
            _signatureBox('c2pa.signature'),
            _signatureBox('c2pa.signature__1'),
          ],
          assertionStoreBoxes: [
            _assertionStore('c2pa.assertions'),
            _assertionStore('c2pa.assertions__1'),
          ],
        );

        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(_store([malformed]).encode()),
        );
        final codes = reader.validationResults.errors
            .map((status) => status.code)
            .toSet();

        expect(codes, contains(ValidationCode.claimMissing.value));
        expect(codes, contains(ValidationCode.claimSignatureMismatch.value));
        expect(codes, contains(ValidationCode.generalError.value));
      },
    );

    test('reports malformed claims and assertion references', () async {
      final malformedClaim = _manifest(
        'urn:c2pa:malformed',
        claimBytes: Uint8List.fromList([0xff]),
      );
      final malformedReferenceMap = _v2Claim();
      malformedReferenceMap['created_assertions'] = [
        {
          'url': 'not-an-assertion',
          'hash': Uint8List.fromList([1]),
        },
        {
          'url': 'self#jumbf=c2pa.assertions/missing',
          'hash': Uint8List.fromList([2]),
        },
      ];
      final malformedReference = _manifest(
        'urn:c2pa:references',
        claimBytes: encodeCbor(malformedReferenceMap),
      );

      final first = await C2paReader.fromSource(
        source: MemoryByteSource(_store([malformedClaim]).encode()),
      );
      final second = await C2paReader.fromSource(
        source: MemoryByteSource(_store([malformedReference]).encode()),
      );

      expect(
        first.validationResults.errors.single.code,
        ValidationCode.claimMalformed.value,
      );
      expect(
        second.validationResults.errors.map((issue) => issue.code),
        containsAll({
          ValidationCode.assertionRequiredMissing.value,
          ValidationCode.assertionMissing.value,
        }),
      );
    });

    test('enforces manifest size, JUMBF depth, and box-count limits', () async {
      final bytes = _store([
        _manifest('urn:c2pa:limits', claimBytes: encodeCbor(_v1Claim())),
      ]).encode();

      await expectLater(
        C2paReader.fromSource(
          source: MemoryByteSource(bytes),
          context: C2paContext(
            settings: C2paSettings(maxManifestBytes: bytes.length - 1),
          ),
        ),
        throwsA(
          isA<C2paParseException>().having(
            (error) => error.stage,
            'stage',
            C2paParseStage.jumbf,
          ),
        ),
      );
      for (final settings in [
        const C2paSettings(maxRecursionDepth: 1),
        const C2paSettings(maxJumbfBoxCount: 3),
      ]) {
        await expectLater(
          C2paReader.fromSource(
            source: MemoryByteSource(bytes),
            context: C2paContext(settings: settings),
          ),
          throwsA(
            isA<C2paParseException>().having(
              (error) => error.stage,
              'stage',
              C2paParseStage.jumbf,
            ),
          ),
        );
      }
    });

    test('rejects a non-C2PA root with a typed parse error', () async {
      final root = JumbfSuperBoxNode(
        description: JumbfDescription.fromUuidHex(
          contentType: JumbfUuid.json,
          label: 'c2pa',
        ),
      );

      await expectLater(
        C2paReader.fromSource(source: MemoryByteSource(root.encode())),
        throwsA(
          isA<C2paParseException>()
              .having(
                (error) => error.stage,
                'stage',
                C2paParseStage.manifestStore,
              )
              .having(
                (error) => error.validationCode,
                'validationCode',
                ValidationCode.claimMissing,
              ),
        ),
      );
    });

    test('wraps missing embedded stores in a typed extraction error', () async {
      await expectLater(
        C2paReader.fromSource(
          source: MemoryByteSource(const [0xff, 0xd8, 0xff, 0xd9]),
          mimeType: 'image/jpeg',
        ),
        throwsA(
          isA<C2paParseException>()
              .having(
                (error) => error.stage,
                'stage',
                C2paParseStage.extraction,
              )
              .having(
                (error) => error.validationCode,
                'validationCode',
                ValidationCode.claimMissing,
              ),
        ),
      );
    });
  });
}

Map<String, Object?> _v1Claim({String instanceId = 'xmp:iid:v1'}) => {
  'claim_generator': 'test/1.0',
  'claim_generator_info': [
    {'name': 'generator', 'version': '1.0', 'vendor': true},
  ],
  'signature': 'self#jumbf=c2pa.signature',
  'assertions': [_reference('test.assertion', 1)],
  'dc:format': 'image/jpeg',
  'instanceID': instanceId,
  'dc:title': 'V1 asset',
  'alg': 'sha256',
};

Map<String, Object?> _v2Claim() => {
  'instanceID': 'xmp:iid:v2',
  'claim_generator_info': {
    'name': 'generator',
    'version': '2.0',
    'vendor': true,
  },
  'signature': 'self#jumbf=c2pa.signature',
  'created_assertions': [_reference('test.assertion', 1)],
  'gathered_assertions': [_reference('gathered.assertion', 2)],
  'dc:title': 'V2 asset',
  'redacted_assertions': ['self#jumbf=c2pa.assertions/redacted'],
  'alg': 'sha256',
  'alg_soft': 'sha384',
};

Map<String, Object?> _reference(String label, int hashByte) => {
  'url': 'self#jumbf=c2pa.assertions/$label',
  'alg': 'sha256',
  'hash': Uint8List.fromList([hashByte, hashByte + 1, hashByte + 2]),
};

JumbfSuperBoxNode _store(List<JumbfSuperBoxNode> manifests) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ),
      children: [
        JumbfUnknownNode(boxType: 'free', payload: Uint8List.fromList([0])),
        ...manifests,
      ],
    );

JumbfSuperBoxNode _manifest(
  String label, {
  Uint8List? claimBytes,
  List<JumbfSuperBoxNode>? claimBoxes,
  List<JumbfSuperBoxNode>? signatureBoxes,
  List<JumbfSuperBoxNode>? assertionStoreBoxes,
  bool includeSignature = true,
  bool includeAssertionStore = true,
  List<JumbfNode> unknownBoxes = const [],
}) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paManifest,
    label: label,
  ),
  children: [
    ...?claimBoxes,
    if (claimBoxes == null)
      _claimBox('c2pa.claim', claimBytes ?? encodeCbor(_v1Claim())),
    if (signatureBoxes case final boxes?)
      ...boxes
    else if (includeSignature)
      _signatureBox('c2pa.signature'),
    if (assertionStoreBoxes case final boxes?)
      ...boxes
    else if (includeAssertionStore)
      _assertionStore('c2pa.assertions'),
    ...unknownBoxes,
  ],
);

JumbfSuperBoxNode _claimBox(String label, Uint8List bytes) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paClaim,
    label: label,
  ),
  children: [JumbfCborNode(bytes)],
);

JumbfSuperBoxNode _signatureBox(String label) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paSignature,
    label: label,
  ),
  children: [
    JumbfCborNode(Uint8List.fromList([0x84])),
  ],
);

JumbfSuperBoxNode _assertionStore(String label) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paAssertionStore,
    label: label,
  ),
  children: [
    _assertionBox('test.assertion'),
    _assertionBox('gathered.assertion'),
  ],
);

JumbfSuperBoxNode _assertionBox(String label) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.cbor,
    label: label,
  ),
  children: [
    JumbfCborNode(encodeCbor({'value': label})),
  ],
);

Uint8List _jpegWithManifest(Uint8List manifest) {
  final payload = [0x4a, 0x50, 0x02, 0x11, 0, 0, 0, 1, ...manifest];
  final length = payload.length + 2;
  return Uint8List.fromList([
    0xff,
    0xd8,
    0xff,
    0xeb,
    length >> 8,
    length,
    ...payload,
    0xff,
    0xd9,
  ]);
}

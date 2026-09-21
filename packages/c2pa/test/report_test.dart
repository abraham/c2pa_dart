import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('reader reports', () {
    test('SDK JSON is stable, immutable, and preserves public data', () async {
      final reader = await _reader(v2: false);
      final report = reader.toSdkJson(
        options: const C2paJsonOptions(binaryOutput: C2paBinaryOutput.base64),
      );
      final manifest = _manifestFrom(report);

      expect(report['active_manifest'], 'urn:c2pa:test');
      expect(report['validation_state'], 'invalid');
      expect(manifest['claim_version'], 1);
      expect(manifest['claim_generator'], 'report-test/1.0');
      expect(manifest['title'], 'Report asset');
      expect(manifest['format'], 'image/jpeg');
      expect(manifest['instance_id'], 'xmp:iid:report');
      expect(
        manifest['assertions'],
        contains(containsPair('label', 'org.example.unknown')),
      );
      final resources = manifest['resources'] as Map<String, Object?>;
      expect(
        (resources['thumbnail'] as Map<String, Object?>)['data'],
        base64.encode([1, 2, 3, 4]),
      );
      expect(
        () => (report['manifests'] as Map<String, Object?>).clear(),
        throwsUnsupportedError,
      );

      final first = reader.encodeSdkJson();
      expect(first, reader.encodeSdkJson());
      expect(
        first.indexOf('"active_manifest"'),
        lessThan(first.indexOf('"manifests"')),
      );
      expect(
        reader.encodeSdkJson(options: const C2paJsonOptions(pretty: true)),
        contains('\n  "active_manifest"'),
      );
    });

    test(
      'detailed JSON preserves raw and unknown data with redaction',
      () async {
        final reader = await _reader(v2: false);
        final redacted = reader.toDetailedJson();
        final included = reader.toDetailedJson(
          options: const C2paJsonOptions(binaryOutput: C2paBinaryOutput.base64),
        );
        final redactedManifest = _manifestFrom(redacted);
        final includedManifest = _manifestFrom(included);

        expect(redacted['raw_manifest_store'], startsWith('<omitted> len = '));
        expect(included['raw_manifest_store'], isNot(startsWith('<omitted>')));
        expect((redactedManifest['claim'] as Map<String, Object?>)['future'], {
          'nested': [true, 7],
        });
        expect(
          redactedManifest['assertion_store'],
          containsPair('org.example.unknown', {
            'bytes': '<omitted> len = 3',
            'name': 'kept',
          }),
        );
        expect(redactedManifest['unknown_boxes'], isNotEmpty);
        expect(includedManifest['assertions'], everyElement(contains('raw')));
        expect(
          jsonDecode(reader.encodeDetailedJson()),
          isA<Map<String, Object?>>(),
        );
      },
    );

    test('crJSON emits claim-v1 schema shape and b64 hashes', () async {
      final reader = await _reader(v2: false);
      final report = reader.toCrJson();
      final manifest =
          (report['manifests'] as List<Object?>).single as Map<String, Object?>;
      final claim = manifest['claim'] as Map<String, Object?>;
      final signature = manifest['signature'] as Map<String, Object?>;
      final validation = manifest['validationResults'] as Map<String, Object?>;

      expect(report['@context'], contains('@vocab'));
      expect(report['jsonGenerator'], {
        'name': 'c2pa-dart',
        'version': '0.1.0-dev.1',
      });
      expect(manifest, isNot(contains('claim.v2')));
      expect(claim['claim_generator_info'], isA<List<Object?>>());
      expect(claim['dc:format'], 'image/jpeg');
      expect(claim['assertions'], hasLength(1));
      expect(
        ((claim['assertions'] as List<Object?>).single
            as Map<String, Object?>)['hash'],
        "b64'AQID'",
      );
      expect(
        ((manifest['assertions'] as Map<String, Object?>)['org.example.unknown']
            as Map<String, Object?>)['bytes'],
        '<omitted> len = 3',
      );
      expect(signature.keys, containsAll(['algorithm', 'certificateInfo']));
      expect(
        signature['certificateInfo'],
        containsPair('validity', isA<Map<String, Object?>>()),
      );
      expect(
        validation.keys,
        containsAll([
          'success',
          'informational',
          'failure',
          'specVersion',
          'validationTime',
        ]),
      );
      expect(validation['specVersion'], '2.3.0');
    });

    test('crJSON emits claim-v2 shape and active manifest first', () async {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          _store([
            _manifest('urn:c2pa:old', _claim(false)),
            _manifest('urn:c2pa:test', _claim(true)),
          ]).encode(),
        ),
      );

      final manifests = reader.toCrJson()['manifests'] as List<Object?>;
      final first = manifests.first as Map<String, Object?>;
      final second = manifests.last as Map<String, Object?>;
      final claim = first['claim.v2'] as Map<String, Object?>;

      expect(first['label'], 'urn:c2pa:test');
      expect(second['label'], 'urn:c2pa:old');
      expect(first, isNot(contains('claim')));
      expect(claim['claim_generator_info'], isA<Map<String, Object?>>());
      expect(claim['created_assertions'], hasLength(1));
      expect(claim['gathered_assertions'], hasLength(1));
      expect(claim, isNot(contains('dc:format')));
      expect(reader.encodeCrJson(), reader.encodeCrJson());
    });
  });
}

Map<String, Object?> _manifestFrom(Map<String, Object?> report) =>
    (report['manifests'] as Map<String, Object?>)['urn:c2pa:test']
        as Map<String, Object?>;

Future<C2paReader> _reader({required bool v2}) => C2paReader.fromSource(
  source: MemoryByteSource(
    _store([_manifest('urn:c2pa:test', _claim(v2))]).encode(),
  ),
);

Map<String, Object?> _claim(bool v2) {
  final common = <String, Object?>{
    'instanceID': 'xmp:iid:report',
    'signature': 'self#jumbf=c2pa.signature',
    'dc:title': 'Report asset',
    'alg': 'sha256',
    'future': {
      'nested': [true, 7],
    },
  };
  if (v2) {
    return {
      ...common,
      'claim_generator_info': {'name': 'report-test', 'version': '2.0'},
      'created_assertions': [_reference('org.example.unknown')],
      'gathered_assertions': [_reference('org.example.gathered')],
    };
  }
  return {
    ...common,
    'claim_generator': 'report-test/1.0',
    'claim_generator_info': [
      {'name': 'report-test', 'version': '1.0'},
    ],
    'assertions': [_reference('org.example.unknown')],
    'dc:format': 'image/jpeg',
  };
}

Map<String, Object?> _reference(String label) => {
  'url': 'self#jumbf=c2pa.assertions/$label',
  'alg': 'sha256',
  'hash': Uint8List.fromList([1, 2, 3]),
};

JumbfSuperBoxNode _store(List<JumbfSuperBoxNode> manifests) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifestStore,
        label: 'c2pa',
      ),
      children: manifests,
    );

JumbfSuperBoxNode _manifest(String label, Map<String, Object?> claim) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: label,
      ),
      children: [
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paClaim,
            label: claim.containsKey('assertions')
                ? 'c2pa.claim'
                : 'c2pa.claim.v2',
          ),
          children: [JumbfCborNode(encodeCbor(claim))],
        ),
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paSignature,
            label: 'c2pa.signature',
          ),
          children: [
            JumbfCborNode(Uint8List.fromList([0x84])),
          ],
        ),
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paAssertionStore,
            label: 'c2pa.assertions',
          ),
          children: [
            _assertion('org.example.unknown', {
              'name': 'kept',
              'bytes': Uint8List.fromList([9, 8, 7]),
            }),
            _assertion('org.example.gathered', {'value': true}),
          ],
        ),
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paDataBoxes,
            label: 'c2pa.databoxes',
          ),
          children: [
            _assertion('thumbnail', {
              'format': 'image/jpeg',
              'data': Uint8List.fromList([1, 2, 3, 4]),
            }),
          ],
        ),
      ],
    );

JumbfSuperBoxNode _assertion(String label, Map<String, Object?> data) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.cbor,
        label: label,
      ),
      children: [JumbfCborNode(encodeCbor(data))],
    );

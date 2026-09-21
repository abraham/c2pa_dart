import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('compressed manifest settings and capabilities', () {
    test('uses a bounded 32 MiB default', () {
      const settings = C2paSettings();
      expect(settings.maxDecompressedManifestBytes, 32 * 1024 * 1024);
      expect(C2paSettings.maximumDecompressedManifestBytes, 1024 * 1024 * 1024);
      expect(
        settings.copyWith(maxDecompressedManifestBytes: 1024).toJson(),
        containsPair('maxDecompressedManifestBytes', 1024),
      );
      expect(
        C2paSettings.fromJson(const {'maxDecompressedManifestBytes': 2048})
            .maxDecompressedManifestBytes,
        2048,
      );
      expect(
        () => C2paSettings(
          maxDecompressedManifestBytes:
              C2paSettings.maximumDecompressedManifestBytes + 1,
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('advertises read-only Brotli support', () {
      expect(C2paCapabilities.compressedManifests.canReadBrotli, isTrue);
      expect(C2paCapabilities.compressedManifests.canWriteBrotli, isFalse);
      expect(
        C2paCapabilities.compressedManifests.maximumDecompressedBytes,
        C2paSettings.maximumDecompressedManifestBytes,
      );
    });
  });

  group('compressed manifest Reader', () {
    test('reads a standalone compressed v2 manifest losslessly', () async {
      final outer = _compressedOuter(_compressedV2);
      final store = _store([outer]);
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(store),
        mimeType: 'application/c2pa',
      );

      final entry = reader.activeManifest!;
      expect(entry.label, 'urn:c2pa:compressed');
      expect(entry.compression, C2paManifestCompression.brotli);
      expect(entry.isCompressed, isTrue);
      expect(entry.bytes, outer);
      expect(entry.logicalBytes, isNot(outer));
      expect(entry.claim, isA<ClaimV2>());
      expect(entry.storedSize, outer.length);
      expect(entry.logicalSize, greaterThan(entry.storedSize));
      expect(
        reader.toDetailedJson()['manifests'],
        contains('urn:c2pa:compressed'),
      );
      final manifest =
          (reader.toDetailedJson()['manifests']! as Map)['urn:c2pa:compressed']
              as Map;
      expect(manifest['compression'], containsPair('state', 'brotli'));
    });

    test('reads compressed update manifests', () async {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          _store([_compressedOuter(_compressedUpdate, label: 'manifest')]),
        ),
      );
      expect(reader.activeManifest!.contentType, JumbfUuid.c2paUpdateManifest);
      expect(
        reader.activeManifest!.compression,
        C2paManifestCompression.brotli,
      );
    });

    test('reads compressed v1 manifests', () async {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          _store([
            _compressedOuter(_compressedV1, label: 'urn:uuid:compressed-v1'),
          ]),
        ),
      );
      expect(reader.activeManifest!.claim, isA<ClaimV1>());
      expect(reader.activeManifest!.isCompressed, isTrue);
    });

    test('reads compressed manifests embedded in JPEG', () async {
      final store = _store([_compressedOuter(_compressedV2)]);
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_jpegWithManifest(store)),
        fileName: 'image.jpg',
      );
      expect(reader.activeManifest!.claim, isA<ClaimV2>());
      expect(reader.activeManifest!.isCompressed, isTrue);
    });

    test('ingredient URI hashes use the preserved compressed form', () async {
      final compressed = _compressedOuter(_compressedV2);
      final digest = await HashAlgorithm.sha256.digest(
        Uint8List.sublistView(compressed, 8),
      );
      final builder = C2paBuilder(
        definition: ManifestDefinition(
          label: 'urn:c2pa:owner',
          intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
          generatorInfo: ClaimGeneratorInfo(name: 'compressed-owner'),
          format: 'application/c2pa',
          instanceId: 'xmp:iid:owner',
          ingredients: [
            BuilderIngredient(
              id: 'xmp:iid:compressed',
              assertion: IngredientAssertion(
                version: IngredientAssertionVersion.v2,
                relationship: Relationship.componentOf,
                title: 'Compressed ingredient',
                format: 'application/c2pa',
                instanceId: 'xmp:iid:compressed',
                c2paManifest: ClaimHashedUri(
                  url: 'self#jumbf=/c2pa/urn:c2pa:compressed',
                  algorithm: 'sha256',
                  hash: Uint8List.fromList(digest),
                ),
              ),
              manifestBoxes: [compressed],
            ),
          ],
        ),
        context: C2paContext(
          signer: CallbackC2paSigner(
            algorithm: 'ed25519',
            callback: (_) async => Uint8List(64),
          ),
        ),
        signingAlgorithm: 'ed25519',
        x5chain: [
          Uint8List.fromList([1]),
        ],
      );
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(await builder.build()),
      );
      expect(
        reader.manifests['urn:c2pa:compressed']!.compression,
        C2paManifestCompression.brotli,
      );
      expect(
        reader.validationResults.ingredientDeltas!
            .expand((delta) => delta.validationDeltas.all)
            .map((issue) => issue.code),
        contains(ValidationCode.ingredientManifestValidated.value),
      );
    });

    test('rejects DataHash in a compressed manifest', () async {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          _store([_compressedOuter(_compressedWithDataHash)]),
        ),
      );
      expect(
        reader.activeManifest!.structuralIssues.map((issue) => issue.code),
        contains(ValidationCode.manifestCompressedInvalid.value),
      );
    });

    test('rejects compressed manifests for BMFF multi-asset layouts', () async {
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(_mp4()),
        manifestSource: MemoryByteSource(
          _store([_compressedOuter(_compressedV2)]),
        ),
        mimeType: 'video/mp4',
        fileName: 'asset.mp4',
      );
      expect(
        reader.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.manifestCompressedInvalid.value),
      );
    });

    test(
      'maps malformed forms and limits to manifest.compressed.invalid',
      () async {
        final cases = <Uint8List>[
          _compressedOuter(Uint8List.fromList([0xff, 0xff, 0xff])),
          _compressedOuter(
            Uint8List.sublistView(_compressedV2, 0, _compressedV2.length - 1),
          ),
          _compressedOuter(_compressedWrongInner),
          _compressedOuter(_compressedTrailing),
          _compressedOuter(_compressedV2, label: 'wrong-label'),
          JumbfSuperBoxNode(
            description: JumbfDescription.fromUuidHex(
              contentType: JumbfUuid.c2paCompressedManifest,
              label: 'manifest',
            ),
          ).encode(),
        ];
        for (final outer in cases) {
          final reader = await C2paReader.fromSource(
            source: MemoryByteSource(_store([outer])),
          );
          expect(
            reader.activeManifest!.compression,
            C2paManifestCompression.invalid,
          );
          expect(
            reader.validationResults.errors.map((issue) => issue.code),
            contains(ValidationCode.manifestCompressedInvalid.value),
          );
        }

        final limited = await C2paReader.fromSource(
          source: MemoryByteSource(_store([_compressedOuter(_compressedV2)])),
          context: C2paContext(
            settings: const C2paSettings(maxDecompressedManifestBytes: 64),
          ),
        );
        expect(
          limited.validationResults.errors.map((issue) => issue.code),
          contains(ValidationCode.manifestCompressedInvalid.value),
        );
      },
    );
  });
}

Uint8List _store(List<Uint8List> manifests) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paManifestStore,
    label: 'c2pa',
  ),
  children: manifests.map(parseJumbf).toList(growable: false),
).encode();

Uint8List _compressedOuter(
  Uint8List compressed, {
  String label = 'urn:c2pa:compressed',
}) => JumbfSuperBoxNode(
  description: JumbfDescription.fromUuidHex(
    contentType: JumbfUuid.c2paCompressedManifest,
    label: label,
  ),
  children: [JumbfBrotliNode(compressed)],
).encode();

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

Uint8List _mp4() => Uint8List.fromList([
  ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
  ..._isoBox('free', const [1, 2, 3, 4]),
  ..._isoBox('mdat', const [5, 6, 7, 8]),
]);

List<int> _isoBox(String type, List<int> payload) {
  final length = payload.length + 8;
  return [
    length >> 24,
    length >> 16,
    length >> 8,
    length,
    ...type.codeUnits,
    ...payload,
  ];
}

Uint8List get _compressedV2 => base64.decode(
  'g8EBAICqqqrqnx38lKdwz1PkIQEiMw6ZEQBhDqAJEeDgAJ4QnpGQAJmQCZAAGZDg'
  'kJAAkWqqamZqYWqqrounBUAe3BMCEhIgISHh7ifPyNWOCQl5y2seMwHynpABuZ0SM'
  'iEPGf931b/n3uqeUV3exnBXvFhYWNjYWNXLjOrgw4cfg8FgHGeyqgaDwWAwGMyhzoh'
  'UlEbhsNBOsvcE3x/Q3M+DigGs5UFxRhRFG60JUKM7GzWDLXuMGNpjWhkrnBMcQON8w'
  'OQrDoM6d/olRgyNqHPCeqlLBwA80GmOtXUX5xl1WRTrSjiYnmOxtnNxDb676TNmKN'
  '/kGXXZAKKkSrgp3yLXB5moWBG44P8BvM5Lg5yx9XSCslzBLBoTAKjSAU9vpDx9mpy'
  'hF2WA749ZQb3gIy5T6WlxQwfLxPaeEVU/8970Oh02jqTxLNI27ZTirmOaC9fhYdCd'
  'g+L3jLg63NuixgcrgMYjgCQ/4yATVriLE1ZQqaKswnfXuM1ibZ8zWqSJyyhZ35BO'
  'piX1wYrqhBNFspwHFSf9rIPd/kouS+dpycTli7ZSpiclR+TRbRGT76DqEPcPkjlOW'
  'LBFtZrAhSaAdxIEz9A2En6+i+HSy8XTb388Xnp39dYbf+XCwsLw2J3tVwtfeOPjw2'
  '9f9a/dg2Tek9FSXDQmyaTvd/Dpw73ptd8nvxd//m7ysHr86F996f3ui5/D1cO6Onz'
  'iWUGl2klFKSz12u7IMtFzXlIlNCPkcb7mhfMAHqAj+VmX1ojZoPplALjJYm0/72/N'
  'G2fmi6cGjaPhJjYfNw==',
);

Uint8List get _compressedV1 => base64.decode(
  'A+0AAICqqqrqXzzsFDezY5wjDuGHMHdXAHewMIAACICIS1xOAaKLmanCZqai6uBHC'
  '4C43OwUEABxsNM9Dqc4neL/rvr33FvdM6rL2xjuihcLCwsbG6t6mVEdfPjwYzAYjO'
  'NMVtVgMBgMBoM51BmRitIoHBbaSfae4PsF2PyZ7DgA7E12UjCHUEE5A6zQLFORo29'
  'z1rIVwY1RESn5cD4AAPybsOh3DkNYd/pDEmzEWljUDgDgV/AQfwTavqMB2fGkpWi7'
  'EB0mox32amdG1WvSvceUo7rckLLdrcmOd0/Rgd2+b5BIxaSDp4/vWI9TkaO9bCnoe'
  'ROg7pKidO3w/coBaXjZXBVGe0rohXp7NRc3tlrL9nwIwqJ2773yKmIKcUiK0u5Q7w'
  'Hg0RQe/d4lJ3fRcvwJAMC14CF+AsAE7eRbh46BLzsWcKwAAM+Bkt87yDxEd+qpUKef'
  'AwCUgof4pc5os9oM',
);

Uint8List get _compressedWithDataHash => base64.decode(
  'g/cBAICqqqrqnx3slKdwz1PmIQE8Mw6LA4Q5gCVEgINDBkB4RkICZEImQAJkQIJD'
  'QgJEqqmqmamFqamZLp4WAHkwT0hISICEhIS7nzwiVzsmJOQtr3nMBMh7QgbkdkrYD'
  'hn/d9W/597qnlFd3sZwV7xYWFjY2FjVy4zq4MOHH4PBYBxnsqoGg8FgMBjMoc6IV'
  'JRG4bDQTrL3BN8f4P1NnQwBrKZOMhpIgg7aNdBgMCs9p/MhDQoypEoWmhvDGYBWE'
  'zD5isMgxp1+iQYF8YkxXFuhcgMALNBpDpV2F+cJMYkfqoo7mJ6lodJzfg2+u+lTWh'
  'C2yRJikhF4TiQ3U7YVXBslvKKZY5z9B/AqLQ1yxtbTCUJzBTN/EgBAlQ54fCPl6X5'
  '0hp6VAb4/qjmxnJVMxMKS7LpymvLtvYJXG4m1xbDfpxNfFJb6Ssf9nN8xVDFu+iw'
  'MunFQ7F7Brw73tkhhneYAMoAkX3av/4QRSwDgHA2V3gcB5HEXm9d7Cha4Y4TKTQ2'
  '0HqWXfMlBDmjmLk5oRoT0wQLfXesWDZV+RkkWRyYhwdq6MCLOiXWaVycNz6LF1Mk'
  'w2gAT2O2vpCI3luSUX7qgK1kMhWBEc3QNzuQ7ZHGIewfJHCfU6azqJXChCeD9BME'
  'TEhkFGN/84sSZN98fd99eufnaXj6/sDA+dnv75cJn1vrw8OsX9XM3mXdlEijGnwT'
  'JpO939PH93enVX6e+Zb//bDLXO370r7n4bvf5j3HvsKkOn1iaESF3Yp5zTazSOyK'
  'P1JzlRHJFmWacr1puLIAH6Ei+7NIa4xhUvwoAN2io9Kf7W/PW0vzE6VHraLyJ/9f'
  'v2ww=',
);

Uint8List get _compressedUpdate => _hex(
  '21a400040000002a6a756d62000000226a756d646332756d00110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List get _compressedWrongInner => _hex(
  '21a400040000002a6a756d62000000226a756d646332706100110010800000aa'
  '00389b71036d616e69666573740003',
);

Uint8List get _compressedTrailing => _hex(
  '21a800040000002a6a756d62000000226a756d6463326d6100110010800000aa'
  '00389b71036d616e6966657374000003',
);

Uint8List _hex(String value) => Uint8List.fromList(
  List<int>.generate(
    value.length ~/ 2,
    (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16),
    growable: false,
  ),
);

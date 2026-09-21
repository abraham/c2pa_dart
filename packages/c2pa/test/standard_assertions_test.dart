import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('standard assertion models', () {
    test('metadata JSON and assertion metadata preserve unknown fields', () {
      final metadata = C2paMetadataAssertion.fromJson({
        '@context': {'dc': 'http://purl.org/dc/elements/1.1/'},
        'dc:title': 'A title',
        'dc:identifier': 'asset-1',
      });
      expect(
        C2paMetadataAssertion.fromJson(
          jsonDecode(jsonEncode(metadata.toAssertionData()))
              as Map<String, Object?>,
        ),
        metadata,
      );
      expect(
        () => C2paMetadataAssertion.fromJson({
          '@context': {'dc': 'http://purl.org/dc/elements/1.1/'},
          'notAllowed': true,
        }),
        throwsFormatException,
      );
      expect(
        () => C2paMetadataAssertion.fromJson({
          '@context': {'dc': 'http://purl.org/dc/elements/1.1/'},
          'dc:title': 'A title',
        }, version: 2),
        throwsFormatException,
      );

      final assertionMetadata = C2paAssertionMetadata.fromCbor({
        'dateTime': '2026-09-20T00:00:00Z',
        'reviewRatings': [
          {'explanation': 'Reviewed', 'value': 4, 'vendor': true},
        ],
        'dataSource': {'type': 'humanEntry.identified', 'detail': 7},
        'regionOfInterest': {
          'region': [
            {
              'type': 'spatial',
              'shape': {
                'type': 'rectangle',
                'unit': 'pixel',
                'origin': {'x': 1, 'y': 2},
                'width': 20,
                'height': 10,
                'future': 'kept',
              },
            },
          ],
          'identifier': 'subject-1',
          'future': true,
        },
        'custom': {'nested': true},
      });
      final roundTrip = C2paAssertionMetadata.fromCbor(
        decodeCbor(encodeCbor(assertionMetadata.toAssertionData())),
      );
      expect(roundTrip, assertionMetadata);
      expect(roundTrip.unknownFields['custom'], {'nested': true});
      expect(roundTrip.regionOfInterest!.unknownFields['future'], isTrue);
      expect(
        roundTrip
            .regionOfInterest!
            .regions
            .single
            .shape!
            .unknownFields['future'],
        'kept',
      );
    });

    test('soft binding and ROI enforce strict discriminated shapes', () {
      final binding = C2paSoftBindingAssertion(
        algorithm: 'com.example.phash',
        algorithmParameters: 'v=1',
        blocks: [
          C2paSoftBindingBlock(
            scope: C2paSoftBindingScope(
              timespan: const C2paSoftBindingTimespan(start: 0, end: 500),
            ),
            value: 'dmFsdWU=',
            unknownFields: const {'future': 1},
          ),
        ],
        pad: const [0, 0],
        unknownFields: const {'extension': 'kept'},
      );
      final encoded = encodeCbor(binding.toAssertionData());
      expect(encoded, encodeCbor(binding.toAssertionData()));
      expect(C2paSoftBindingAssertion.fromCbor(decodeCbor(encoded)), binding);
      expect(
        () => C2paRegionRange(
          type: C2paRegionRangeType.temporal,
          frame: const {'start': 0},
        ),
        throwsFormatException,
      );
      expect(
        () => C2paRegionShape(
          type: C2paShapeType.polygon,
          unit: C2paUnitType.percent,
          origin: const C2paCoordinate(x: 0, y: 0),
          vertices: const [C2paCoordinate(x: 0, y: 0)],
        ),
        throwsFormatException,
      );
    });

    test('asset, timestamp, certificate, and legacy models round-trip', () {
      final references = C2paAssetReferenceAssertion.fromCbor({
        'references': [
          {
            'reference': {'uri': 'https://example.test/asset'},
            'description': 'Primary copy',
            'future': 1,
          },
          {
            'reference': {'uri': 'ipfs://example'},
          },
        ],
        'future': true,
      });
      expect(
        C2paAssetReferenceAssertion.fromCbor(
          decodeCbor(encodeCbor(references.toAssertionData())),
        ),
        references,
      );

      final types = C2paAssetTypesAssertion.fromCbor({
        'types': [
          {'type': 'c2pa.types.model', 'version': '1', 'future': true},
        ],
        'future': 2,
      });
      expect(
        C2paAssetTypesAssertion.fromCbor(
          decodeCbor(encodeCbor(types.toAssertionData())),
        ),
        types,
      );
      expect(
        () => C2paAssetTypesAssertion.fromCbor({
          'types': [
            {'type': 'c2pa.types.model'},
          ],
        }, version: 2),
        throwsFormatException,
      );

      final timestamp = C2paTimestampAssertion({
        'urn:c2pa:manifest': Uint8List.fromList([1, 2, 3]),
      });
      expect(
        C2paTimestampAssertion.fromCbor(
          decodeCbor(encodeCbor(timestamp.toAssertionData())),
        ),
        timestamp,
      );
      expect(() => timestamp.timestamps.clear(), throwsUnsupportedError);

      final status = C2paCertificateStatusAssertion.fromJson({
        'ocspVals': ['AQID'],
        'future': true,
      });
      expect(status.toJson()['ocspVals'], ['AQID']);
      expect(
        C2paCertificateStatusAssertion.fromCbor(
          decodeCbor(encodeCbor(status.toAssertionData())),
        ),
        status,
      );

      for (final legacy in [
        C2paLegacyJsonAssertion(
          kind: C2paLegacyAssertionKind.exif,
          value: const {'exif:ExposureTime': '1/100', 'future': true},
        ),
        C2paLegacyJsonAssertion(
          kind: C2paLegacyAssertionKind.creativeWork,
          value: const {
            '@context': 'https://schema.org',
            '@type': 'CreativeWork',
            'author': 'Example',
          },
        ),
        C2paLegacyJsonAssertion(
          kind: C2paLegacyAssertionKind.schemaOrg,
          label: 'stds.schema-org.ClaimReview',
          value: const {'@type': 'ClaimReview', 'claimReviewed': 'Example'},
        ),
      ]) {
        expect(
          C2paLegacyJsonAssertion.fromJson(
            label: legacy.label,
            value: legacy.toAssertionData(),
          ),
          legacy,
        );
      }
    });

    test('embedded data and thumbnail own their bytes', () {
      final source = Uint8List.fromList([1, 2, 3]);
      final embedded = C2paEmbeddedData(
        label: 'c2pa.embedded-data.example',
        contentType: 'application/octet-stream',
        bytes: source,
      );
      final thumbnail = C2paThumbnail(
        kind: C2paThumbnailKind.claim,
        mediaType: 'image/png',
        bytes: source,
      );
      source[0] = 9;
      expect(embedded.bytes, [1, 2, 3]);
      expect(thumbnail.label, 'c2pa.thumbnail.claim.png');
      expect(() => embedded.bytes[0] = 0, throwsUnsupportedError);
    });
  });

  group('standard assertion Reader and Builder integration', () {
    test(
      'typed APIs build and read all supported assertion families',
      () async {
        final metadata = C2paMetadataAssertion(
          context: const {'dc': 'http://purl.org/dc/elements/1.1/'},
          values: const {'dc:title': 'Metadata title'},
        );
        final builder = _builder()
            .withMetadata(metadata)
            .withMetadata(metadata)
            .withAssertionMetadata(
              C2paAssertionMetadata(
                reference: ClaimHashedUri(
                  url: 'self#jumbf=c2pa.assertions/missing',
                  hash: Uint8List(32),
                  algorithm: 'sha256',
                ),
              ),
            )
            .withSoftBinding(
              C2paSoftBindingAssertion(
                algorithm: 'com.example.phash',
                blocks: [
                  C2paSoftBindingBlock(
                    scope: C2paSoftBindingScope(
                      region: C2paRegionOfInterest(
                        regions: [
                          C2paRegionRange(
                            type: C2paRegionRangeType.frame,
                            frame: const {'start': 0, 'end': 1},
                          ),
                        ],
                      ),
                    ),
                    value: 'value',
                  ),
                ],
              ),
            )
            .withEmbeddedData(
              C2paEmbeddedData(
                label: 'c2pa.embedded-data.preview',
                contentType: 'application/octet-stream',
                bytes: const [1, 2],
              ),
            )
            .withThumbnail(
              C2paThumbnail(
                kind: C2paThumbnailKind.claim,
                mediaType: 'image/png',
                bytes: const [3, 4],
              ),
            )
            .withAssetReferences(
              C2paAssetReferenceAssertion(
                references: [
                  C2paAssetReferenceEntry(uri: 'https://example.test/asset'),
                ],
              ),
            )
            .withAssetTypes(
              C2paAssetTypesAssertion(
                types: [C2paAssetType(type: 'c2pa.types.dataset')],
              ),
            )
            .withTimestampAssertion(
              C2paTimestampAssertion({
                'urn:c2pa:other': Uint8List.fromList([5]),
              }),
            )
            .withCertificateStatus(
              C2paCertificateStatusAssertion(
                ocspValues: [
                  Uint8List.fromList([6]),
                ],
              ),
            )
            .withLegacyAssertion(
              C2paLegacyJsonAssertion(
                kind: C2paLegacyAssertionKind.creativeWork,
                value: const {'@type': 'CreativeWork', 'future': true},
              ),
            )
            .withResource(
              ManifestResource(
                label: 'resource',
                format: 'application/octet-stream',
                bytes: Uint8List.fromList([7, 8]),
              ),
            );

        expect(
          builder.definition.assertions.where(
            (item) => item.label.startsWith('c2pa.metadata.v1'),
          ),
          hasLength(2),
        );
        expect(
          builder.definition.assertions.map((item) => item.label),
          contains('c2pa.metadata.v1__2'),
        );

        final manifestBytes = await builder.build();
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(manifestBytes),
        );
        final entry = reader.activeManifest!;

        expect(entry.metadataAssertions, hasLength(2));
        expect(entry.assertionMetadata, hasLength(1));
        expect(entry.softBindings, hasLength(1));
        expect(entry.embeddedData, hasLength(2));
        expect(entry.thumbnails.single.bytes, [3, 4]);
        expect(entry.assetReferences, hasLength(1));
        expect(entry.assetTypes, hasLength(1));
        expect(entry.timestamps, hasLength(1));
        expect(entry.certificateStatuses, hasLength(1));
        expect(entry.legacyAssertions, hasLength(1));
        expect(
          reader.validationResults.issues.map((issue) => issue.code),
          contains(ValidationCode.hashedUriMismatch.value),
        );
        expect(reader.toSdkJson()['manifests'], contains('urn:c2pa:standard'));
      },
    );

    test(
      'reads unversioned v1 metadata and requires a soft-binding alg',
      () async {
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(
            await _builder(
              assertions: [
                AssertionDefinition.json(
                  label: C2paMetadataAssertion.baseLabel,
                  data: {
                    '@context': {'dc': 'http://purl.org/dc/elements/1.1/'},
                    'dc:title': 'Legacy label',
                  },
                ),
              ],
            ).build(),
          ),
        );
        expect(reader.activeManifest!.metadataAssertions.single.version, 1);

        final missingAlgorithm = _builder().withSoftBinding(
          C2paSoftBindingAssertion(
            blocks: [
              C2paSoftBindingBlock(
                scope: C2paSoftBindingScope(
                  timespan: const C2paSoftBindingTimespan(start: 0, end: 1),
                ),
                value: 'value',
              ),
            ],
          ),
        );
        await expectLater(
          missingAlgorithm.build(),
          throwsA(isA<C2paValidationException>()),
        );
      },
    );

    test(
      'malformed standard assertions emit typed validation statuses',
      () async {
        final builder = _builder(
          assertions: [
            AssertionDefinition.json(
              label: 'c2pa.metadata.v1',
              data: {'disallowed': true},
            ),
            AssertionDefinition.cbor(
              label: 'c2pa.time-stamp',
              data: {'manifest': 'not-bytes'},
            ),
            AssertionDefinition.json(
              label: 'stds.schema-org.CreativeWork',
              data: {'@type': 'NotCreativeWork'},
            ),
            AssertionDefinition.cbor(
              label: 'c2pa.asset-type.v2',
              data: {
                'types': [
                  {'type': 'c2pa.types.model'},
                ],
              },
            ),
          ],
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(await builder.build()),
        );
        final codes = reader.validationResults.issues
            .map((issue) => issue.code)
            .toSet();
        expect(
          codes,
          contains(ValidationCode.assertionMetadataDisallowed.value),
        );
        expect(
          codes,
          contains(ValidationCode.assertionTimestampMalformed.value),
        );
        expect(codes, contains(ValidationCode.assertionJsonInvalid.value));
        expect(codes, contains(ValidationCode.assertionCborInvalid.value));
        expect(reader.activeManifest!.metadataAssertions, isEmpty);
        expect(reader.activeManifest!.timestamps, isEmpty);
        expect(reader.activeManifest!.legacyAssertions, isEmpty);
      },
    );
  });
}

C2paBuilder _builder({Iterable<AssertionDefinition> assertions = const []}) =>
    C2paBuilder(
      definition: ManifestDefinition(
        label: 'urn:c2pa:standard',
        intent: const CreateIntent(DigitalSourceType.digitalCapture),
        generatorInfo: ClaimGeneratorInfo(name: 'test', version: '1'),
        format: 'application/c2pa',
        instanceId: 'xmp:iid:standard',
        assertions: assertions,
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

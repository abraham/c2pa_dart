import 'dart:convert';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:c2pa_formats/c2pa_formats.dart';
import 'package:test/test.dart';

import 'x509_test_support.dart';

late TestCertificateChain _certificates;

void main() {
  setUpAll(() async {
    _certificates = await loadTestCertificateChain();
  });

  group('C2paBuilder', () {
    test(
      'produces deterministic v2 output and round-trips through Reader',
      () async {
        final signer = _DigestSigner();
        final verifier = _DigestVerifier(_certificates.leafSpki);
        final definition = _definition(
          assertions: [
            AssertionDefinition.json(
              label: 'org.example.json',
              data: {
                'z': 1,
                'a': [true, null],
              },
            ),
            AssertionDefinition.cbor(
              label: 'org.example.cbor',
              data: {
                'z': 2,
                'a': Uint8List.fromList([1, 2, 3]),
              },
            ),
          ],
          resources: [
            ManifestResource(
              label: 'org.example.resource',
              format: 'application/octet-stream',
              bytes: Uint8List.fromList([9, 8, 7]),
              name: 'example.bin',
              dataTypes: const ['com.example.binary'],
              extra: const {'vendor': 'example'},
            ),
          ],
        );
        final builder = _builder(definition, signer: signer);

        final first = await builder.build();
        final second = await builder.build();
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(first),
          context: C2paContext(verifier: verifier, trust: _trust()),
        );

        expect(first, second);
        expect(reader.activeManifestLabel, definition.label);
        expect(reader.activeClaim, isA<ClaimV2>());
        expect(reader.activeClaim!.instanceId, definition.instanceId);
        expect(reader.activeClaim!.title, definition.title);
        expect(reader.activeClaim!.assertions, hasLength(4));
        expect(
          reader.activeManifest!.assertions.map((assertion) => assertion.label),
          [
            'c2pa.hash.boxes',
            'c2pa.actions.v2',
            'org.example.json',
            'org.example.cbor',
          ],
        );
        expect(
          reader.activeManifest!.unknownBoxes.map((box) => box.label),
          contains('c2pa.databoxes'),
        );
        expect(reader.activeManifest!.resources, hasLength(1));
        final resource = await reader.lookupResource('org.example.resource');
        expect(resource.bytes, [9, 8, 7]);
        expect(resource.mimeType, 'application/octet-stream');
        expect(resource.name, 'example.bin');
        expect(resource.dataTypes, ['com.example.binary']);
        expect(resource.unknownFields['vendor'], 'example');
        expect(
          resource.uri,
          'self#jumbf=/c2pa/${Uri.encodeComponent(definition.label)}/'
          'c2pa.databoxes/org.example.resource',
        );
        expect(await reader.lookupResource(resource.uri), resource);
        expect(() => resource.bytes[0] = 0, throwsUnsupportedError);
        await expectLater(
          reader.lookupResource('missing'),
          throwsA(isA<C2paResourceNotFoundException>()),
        );
        await expectLater(
          C2paReader.fromSource(
            source: MemoryByteSource(first),
            context: C2paContext(
              settings: const C2paSettings(maxResourceBytes: 2),
            ),
          ),
          throwsA(isA<C2paResourceLimitException>()),
        );
        expect(reader.validationResults.errors, isEmpty);
        expect(
          reader.validationResults.activeManifest!.success.map(
            (issue) => issue.code,
          ),
          containsAll({
            ValidationCode.assertionHashedUriMatch.value,
            ValidationCode.assertionBoxesHashMatch.value,
            ValidationCode.claimSignatureValidated.value,
          }),
        );
        expect(reader.validationResults.state, ValidationState.trusted);
        expect(signer.calls, 2);
        expect(verifier.calls, 1);
      },
    );

    test('canonical JSON makes map insertion order deterministic', () async {
      final first = _builder(
        _definition(
          assertions: [
            AssertionDefinition.json(
              label: 'org.example.order',
              data: {'b': 2, 'a': 1},
            ),
          ],
        ),
      );
      final second = _builder(
        _definition(
          assertions: [
            AssertionDefinition.json(
              label: 'org.example.order',
              data: {'a': 1, 'b': 2},
            ),
          ],
        ),
      );

      expect(await first.build(), await second.build());
    });

    test('Reader detects assertion tampering in builder output', () async {
      final builder = _builder(
        _definition(
          assertions: [
            AssertionDefinition.cbor(
              label: 'org.example.tamper',
              data: {'value': 1},
            ),
          ],
        ),
      );
      final bytes = await builder.build();
      final assertionPayload = encodeCbor({'value': 1});
      final offset = _indexOf(bytes, assertionPayload);
      expect(offset, greaterThanOrEqualTo(0));
      final tampered = Uint8List.fromList(bytes);
      tampered[offset + assertionPayload.length - 1] ^= 1;

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(tampered),
        context: C2paContext(
          verifier: _DigestVerifier(_certificates.leafSpki),
          trust: _trust(),
        ),
      );

      expect(
        reader.validationResults.errors.map((issue) => issue.code),
        contains(ValidationCode.assertionHashedUriMismatch.value),
      );
    });

    test(
      'writes trusted BoxHash-bound standalone, JPEG, PNG, GIF, and JXL',
      () async {
        final builder = _builder(_definition());
        final standalone = MemoryByteSink();
        final jpeg = MemoryByteSink();
        final png = MemoryByteSink();
        final gif = MemoryByteSink();
        final jxl = MemoryByteSink();

        await builder.saveToSource(output: standalone);
        await builder.saveToSource(
          source: MemoryByteSource(_jpeg()),
          output: jpeg,
          mimeType: 'image/jpeg',
        );
        await builder.saveToSource(
          source: MemoryByteSource(_png()),
          output: png,
          fileName: 'asset.png',
        );
        await builder.saveToSource(
          source: MemoryByteSource(_gif()),
          output: gif,
          mimeType: 'image/gif',
        );
        await builder.saveToSource(
          source: MemoryByteSource(_jxl()),
          output: jxl,
          mimeType: 'image/jxl',
        );

        for (final output in [standalone, jpeg, png, gif, jxl]) {
          final reader = await C2paReader.fromSource(
            source: MemoryByteSource(output.toBytes()),
            context: C2paContext(
              verifier: _DigestVerifier(_certificates.leafSpki),
              trust: _trust(),
            ),
            mimeType: identical(output, jpeg)
                ? 'image/jpeg'
                : identical(output, png)
                ? 'image/png'
                : identical(output, gif)
                ? 'image/gif'
                : identical(output, jxl)
                ? 'image/jxl'
                : 'application/c2pa',
          );
          expect(reader.activeManifestLabel, 'urn:c2pa:builder-test');
          expect(
            _codes(reader),
            contains(ValidationCode.assertionBoxesHashMatch.value),
            reason: identical(output, standalone)
                ? 'standalone'
                : identical(output, jpeg)
                ? 'JPEG'
                : identical(output, png)
                ? 'PNG'
                : identical(output, gif)
                ? 'GIF'
                : identical(output, jxl)
                ? 'JXL'
                : 'GIF',
          );
          expect(reader.validationResults.state, ValidationState.trusted);
        }
      },
    );

    test('detects tampered media through BoxHash', () async {
      final output = MemoryByteSink();
      await _builder(_definition()).saveToSource(
        source: MemoryByteSource(_jpeg()),
        output: output,
        mimeType: 'image/jpeg',
      );
      final tampered = output.toBytes();
      tampered[tampered.length - 6] ^= 1;

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(tampered),
        mimeType: 'image/jpeg',
        context: C2paContext(
          verifier: _DigestVerifier(_certificates.leafSpki),
          trust: _trust(),
        ),
      );

      expect(
        _codes(reader),
        contains(ValidationCode.assertionBoxesHashMismatch.value),
      );
    });

    test('supports SHA-256, SHA-384, and SHA-512 BoxHash entries', () async {
      for (final algorithm in ['sha256', 'sha384', 'sha512']) {
        final output = MemoryByteSink();
        await _builder(
          ManifestDefinition(
            label: 'urn:c2pa:boxhash-$algorithm',
            intent: const BuilderIntent.create(
              DigitalSourceType.digitalCapture,
            ),
            generatorInfo: ClaimGeneratorInfo(
              name: 'builder-test',
              version: '1.0',
            ),
            format: 'image/jpeg',
            instanceId: 'xmp:iid:$algorithm',
            hashAlgorithm: algorithm,
          ),
        ).saveToSource(
          source: MemoryByteSource(_jpeg()),
          output: output,
          mimeType: 'image/jpeg',
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(output.toBytes()),
          mimeType: 'image/jpeg',
          context: C2paContext(
            verifier: _DigestVerifier(_certificates.leafSpki),
            trust: _trust(),
          ),
        );

        expect(
          _codes(reader),
          contains(ValidationCode.assertionBoxesHashMatch.value),
          reason: algorithm,
        );
      }
    });

    test('maps BoxHash order, digest, and schema failures', () async {
      final output = MemoryByteSink();
      await _builder(_definition()).saveToSource(
        source: MemoryByteSource(_jpeg()),
        output: output,
        mimeType: 'image/jpeg',
      );
      final embedded = output.toBytes();

      final reordered = await _rewriteEmbeddedBoxHash(embedded, (boxes) {
        final copy = List<Object?>.from(boxes);
        final first = copy.removeAt(0);
        copy.insert(1, first);
        return copy;
      });
      final changedHash = await _rewriteEmbeddedBoxHash(embedded, (boxes) {
        final copy = List<Object?>.from(boxes);
        final entry = Map<Object?, Object?>.from(copy.first as Map);
        final hash = Uint8List.fromList(entry['hash'] as Uint8List);
        hash[0] ^= 1;
        entry['hash'] = hash;
        copy[0] = entry;
        return copy;
      });
      final malformed = await _rewriteEmbeddedBoxHash(embedded, (boxes) {
        final copy = List<Object?>.from(boxes);
        final index = copy.indexWhere(
          (entry) => ((entry as Map)['names'] as List).contains('C2PA'),
        );
        final c2pa = Map<Object?, Object?>.from(copy[index] as Map);
        c2pa['pad'] = Uint8List.fromList([1]);
        copy[index] = c2pa;
        return copy;
      });

      for (final bytes in [reordered, changedHash]) {
        final reader = await _readJpeg(bytes);
        expect(
          _codes(reader),
          contains(ValidationCode.assertionBoxesHashMismatch.value),
        );
      }
      expect(
        _codes(await _readJpeg(malformed)),
        contains(ValidationCode.assertionBoxesHashMalformed.value),
      );
    });

    test('enforces missing, multiple, and update hard-binding rules', () async {
      final manifest = await _builder(_definition()).build();
      final missing = _rewriteHardBindingStructure(manifest, remove: true);
      final multiple = _rewriteHardBindingStructure(manifest, duplicate: true);
      final update = _rewriteHardBindingStructure(
        manifest,
        updateManifest: true,
      );

      expect(
        _codes(await _readStandalone(missing)),
        contains(ValidationCode.hardBindingsMissing.value),
      );
      expect(
        _codes(await _readStandalone(multiple)),
        contains(ValidationCode.hardBindingsMultiple.value),
      );
      expect(
        _codes(await _readStandalone(update)),
        contains(ValidationCode.manifestUpdateInvalid.value),
      );
    });

    test(
      'validates intents, duplicate labels, and hard-binding requests',
      () async {
        await expectLater(
          _builder(
            _definition(
              intent: const BuilderIntent.create(
                DigitalSourceType.digitalCapture,
              ),
              redactions: const [
                'self#jumbf=/c2pa/parent/c2pa.assertions/example',
              ],
            ),
          ).build(),
          throwsA(isA<C2paValidationException>()),
        );
        await expectLater(
          _builder(_definition(intent: const BuilderIntent.edit())).build(),
          throwsA(isA<C2paValidationException>()),
        );
        await expectLater(
          _builder(
            _definition(
              intent: const BuilderIntent.update(),
              assertions: [
                AssertionDefinition.cbor(label: 'org.example.update', data: 1),
              ],
            ),
          ).build(),
          throwsA(isA<C2paValidationException>()),
        );
        await expectLater(
          _builder(
            _definition(
              assertions: [
                AssertionDefinition.cbor(label: 'org.example.same', data: 1),
                AssertionDefinition.cbor(label: 'org.example.same', data: 2),
              ],
            ),
          ).build(),
          throwsA(isA<C2paValidationException>()),
        );
        await expectLater(
          _builder(
            _definition(
              assertions: [
                AssertionDefinition.cbor(
                  label: 'c2pa.hash.data',
                  data: {'hash': Uint8List(32)},
                ),
              ],
            ),
          ).build(),
          throwsA(isA<C2paValidationException>()),
        );
        await expectLater(
          _builder(
            _definition(
              resources: [
                ManifestResource(
                  label: 'same',
                  format: 'text/plain',
                  bytes: Uint8List.fromList([1]),
                ),
                ManifestResource(
                  label: 'same',
                  format: 'text/plain',
                  bytes: Uint8List.fromList([2]),
                ),
              ],
            ),
          ).build(),
          throwsA(isA<C2paValidationException>()),
        );
        expect(
          await _builder(_definition()).build(requireValidClaim: true),
          isNotEmpty,
        );
      },
    );

    test('requires matching algorithms and wraps signer failures', () async {
      await expectLater(
        C2paBuilder(
          definition: _definition(),
          context: C2paContext(signer: _DigestSigner()),
          signingAlgorithm: 'es256',
          x5chain: [_certificates.leaf, _certificates.intermediate],
        ).build(),
        throwsA(isA<C2paSigningException>()),
      );
      await expectLater(
        _builder(_definition(), signer: _FailingSigner()).build(),
        throwsA(
          isA<C2paSigningException>().having(
            (error) => error.cause,
            'cause',
            isA<StateError>(),
          ),
        ),
      );
      await expectLater(
        C2paBuilder(
          definition: _definition(),
          context: C2paContext(signer: _DigestSigner()),
          signingAlgorithm: 'ed25519',
          x5chain: const [],
        ).build(),
        throwsA(isA<C2paSigningException>()),
      );
    });

    test('embeds and validates a DataHash-bound RIFF asset', () async {
      final output = MemoryByteSink();
      await _builder(
        _definition(),
        signer: _ReservedDigestSigner(),
      ).saveToSource(
        source: MemoryByteSource(_webp()),
        output: output,
        mimeType: 'image/webp',
      );

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(output.toBytes()),
        mimeType: 'image/webp',
        context: C2paContext(
          verifier: _DigestVerifier(_certificates.leafSpki),
          trust: _trust(),
        ),
      );
      expect(
        _codes(reader),
        contains(ValidationCode.assertionDataHashMatch.value),
      );

      final tampered = output.toBytes()..[20] ^= 1;
      final tamperedReader = await C2paReader.fromSource(
        source: MemoryByteSource(tampered),
        mimeType: 'image/webp',
        context: C2paContext(
          verifier: _DigestVerifier(_certificates.leafSpki),
          trust: _trust(),
        ),
      );
      expect(
        _codes(tamperedReader),
        contains(ValidationCode.assertionDataHashMismatch.value),
      );
    });

    test('DataHash sidecar hashes the complete source', () async {
      final output = MemoryByteSink();
      await _builder(
        _definition(),
        signer: _ReservedDigestSigner(),
      ).saveToSource(
        source: MemoryByteSource(_webp()),
        output: output,
        mimeType: 'image/webp',
        embedManifest: false,
      );
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(output.toBytes()),
        assetSource: MemoryByteSource(_webp()),
        assetMimeType: 'image/webp',
        context: C2paContext(
          verifier: _DigestVerifier(_certificates.leafSpki),
          trust: _trust(),
        ),
      );
      expect(
        _codes(reader),
        contains(ValidationCode.assertionDataHashMatch.value),
      );
    });

    test('round-trips DataHash TIFF/SVG and BMFF Hash MP4 assets', () async {
      final fixtures = <(List<int>, String, String)>[
        (_tiff(), 'image/tiff', ValidationCode.assertionDataHashMatch.value),
        (
          utf8.encode('<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>'),
          'image/svg+xml',
          ValidationCode.assertionDataHashMatch.value,
        ),
        (_mp4(), 'video/mp4', ValidationCode.assertionBmffHashMatch.value),
      ];
      for (final (bytes, mimeType, expectedCode) in fixtures) {
        final output = MemoryByteSink();
        await _builder(
          _definition(),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(bytes),
          output: output,
          mimeType: mimeType,
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(output.toBytes()),
          mimeType: mimeType,
          context: C2paContext(
            verifier: _DigestVerifier(_certificates.leafSpki),
            trust: _trust(),
          ),
        );
        expect(_codes(reader), contains(expectedCode), reason: mimeType);
      }
    });

    test('supports SHA-256, SHA-384, and SHA-512 DataHash', () async {
      for (final algorithm in ['sha256', 'sha384', 'sha512']) {
        final output = MemoryByteSink();
        await _builder(
          _definition(hashAlgorithm: algorithm),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(_webp()),
          output: output,
          mimeType: 'image/webp',
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(output.toBytes()),
          mimeType: 'image/webp',
          context: C2paContext(
            verifier: _DigestVerifier(_certificates.leafSpki),
            trust: _trust(),
          ),
        );
        expect(
          _codes(reader),
          contains(ValidationCode.assertionDataHashMatch.value),
          reason: algorithm,
        );
      }
    });

    test('reports malformed and additional DataHash exclusions', () async {
      final output = MemoryByteSink();
      await _builder(
        _definition(),
        signer: _ReservedDigestSigner(),
      ).saveToSource(
        source: MemoryByteSource(_webp()),
        output: output,
        mimeType: 'image/webp',
      );
      final malformed = await _rewriteEmbeddedDataHash(output.toBytes(), (
        value,
      ) {
        final exclusions = List<Object?>.from(value['exclusions'] as List);
        final first = Map<Object?, Object?>.from(exclusions.first as Map);
        first['length'] = 0;
        value['exclusions'] = [first];
      });
      expect(
        _codes(await _readWebp(malformed)),
        contains(ValidationCode.assertionDataHashMalformed.value),
      );

      final additional = await _rewriteEmbeddedDataHash(output.toBytes(), (
        value,
      ) {
        final exclusions = List<Object?>.from(value['exclusions'] as List);
        value['exclusions'] = [
          ...exclusions,
          {'start': 0, 'length': 1},
        ];
      });
      expect(
        _codes(await _readWebp(additional)),
        contains(ValidationCode.assertionDataHashAdditionalExclusions.value),
      );
    });

    test('DataHash requires reservation and honors cancellation', () async {
      await expectLater(
        _builder(_definition()).saveToSource(
          source: MemoryByteSource(_webp()),
          output: MemoryByteSink(),
          mimeType: 'image/webp',
        ),
        throwsA(isA<C2paSigningException>()),
      );
      await expectLater(
        _builder(
          _definition(),
          signer: _UndersizedReservationSigner(),
        ).saveToSource(
          source: MemoryByteSource(_webp()),
          output: MemoryByteSink(),
          mimeType: 'image/webp',
        ),
        throwsA(isA<C2paSigningException>()),
      );
      final builder = C2paBuilder(
        definition: _definition(),
        context: C2paContext(
          signer: _ReservedDigestSigner(),
          isCancelled: () => true,
        ),
        signingAlgorithm: 'ps256',
        x5chain: [_certificates.leaf, _certificates.intermediate],
      );
      await expectLater(
        builder.saveToSource(
          source: MemoryByteSource(_webp()),
          output: MemoryByteSink(),
          mimeType: 'image/webp',
          embedManifest: false,
        ),
        throwsA(isA<C2paFormatException>()),
      );
    });

    test('BMFF Hash v3 models are deterministic, owned, and strict', () {
      final replacement = Uint8List.fromList([1, 2, 3]);
      final digest = Uint8List.fromList(
        List<int>.generate(32, (index) => index),
      );
      final assertion = BmffHashAssertion(
        exclusions: [
          BmffHashExclusion(
            xpath: '/moov/trak',
            length: 24,
            data: [BmffHashDataReplacement(offset: 4, value: replacement)],
            subsets: const [
              BmffHashSubset(offset: 8, length: 4),
              BmffHashSubset(offset: 16),
            ],
            version: 1,
            flags: const [0, 0, 1],
            exact: false,
          ),
        ],
        algorithm: 'sha256',
        hash: digest,
        name: 'asset',
      );
      replacement[0] = 9;
      digest[0] = 9;

      final encoded = encodeCbor(assertion.toCborMap());
      final decoded = BmffHashAssertion.fromCbor(decodeCbor(encoded));
      expect(encodeCbor(decoded.toCborMap()), encoded);
      expect(decoded, assertion);
      expect(decoded.hash!.first, 0);
      expect(decoded.exclusions.single.data.single.value.first, 1);
      expect(
        BmffHashAssertion.fromCbor({
          'exclusions': [
            {'xpath': '/free'},
          ],
        }).toCborMap(),
        {
          'exclusions': [
            {'xpath': '/free'},
          ],
        },
      );
      expect(
        () => BmffHashAssertion.fromCbor({
          'exclusions': [
            {'xpath': '/free', 'unknown': true},
          ],
        }),
        throwsFormatException,
      );
      expect(
        () => BmffHashExclusion(xpath: '/free', flags: const [0, 1]),
        throwsFormatException,
      );
      expect(
        () => BmffHashExclusion(
          xpath: '/free',
          subsets: const [
            BmffHashSubset(offset: 8, length: 4),
            BmffHashSubset(offset: 10, length: 1),
          ],
        ),
        throwsFormatException,
      );
      final merkle = MerkleMap(
        uniqueId: 7,
        localId: 3,
        count: 2,
        algorithm: 'sha256',
        initHash: List<int>.filled(32, 1),
        hashes: [List<int>.filled(32, 2)],
        variableBlockSizes: const [40, 50],
      );
      expect(MerkleMap.fromCbor(merkle.toCborMap()), merkle);
      expect(
        BmffHashAssertion(
          exclusions: [BmffHashExclusion(xpath: '/uuid')],
          algorithm: 'sha256',
          merkle: [merkle],
        ).toCborMap(),
        containsPair('merkle', [merkle.toCborMap()]),
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 2,
          hashes: [List<int>.filled(32, 0)],
          variableBlockSizes: const [10],
        ),
        throwsFormatException,
      );
      expect(
        () => MerkleMap(
          uniqueId: 0,
          localId: 0,
          count: 1,
          hashes: [List<int>.filled(32, 0)],
          fixedBlockSize: 10,
          variableBlockSizes: const [10],
        ),
        throwsFormatException,
      );
    });

    test('round-trips BMFF Hash v3 for MP4, MOV, and HEIF', () async {
      final fixtures = <(List<int>, String)>[
        (_mp4(), 'video/mp4'),
        (_mov(), 'video/quicktime'),
        (_heif(), 'image/heif'),
      ];
      for (final (bytes, mimeType) in fixtures) {
        final output = MemoryByteSink();
        await _builder(
          _definition(),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(bytes),
          output: output,
          mimeType: mimeType,
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(output.toBytes()),
          mimeType: mimeType,
          context: C2paContext(
            verifier: _DigestVerifier(_certificates.leafSpki),
            trust: _trust(),
          ),
        );
        expect(
          _codes(reader),
          contains(ValidationCode.assertionBmffHashMatch.value),
          reason: mimeType,
        );
        expect(reader.validationResults.state, ValidationState.trusted);
      }
    });

    test('supports BMFF Hash SHA-256, SHA-384, and SHA-512', () async {
      for (final algorithm in ['sha256', 'sha384', 'sha512']) {
        final output = MemoryByteSink();
        await _builder(
          _definition(hashAlgorithm: algorithm),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(_mp4()),
          output: output,
          mimeType: 'video/mp4',
        );
        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(output.toBytes()),
          mimeType: 'video/mp4',
          context: C2paContext(
            verifier: _DigestVerifier(_certificates.leafSpki),
            trust: _trust(),
          ),
        );
        expect(
          _codes(reader),
          contains(ValidationCode.assertionBmffHashMatch.value),
          reason: algorithm,
        );
      }
    });

    test('BMFF custom nested subsets control the hashed bytes', () async {
      final source = _nestedMp4();
      final output = MemoryByteSink();
      await _builder(
        _definition(
          bmffExclusions: [
            BmffHashExclusion(
              xpath: '/moov/trak/mdia/minf/stbl/stco',
              version: 0,
              flags: const [0, 0, 1],
              subsets: const [BmffHashSubset(offset: 12, length: 2)],
            ),
          ],
        ),
        signer: _ReservedDigestSigner(),
      ).saveToSource(
        source: MemoryByteSource(source),
        output: output,
        mimeType: 'video/mp4',
      );
      final signed = output.toBytes();
      final stco = _lastIndexOf(signed, 'stco'.codeUnits) - 4;
      expect(stco, greaterThanOrEqualTo(0));

      final excludedMutation = Uint8List.fromList(signed);
      excludedMutation[stco + 12] ^= 0xff;
      final excludedReader = await _readBmff(excludedMutation, 'video/mp4');
      expect(
        _codes(excludedReader),
        contains(ValidationCode.assertionBmffHashMatch.value),
      );

      final includedMutation = Uint8List.fromList(signed);
      includedMutation[stco + 14] ^= 0xff;
      final includedReader = await _readBmff(includedMutation, 'video/mp4');
      expect(
        _codes(includedReader),
        contains(ValidationCode.assertionBmffHashMismatch.value),
      );
    });

    test(
      'BMFF Hash reports malformed data and malformed Merkle maps',
      () async {
        final output = MemoryByteSink();
        await _builder(
          _definition(),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(_mp4()),
          output: output,
          mimeType: 'video/mp4',
        );
        final malformed = await _rewriteEmbeddedBmffHash(
          output.toBytes(),
          'video/mp4',
          (value) {
            final exclusions = List<Object?>.from(value['exclusions'] as List);
            final first = Map<Object?, Object?>.from(exclusions.first as Map);
            first['flags'] = Uint8List.fromList([0, 1]);
            exclusions[0] = first;
            value['exclusions'] = exclusions;
          },
        );
        final malformedReader = await _readBmff(malformed, 'video/mp4');
        expect(
          _codes(malformedReader),
          contains(ValidationCode.assertionBmffHashMalformed.value),
        );

        final merkle = await _rewriteEmbeddedBmffHash(
          output.toBytes(),
          'video/mp4',
          (value) => value['merkle'] = const [],
        );
        expect(
          _codes(await _readBmff(merkle, 'video/mp4')),
          contains(ValidationCode.assertionBmffHashMalformed.value),
        );
      },
    );

    test('signs and validates fixed and variable fragmented BMFF', () async {
      for (final variable in [false, true]) {
        final result =
            await _builder(
              _definition(),
              signer: _ReservedDigestSigner(),
            ).buildFragmentedBmff(
              initializationSegment: MemoryByteSource(_fragmentedInit()),
              fragments: [
                MemoryByteSource(_fragment(1, const [1, 2, 3, 4])),
                MemoryByteSource(_fragment(2, const [5, 6, 7, 8, 9])),
                MemoryByteSource(_fragment(3, const [10, 11, 12])),
              ],
              merkleReservationBytes: 4096,
              uniqueId: 42,
              localId: 7,
              fixedBlockSize: variable ? null : 1024,
              useVariableBlockSizes: variable,
              mimeType: 'video/mp4',
            );
        final reader = await _readFragmented(
          result.initializationSegment,
          result.fragments,
        );
        expect(
          _codes(reader),
          contains(ValidationCode.assertionBmffHashMatch.value),
          reason: variable ? 'variable' : 'fixed',
        );
        expect(reader.validationResults.state, ValidationState.trusted);
      }
    });

    test(
      'fragmented BMFF detects tamper, reorder, missing, and bad proof',
      () async {
        final result =
            await _builder(
              _definition(),
              signer: _ReservedDigestSigner(),
            ).buildFragmentedBmff(
              initializationSegment: MemoryByteSource(_fragmentedInit()),
              fragments: [
                MemoryByteSource(_fragment(1, const [1, 2, 3, 4])),
                MemoryByteSource(_fragment(2, const [5, 6, 7, 8])),
              ],
              merkleReservationBytes: 4096,
              fixedBlockSize: 1024,
              mimeType: 'video/mp4',
            );

        final tampered = Uint8List.fromList(result.fragments.first);
        tampered[tampered.length - 1] ^= 0xff;
        expect(
          _codes(
            await _readFragmented(result.initializationSegment, [
              tampered,
              result.fragments.last,
            ]),
          ),
          contains(ValidationCode.assertionBmffHashMismatch.value),
        );
        expect(
          _codes(
            await _readFragmented(
              result.initializationSegment,
              result.fragments.reversed,
            ),
          ),
          contains(ValidationCode.assertionBmffHashMismatch.value),
        );
        expect(
          _codes(
            await _readFragmented(result.initializationSegment, [
              result.fragments.first,
            ]),
          ),
          contains(ValidationCode.assertionBmffHashMismatch.value),
        );
        expect(
          _codes(
            await _readFragmented(result.initializationSegment, [
              ...result.fragments,
              Uint8List.fromList(_fragment(3, const [9])),
            ]),
          ),
          contains(ValidationCode.assertionBmffHashMismatch.value),
        );

        final badProof = await _rewriteMerkleProof(
          result.fragments.first,
          (value) => value['localId'] = 1,
        );
        expect(
          _codes(
            await _readFragmented(result.initializationSegment, [
              badProof,
              result.fragments.last,
            ]),
          ),
          contains(ValidationCode.assertionBmffHashMalformed.value),
        );
      },
    );

    test(
      'fragmented BMFF supports SHA algorithms and enforces capacity',
      () async {
        for (final algorithm in ['sha256', 'sha384', 'sha512']) {
          final result =
              await _builder(
                _definition(hashAlgorithm: algorithm),
                signer: _ReservedDigestSigner(),
              ).buildFragmentedBmff(
                initializationSegment: MemoryByteSource(_fragmentedInit()),
                fragments: [
                  MemoryByteSource(_fragment(1, const [1, 2, 3])),
                  MemoryByteSource(_fragment(2, const [4, 5, 6])),
                ],
                merkleReservationBytes: 4096,
                fixedBlockSize: 1024,
                mimeType: 'video/mp4',
              );
          expect(
            _codes(
              await _readFragmented(
                result.initializationSegment,
                result.fragments,
              ),
            ),
            contains(ValidationCode.assertionBmffHashMatch.value),
            reason: algorithm,
          );
        }
        await expectLater(
          _builder(
            _definition(),
            signer: _ReservedDigestSigner(),
          ).buildFragmentedBmff(
            initializationSegment: MemoryByteSource(_fragmentedInit()),
            fragments: [
              MemoryByteSource(_fragment(1, const [1])),
            ],
            merkleReservationBytes: 1,
            mimeType: 'video/mp4',
          ),
          throwsA(isA<C2paSigningException>()),
        );
        await expectLater(
          _builder(
            _definition(),
            signer: _ReservedDigestSigner(),
          ).buildFragmentedBmff(
            initializationSegment: MemoryByteSource(_fragmentedInit()),
            fragments: [
              MemoryByteSource(_fragment(1, const [1, 2, 3])),
            ],
            merkleReservationBytes: 4096,
            fixedBlockSize: 1,
            mimeType: 'video/mp4',
          ),
          throwsA(isA<C2paValidationException>()),
        );
      },
    );

    test(
      'BMFF Hash rejects fragmented input and reservation overflow',
      () async {
        await expectLater(
          _builder(_definition(), signer: _ReservedDigestSigner()).saveToSource(
            source: MemoryByteSource(_fragmentedMp4()),
            output: MemoryByteSink(),
            mimeType: 'video/mp4',
          ),
          throwsA(isA<C2paUnsupportedException>()),
        );
        final regular = MemoryByteSink();
        await _builder(
          _definition(),
          signer: _ReservedDigestSigner(),
        ).saveToSource(
          source: MemoryByteSource(_mp4()),
          output: regular,
          mimeType: 'video/mp4',
        );
        final regularBytes = regular.toBytes();
        final ftypLength =
            (regularBytes[0] << 24) |
            (regularBytes[1] << 16) |
            (regularBytes[2] << 8) |
            regularBytes[3];
        final fragmentedSigned = Uint8List.fromList([
          ...regularBytes.sublist(0, ftypLength),
          ..._isoBox('moof', const []),
          ...regularBytes.sublist(ftypLength),
        ]);
        await expectLater(
          _readBmff(fragmentedSigned, 'video/mp4'),
          throwsA(isA<C2paUnsupportedException>()),
        );
        await expectLater(
          _builder(
            _definition(),
            signer: _UndersizedReservationSigner(),
          ).saveToSource(
            source: MemoryByteSource(_mp4()),
            output: MemoryByteSink(),
            mimeType: 'video/mp4',
          ),
          throwsA(isA<C2paSigningException>()),
        );
      },
    );

    test('updates and removes provenance URLs for capable formats', () async {
      final registry = AssetHandlerRegistry();
      final fixtures = <(List<int>, String, String)>[
        (_jpeg(), 'image/jpeg', 'jpg'),
        (_png(), 'image/png', 'png'),
        (_tiff(), 'image/tiff', 'tiff'),
        (_svg(), 'image/svg+xml', 'svg'),
        (_mp4(), 'video/mp4', 'mp4'),
        (_wav(), 'audio/wav', 'wav'),
        (_mp3(), 'audio/mpeg', 'mp3'),
        (_jxl(), 'image/jxl', 'jxl'),
      ];
      final first = Uri.parse('https://assets.example/one.c2pa');
      final second = Uri.parse('https://assets.example/two.c2pa');

      for (final (bytes, mimeType, extension) in fixtures) {
        final updated = await C2paBuilder.updateRemoteManifestReference(
          source: MemoryByteSource(bytes),
          remoteManifestUrl: first,
          mimeType: mimeType,
          fileName: 'asset.$extension',
        );
        expect(
          await registry.readRemoteManifestReference(
            MemoryByteSource(updated),
            mimeType: mimeType,
            fileExtension: extension,
          ),
          first.toString(),
          reason: mimeType,
        );
        final replaced = await C2paBuilder.updateRemoteManifestReference(
          source: MemoryByteSource(updated),
          remoteManifestUrl: second,
          mimeType: mimeType,
          fileName: 'asset.$extension',
        );
        expect(
          await registry.readRemoteManifestReference(
            MemoryByteSource(replaced),
            mimeType: mimeType,
            fileExtension: extension,
          ),
          second.toString(),
          reason: mimeType,
        );
        final removed = await C2paBuilder.removeRemoteManifestReference(
          source: MemoryByteSource(replaced),
          mimeType: mimeType,
          fileName: 'asset.$extension',
        );
        expect(
          await registry.readRemoteManifestReference(
            MemoryByteSource(removed),
            mimeType: mimeType,
            fileExtension: extension,
          ),
          isNull,
          reason: mimeType,
        );
      }
    });

    test('sidecar discovery honors explicit and remote precedence', () async {
      final remoteUrl = Uri.parse('https://assets.example/manifest.c2pa');
      final explicitBuilder = _builder(
        ManifestDefinition(
          label: 'urn:c2pa:explicit',
          intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
          generatorInfo: ClaimGeneratorInfo(name: 'test'),
          title: 'Explicit',
          format: 'image/jpeg',
          instanceId: 'xmp:iid:explicit',
        ),
      );
      final remoteBuilder = _builder(
        ManifestDefinition(
          label: 'urn:c2pa:remote',
          intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
          generatorInfo: ClaimGeneratorInfo(name: 'test'),
          title: 'Remote',
          format: 'image/jpeg',
          instanceId: 'xmp:iid:remote',
        ),
      );
      final sidecar = await explicitBuilder.buildSidecar(
        source: MemoryByteSource(_jpeg()),
        remoteManifestUrl: remoteUrl,
        mimeType: 'image/jpeg',
      );
      final remoteManifest = await remoteBuilder.buildSidecar(
        source: MemoryByteSource(sidecar.assetBytes!),
        mimeType: 'image/jpeg',
      );
      final resolver = _RemoteResolver(remoteManifest.manifestBytes);
      final context = C2paContext(
        settings: const C2paSettings(allowNetworkAccess: true),
        verifier: _DigestVerifier(_certificates.leafSpki),
        trust: _trust(),
        remoteResolver: resolver,
        remoteManifestPolicy: RemoteManifestPolicy(
          enabled: true,
          allowedHosts: const {'assets.example'},
          maxBytes: 1024 * 1024,
        ),
      );

      final explicit = await C2paReader.fromSource(
        source: MemoryByteSource(sidecar.assetBytes!),
        manifestSource: MemoryByteSource(sidecar.manifestBytes),
        mimeType: 'image/jpeg',
        context: context,
      );
      expect(explicit.activeManifestLabel, 'urn:c2pa:explicit');
      expect(
        _codes(explicit),
        contains(ValidationCode.assertionDataHashMatch.value),
      );
      expect(explicit.validationResults.state, ValidationState.trusted);
      expect(resolver.calls, 0);

      final remote = await C2paReader.fromSource(
        source: MemoryByteSource(sidecar.assetBytes!),
        mimeType: 'image/jpeg',
        context: context,
      );
      expect(remote.activeManifestLabel, 'urn:c2pa:remote');
      expect(
        _codes(remote),
        contains(ValidationCode.assertionDataHashMatch.value),
      );
      expect(remote.validationResults.state, ValidationState.trusted);
      expect(resolver.calls, 1);

      await expectLater(
        C2paReader.fromSource(
          source: MemoryByteSource(sidecar.assetBytes!),
          mimeType: 'image/jpeg',
        ),
        throwsA(
          isA<C2paUriPolicyException>().having(
            (error) => error.violation,
            'violation',
            RemoteManifestPolicyViolation.disabled,
          ),
        ),
      );
    });

    test('embedded manifests take precedence over remote references', () async {
      final embeddedOutput = MemoryByteSink();
      await _builder(
        ManifestDefinition(
          label: 'urn:c2pa:embedded',
          intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
          generatorInfo: ClaimGeneratorInfo(name: 'test'),
          title: 'Embedded',
          format: 'image/jpeg',
          instanceId: 'xmp:iid:embedded',
        ),
      ).saveToSource(
        source: MemoryByteSource(_jpeg()),
        output: embeddedOutput,
        mimeType: 'image/jpeg',
      );
      final asset = await C2paBuilder.updateRemoteManifestReference(
        source: MemoryByteSource(embeddedOutput.toBytes()),
        remoteManifestUrl: Uri.parse('https://assets.example/manifest.c2pa'),
        mimeType: 'image/jpeg',
      );
      final resolver = _RemoteResolver(await _builder(_definition()).build());

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(asset),
        mimeType: 'image/jpeg',
        context: C2paContext(
          settings: const C2paSettings(allowNetworkAccess: true),
          remoteResolver: resolver,
          remoteManifestPolicy: RemoteManifestPolicy(
            enabled: true,
            allowedHosts: const {'assets.example'},
            maxBytes: 1024 * 1024,
          ),
        ),
      );

      expect(reader.activeManifestLabel, 'urn:c2pa:embedded');
      expect(resolver.calls, 0);
    });

    test('remote malformed stores remain typed parse failures', () async {
      final asset = await C2paBuilder.updateRemoteManifestReference(
        source: MemoryByteSource(_jpeg()),
        remoteManifestUrl: Uri.parse('https://assets.example/manifest.c2pa'),
        mimeType: 'image/jpeg',
      );
      await expectLater(
        C2paReader.fromSource(
          source: MemoryByteSource(asset),
          mimeType: 'image/jpeg',
          context: C2paContext(
            settings: const C2paSettings(allowNetworkAccess: true),
            remoteResolver: _RemoteResolver(Uint8List.fromList([1, 2, 3])),
            remoteManifestPolicy: RemoteManifestPolicy(
              enabled: true,
              allowedHosts: const {'assets.example'},
              maxBytes: 1024,
            ),
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
    });
  });
}

ManifestDefinition _definition({
  BuilderIntent intent = const BuilderIntent.create(
    DigitalSourceType.digitalCapture,
  ),
  List<AssertionDefinition> assertions = const [],
  List<ManifestResource> resources = const [],
  List<String> redactions = const [],
  String hashAlgorithm = 'sha256',
  List<BmffHashExclusion> bmffExclusions = const [],
}) => ManifestDefinition(
  label: 'urn:c2pa:builder-test',
  intent: intent,
  generatorInfo: ClaimGeneratorInfo(name: 'builder-test', version: '1.0'),
  title: 'Builder test',
  format: 'image/jpeg',
  instanceId: 'xmp:iid:builder-test',
  hashAlgorithm: hashAlgorithm,
  assertions: assertions,
  resources: resources,
  redactions: redactions,
  bmffExclusions: bmffExclusions,
);

C2paBuilder _builder(ManifestDefinition definition, {C2paSigner? signer}) =>
    C2paBuilder(
      definition: definition,
      context: C2paContext(signer: signer ?? _DigestSigner()),
      signingAlgorithm: 'ps256',
      x5chain: [_certificates.leaf, _certificates.intermediate],
    );

final class _DigestSigner implements C2paSigner {
  int calls = 0;

  @override
  String get algorithm => 'ps256';

  @override
  Future<Uint8List> sign(Uint8List data) async {
    calls++;
    return Uint8List.fromList(await HashAlgorithm.sha512.digest(data));
  }
}

class _ReservedDigestSigner implements C2paReservedSizeSigner {
  @override
  String get algorithm => 'ps256';

  @override
  int get reservedSignatureSize => 64;

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      Uint8List.fromList(await HashAlgorithm.sha512.digest(data));
}

final class _UndersizedReservationSigner extends _ReservedDigestSigner {
  @override
  int get reservedSignatureSize => 63;
}

final class _FailingSigner implements C2paSigner {
  @override
  String get algorithm => 'ps256';

  @override
  Future<Uint8List> sign(Uint8List data) {
    throw StateError('signer failed');
  }
}

final class _DigestVerifier implements C2paVerifier {
  _DigestVerifier(this.expectedKey);

  final Uint8List expectedKey;
  int calls = 0;

  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async {
    calls++;
    final expected = await HashAlgorithm.sha512.digest(data);
    return algorithm == 'ps256' &&
        _equalBytes(publicKey, expectedKey) &&
        _equalBytes(signature, expected);
  }
}

C2paTrustConfiguration _trust() => C2paTrustConfiguration(
  trustAnchors: [_certificates.root],
  evaluationTime: DateTime.utc(2027),
);

int _indexOf(List<int> bytes, List<int> pattern) {
  for (var offset = 0; offset <= bytes.length - pattern.length; offset++) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  return -1;
}

int _lastIndexOf(List<int> bytes, List<int> pattern) {
  for (var offset = bytes.length - pattern.length; offset >= 0; offset--) {
    var matches = true;
    for (var index = 0; index < pattern.length; index++) {
      if (bytes[offset + index] != pattern[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return offset;
  }
  return -1;
}

bool _equalBytes(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

Set<String> _codes(C2paReader reader) =>
    reader.validationResults.issues.map((issue) => issue.code).toSet();

Future<C2paReader> _readStandalone(Uint8List bytes) => C2paReader.fromSource(
  source: MemoryByteSource(bytes),
  context: C2paContext(
    verifier: _DigestVerifier(_certificates.leafSpki),
    trust: _trust(),
  ),
);

Future<C2paReader> _readJpeg(Uint8List bytes) => C2paReader.fromSource(
  source: MemoryByteSource(bytes),
  mimeType: 'image/jpeg',
  context: C2paContext(
    verifier: _DigestVerifier(_certificates.leafSpki),
    trust: _trust(),
  ),
);

Future<C2paReader> _readWebp(Uint8List bytes) => C2paReader.fromSource(
  source: MemoryByteSource(bytes),
  mimeType: 'image/webp',
  context: C2paContext(
    verifier: _DigestVerifier(_certificates.leafSpki),
    trust: _trust(),
  ),
);

Future<C2paReader> _readBmff(Uint8List bytes, String mimeType) =>
    C2paReader.fromSource(
      source: MemoryByteSource(bytes),
      mimeType: mimeType,
      context: C2paContext(
        verifier: _DigestVerifier(_certificates.leafSpki),
        trust: _trust(),
      ),
    );

Future<C2paReader> _readFragmented(
  List<int> initializationSegment,
  Iterable<List<int>> fragments,
) => C2paReader.fromFragmentedBmff(
  initializationSegment: MemoryByteSource(initializationSegment),
  fragments: fragments.map(MemoryByteSource.new),
  mimeType: 'video/mp4',
  context: C2paContext(
    verifier: _DigestVerifier(_certificates.leafSpki),
    trust: _trust(),
  ),
);

Future<Uint8List> _rewriteMerkleProof(
  Uint8List fragment,
  void Function(Map<Object?, Object?> value) transform,
) async {
  final marker = [
    ...IsoBmffAssetHandler.c2paUuid,
    0,
    0,
    0,
    0,
    ...'merkle'.codeUnits,
    0,
  ];
  final markerOffset = _indexOf(fragment, marker);
  if (markerOffset < 8) throw StateError('Merkle UUID box not found');
  final boxOffset = markerOffset - 8;
  final boxSize =
      (fragment[boxOffset] << 24) |
      (fragment[boxOffset + 1] << 16) |
      (fragment[boxOffset + 2] << 8) |
      fragment[boxOffset + 3];
  final payloadOffset = markerOffset + marker.length;
  final value = Map<Object?, Object?>.from(
    decodeCbor(fragment.sublist(payloadOffset, boxOffset + boxSize)) as Map,
  );
  transform(value);
  final encoded = encodeCbor(value);
  if (encoded.length != boxOffset + boxSize - payloadOffset) {
    throw StateError('Rewritten Merkle proof changed size');
  }
  final result = Uint8List.fromList(fragment);
  result.setRange(payloadOffset, boxOffset + boxSize, encoded);
  return result;
}

Future<Uint8List> _rewriteEmbeddedBmffHash(
  Uint8List asset,
  String mimeType,
  void Function(Map<Object?, Object?> value) transform,
) async {
  final registry = AssetHandlerRegistry();
  final manifest = await registry.extractManifest(
    MemoryByteSource(asset),
    mimeType: mimeType,
  );

  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    if (node.label == BmffHashAssertion.label) {
      final payload = (node.children.single as JumbfCborNode).payload;
      final value = Map<Object?, Object?>.from(decodeCbor(payload) as Map);
      transform(value);
      return JumbfSuperBoxNode(
        description: node.description,
        children: [JumbfCborNode(encodeCbor(value))],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children.map(rewrite),
    );
  }

  final rewritten = (rewrite(parseJumbf(manifest)) as JumbfSuperBoxNode)
      .encode();
  final output = MemoryByteSink();
  await registry.replaceManifest(
    MemoryByteSource(asset),
    rewritten,
    output,
    mimeType: mimeType,
  );
  return output.toBytes();
}

Future<Uint8List> _rewriteEmbeddedDataHash(
  Uint8List asset,
  void Function(Map<Object?, Object?> value) transform,
) async {
  final registry = AssetHandlerRegistry();
  final manifest = await registry.extractManifest(
    MemoryByteSource(asset),
    mimeType: 'image/webp',
  );

  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    if (node.label == DataHashAssertion.label) {
      final payload = (node.children.single as JumbfCborNode).payload;
      final value = Map<Object?, Object?>.from(decodeCbor(payload) as Map);
      transform(value);
      return JumbfSuperBoxNode(
        description: node.description,
        children: [JumbfCborNode(encodeCbor(value))],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children.map(rewrite),
    );
  }

  final rewritten = (rewrite(parseJumbf(manifest)) as JumbfSuperBoxNode)
      .encode();
  final output = MemoryByteSink();
  await registry.replaceManifest(
    MemoryByteSource(asset),
    rewritten,
    output,
    mimeType: 'image/webp',
  );
  return output.toBytes();
}

Future<Uint8List> _rewriteEmbeddedBoxHash(
  Uint8List asset,
  List<Object?> Function(List<Object?> boxes) transform,
) async {
  final registry = AssetHandlerRegistry();
  final manifest = await registry.extractManifest(
    MemoryByteSource(asset),
    mimeType: 'image/jpeg',
  );
  final rewritten = _rewriteBoxHashPayload(manifest, transform);
  final output = MemoryByteSink();
  await registry.replaceManifest(
    MemoryByteSource(asset),
    rewritten,
    output,
    mimeType: 'image/jpeg',
  );
  return output.toBytes();
}

Uint8List _rewriteBoxHashPayload(
  Uint8List manifest,
  List<Object?> Function(List<Object?> boxes) transform,
) {
  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    if (node.label == BoxHashAssertion.label) {
      final payload = (node.children.single as JumbfCborNode).payload;
      final value = Map<Object?, Object?>.from(decodeCbor(payload) as Map);
      value['boxes'] = transform(List<Object?>.from(value['boxes'] as List));
      return JumbfSuperBoxNode(
        description: node.description,
        children: [JumbfCborNode(encodeCbor(value))],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children.map(rewrite),
    );
  }

  return (rewrite(parseJumbf(manifest)) as JumbfSuperBoxNode).encode();
}

Uint8List _rewriteHardBindingStructure(
  Uint8List manifest, {
  bool remove = false,
  bool duplicate = false,
  bool updateManifest = false,
}) {
  JumbfNode rewrite(JumbfNode node) {
    if (node is! JumbfSuperBoxNode) return node;
    var description = node.description;
    if (updateManifest &&
        node.description.contentTypeHex == JumbfUuid.c2paManifest) {
      description = JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paUpdateManifest,
        label: node.label,
      );
    }
    var children = node.children.map(rewrite).toList();
    if (node.label == 'c2pa.assertions') {
      final binding = children.whereType<JumbfSuperBoxNode>().singleWhere(
        (child) => child.label == BoxHashAssertion.label,
      );
      if (remove) {
        children.remove(binding);
      } else if (duplicate) {
        children.add(
          JumbfSuperBoxNode(
            description: JumbfDescription.fromUuidHex(
              contentType: JumbfUuid.cbor,
              label: '${BoxHashAssertion.label}__1',
            ),
            children: binding.children,
          ),
        );
      }
    }
    if (duplicate && node.label == 'c2pa.claim.v2') {
      final value = Map<Object?, Object?>.from(
        decodeCbor((node.children.single as JumbfCborNode).payload) as Map,
      );
      final references = List<Object?>.from(value['created_assertions'] as List)
        ..add({
          'url':
              'self#jumbf=c2pa.assertions/'
              '${BoxHashAssertion.label}__1',
          'alg': 'sha256',
          'hash': Uint8List(32),
        });
      children = [
        JumbfCborNode(encodeCbor({...value, 'created_assertions': references})),
      ];
    }
    return JumbfSuperBoxNode(description: description, children: children);
  }

  return (rewrite(parseJumbf(manifest)) as JumbfSuperBoxNode).encode();
}

List<int> _webp() => [
  0x52, 0x49, 0x46, 0x46, // RIFF
  0x10, 0x00, 0x00, 0x00,
  0x57, 0x45, 0x42, 0x50, // WEBP
  0x54, 0x45, 0x53, 0x54, // TEST
  0x04, 0x00, 0x00, 0x00,
  1, 2, 3, 4,
];

List<int> _wav() {
  final payload = <int>[
    ...'WAVE'.codeUnits,
    ...'fmt '.codeUnits,
    16,
    0,
    0,
    0,
    1,
    0,
    1,
    0,
    0x40,
    0x1f,
    0,
    0,
    0x40,
    0x1f,
    0,
    0,
    1,
    0,
    8,
    0,
    ...'data'.codeUnits,
    2,
    0,
    0,
    0,
    1,
    2,
  ];
  return [...'RIFF'.codeUnits, payload.length, 0, 0, 0, ...payload];
}

List<int> _svg() => '<svg xmlns="http://www.w3.org/2000/svg"></svg>'.codeUnits;

List<int> _mp3() => [...'ID3'.codeUnits, 4, 0, 0, 0, 0, 0, 0, 1, 2, 3];

List<int> _tiff() => [
  0x49, 0x49, // little endian
  42, 0,
  8, 0, 0, 0, // first IFD
  0, 0, // zero entries
  0, 0, 0, 0, // no next IFD
];

List<int> _mp4() => [
  ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
  ..._isoBox('free', const [1, 2, 3, 4]),
  ..._isoBox('mdat', const [5, 6, 7, 8]),
];

List<int> _mov() => [
  ..._isoBox('ftyp', [...'qt  '.codeUnits, 0, 0, 0, 0, ...'qt  '.codeUnits]),
  ..._isoBox('mdat', const [1, 2, 3, 4]),
];

List<int> _heif() => [
  ..._isoBox('ftyp', [...'mif1'.codeUnits, 0, 0, 0, 0, ...'mif1'.codeUnits]),
  ..._isoBox('mdat', const [1, 2, 3, 4]),
];

List<int> _nestedMp4() {
  final stco = [0, 0, 0, 1, 10, 11, 12, 13, 14, 15, 16, 17];
  return [
    ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
    ..._isoBox(
      'moov',
      _isoBox(
        'trak',
        _isoBox(
          'mdia',
          _isoBox('minf', _isoBox('stbl', _isoBox('stco', stco))),
        ),
      ),
    ),
    ..._isoBox('mdat', const [1, 2, 3, 4]),
  ];
}

List<int> _fragmentedMp4() => [
  ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
  ..._isoBox('moov', _isoBox('mvex', const [])),
  ..._isoBox('moof', const []),
  ..._isoBox('mdat', const [1]),
];

List<int> _fragmentedInit() => [
  ..._isoBox('ftyp', [...'mp42'.codeUnits, 0, 0, 0, 0, ...'mp42'.codeUnits]),
  ..._isoBox('moov', _isoBox('mvex', const [])),
];

List<int> _fragment(int sequence, List<int> media) => [
  ..._isoBox('moof', _isoBox('mfhd', [0, 0, 0, 0, ..._uint32(sequence)])),
  ..._isoBox('mdat', media),
];

List<int> _uint32(int value) => [value >> 24, value >> 16, value >> 8, value];

List<int> _jpeg() => [
  0xff,
  0xd8,
  ..._jpegSegment(0xe0, const [1, 2]),
  ..._jpegSegment(0xda, const [1, 1]),
  1,
  2,
  3,
  4,
  0xff,
  0xd9,
];

List<int> _jpegSegment(int marker, List<int> payload) {
  final length = payload.length + 2;
  return [0xff, marker, length >> 8, length, ...payload];
}

List<int> _gif() => [
  ...'GIF87a'.codeUnits,
  1,
  0,
  1,
  0,
  0x80,
  0,
  0,
  0,
  0,
  0,
  255,
  255,
  255,
  0x2c,
  0,
  0,
  0,
  0,
  1,
  0,
  1,
  0,
  0,
  2,
  2,
  0x44,
  0x01,
  0,
  0x3b,
];

List<int> _jxl() => [
  ...JpegXlAssetHandler.containerSignature,
  ..._isoBox('ftyp', [...'jxl '.codeUnits, 0, 0, 0, 0, ...'jxl '.codeUnits]),
  ..._isoBox('jxlc', const [0xff, 0x0a, 1]),
];

final class _RemoteResolver implements C2paRemoteResolver {
  _RemoteResolver(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int calls = 0;

  @override
  Future<C2paRemoteResponse> resolve(C2paRemoteRequest request) async {
    calls++;
    return C2paRemoteResponse.bytes(
      bytes: _bytes,
      contentLength: _bytes.length,
      resolvedAddresses: const {'93.184.216.34'},
    );
  }
}

List<int> _isoBox(String type, List<int> payload) {
  final size = payload.length + 8;
  return [
    size >> 24 & 0xff,
    size >> 16 & 0xff,
    size >> 8 & 0xff,
    size & 0xff,
    ...type.codeUnits,
    ...payload,
  ];
}

const List<int> _pngSignature = [
  0x89,
  0x50,
  0x4e,
  0x47,
  0x0d,
  0x0a,
  0x1a,
  0x0a,
];

List<int> _png() => [
  ..._pngSignature,
  ..._pngChunk('IHDR', List<int>.filled(13, 0)),
  ..._pngChunk('IEND', const []),
];

List<int> _pngChunk(String type, List<int> data) {
  final typeBytes = type.codeUnits;
  final crc = _crc32([...typeBytes, ...data]);
  return [
    (data.length >> 24) & 0xff,
    (data.length >> 16) & 0xff,
    (data.length >> 8) & 0xff,
    data.length & 0xff,
    ...typeBytes,
    ...data,
    (crc >> 24) & 0xff,
    (crc >> 16) & 0xff,
    (crc >> 8) & 0xff,
    crc & 0xff,
  ];
}

int _crc32(List<int> bytes) {
  var crc = 0xffffffff;
  for (final byte in bytes) {
    crc ^= byte;
    for (var bit = 0; bit < 8; bit++) {
      crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320 : crc >> 1;
    }
  }
  return crc ^ 0xffffffff;
}

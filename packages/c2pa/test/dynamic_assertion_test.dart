import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('dynamic assertions', () {
    test(
      'receives preliminary claim and preserves declaration order',
      () async {
        C2paDynamicClaimContext? observed;
        final firstData = {'value': 1};
        final secondData = {'value': 2};
        final builder =
            _builder(
                  assertions: [
                    AssertionDefinition.cbor(
                      label: 'com.example.static',
                      data: 0,
                    ),
                  ],
                )
                .withDynamicAssertion(
                  C2paDynamicAssertion(
                    label: 'com.example.first',
                    reservedSize: encodeCbor(firstData).length,
                    encoding: C2paDynamicAssertionEncoding.cbor,
                    callback: (request) async {
                      observed = request.claim;
                      expect(request.label, 'com.example.first');
                      return C2paDynamicAssertionOutput.cbor(
                        label: request.label,
                        data: firstData,
                      );
                    },
                  ),
                )
                .withDynamicAssertion(
                  C2paDynamicAssertion(
                    label: 'com.example.second',
                    reservedSize: encodeCbor(secondData).length,
                    encoding: C2paDynamicAssertionEncoding.cbor,
                    callback: (request) async =>
                        C2paDynamicAssertionOutput.cbor(
                          label: request.label,
                          data: secondData,
                        ),
                  ),
                );

        final first = await builder.build();
        final second = await builder.build();
        expect(first, second);
        expect(observed!.manifestLabel, 'urn:c2pa:dynamic');
        expect(
          observed!.assertions.map((value) => value.url),
          containsAllInOrder([
            contains('c2pa.hash.boxes'),
            contains('c2pa.actions'),
            contains('com.example.static'),
            contains('com.example.first'),
            contains('com.example.second'),
          ]),
        );

        final reader = await C2paReader.fromSource(
          source: MemoryByteSource(first),
        );
        expect(
          reader.activeManifest!.assertions.map((value) => value.label),
          containsAllInOrder([
            'c2pa.hash.boxes',
            'c2pa.actions.v2',
            'com.example.static',
            'com.example.first',
            'com.example.second',
          ]),
        );
      },
    );

    test('supports exact-size JSON and binary output', () async {
      final jsonData = {'ok': true};
      final jsonSize = Uint8List.fromList('{"ok":true}'.codeUnits).length;
      final builder = _builder()
          .withDynamicAssertion(
            C2paDynamicAssertion(
              label: 'com.example.json',
              reservedSize: jsonSize,
              encoding: C2paDynamicAssertionEncoding.json,
              callback: (request) async => C2paDynamicAssertionOutput.json(
                label: request.label,
                data: jsonData,
              ),
            ),
          )
          .withDynamicAssertion(
            C2paDynamicAssertion(
              label: 'com.example.binary',
              reservedSize: 4,
              encoding: C2paDynamicAssertionEncoding.binary,
              contentType: 'application/octet-stream',
              callback: (request) async => C2paDynamicAssertionOutput.binary(
                label: request.label,
                contentType: 'application/octet-stream',
                data: Uint8List.fromList([1, 2, 3, 4]),
              ),
            ),
          );

      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(await builder.build()),
      );
      expect(
        reader.activeManifest!.assertions.map((value) => value.label),
        containsAll(['com.example.json', 'com.example.binary']),
      );
    });

    test(
      'wraps callback failures and validates output label and size',
      () async {
        Future<void> expectSigningFailure(C2paDynamicAssertion assertion) =>
            expectLater(
              _builder().withDynamicAssertion(assertion).build(),
              throwsA(isA<C2paSigningException>()),
            );

        await expectSigningFailure(
          C2paDynamicAssertion(
            label: 'com.example.failure',
            reservedSize: 1,
            encoding: C2paDynamicAssertionEncoding.cbor,
            callback: (_) async => throw StateError('failed'),
          ),
        );
        await expectSigningFailure(
          C2paDynamicAssertion(
            label: 'com.example.label',
            reservedSize: 1,
            encoding: C2paDynamicAssertionEncoding.cbor,
            callback: (_) async =>
                C2paDynamicAssertionOutput.cbor(label: 'wrong', data: 0),
          ),
        );
        await expectSigningFailure(
          C2paDynamicAssertion(
            label: 'com.example.oversize',
            reservedSize: 1,
            encoding: C2paDynamicAssertionEncoding.cbor,
            callback: (request) async => C2paDynamicAssertionOutput.cbor(
              label: request.label,
              data: Uint8List(20),
            ),
          ),
        );
      },
    );

    test('rejects duplicate, reserved, and invalid declarations', () async {
      C2paDynamicAssertion assertion(String label, {int size = 1}) =>
          C2paDynamicAssertion(
            label: label,
            reservedSize: size,
            encoding: C2paDynamicAssertionEncoding.cbor,
            callback: (request) async =>
                C2paDynamicAssertionOutput.cbor(label: request.label, data: 0),
          );

      await expectLater(
        _builder(
          assertions: [
            AssertionDefinition.cbor(label: 'com.example.same', data: 0),
          ],
        ).withDynamicAssertion(assertion('com.example.same')).build(),
        throwsA(isA<C2paValidationException>()),
      );
      await expectLater(
        _builder()
            .withDynamicAssertion(assertion('com.example.same'))
            .withDynamicAssertion(assertion('com.example.same'))
            .build(),
        throwsA(isA<C2paValidationException>()),
      );
      await expectLater(
        _builder().withDynamicAssertion(assertion('c2pa.hash.data')).build(),
        throwsA(isA<C2paValidationException>()),
      );
      await expectLater(
        _builder()
            .withDynamicAssertion(assertion('com.example.empty', size: 0))
            .build(),
        throwsA(isA<C2paValidationException>()),
      );
    });

    test('runs once after DataHash placeholder reservation', () async {
      var calls = 0;
      final data = {'final': true};
      final builder = _builder(reservedSignatureSize: 64).withDynamicAssertion(
        C2paDynamicAssertion(
          label: 'com.example.datahash',
          reservedSize: encodeCbor(data).length,
          encoding: C2paDynamicAssertionEncoding.cbor,
          callback: (request) async {
            calls++;
            expect(
              request.claim.assertions.map((item) => item.url),
              contains(contains('c2pa.hash.data')),
            );
            return C2paDynamicAssertionOutput.cbor(
              label: request.label,
              data: data,
            );
          },
        ),
      );
      final output = MemoryByteSink();
      await builder.saveToSource(
        source: MemoryByteSource(_wave()),
        output: output,
        mimeType: 'audio/wav',
      );

      expect(calls, 1);
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(output.toBytes()),
        mimeType: 'audio/wav',
      );
      expect(
        reader.activeManifest!.assertions.map((item) => item.label),
        contains('com.example.datahash'),
      );
    });
  });

  group('advanced intent restrictions', () {
    test('update rejects extensions with manifest.update.invalid', () async {
      final parent = _parentIngredient();
      final builder =
          _builder(
            intent: const BuilderIntent.update(),
            ingredients: [parent],
          ).withDynamicAssertion(
            C2paDynamicAssertion(
              label: 'com.example.dynamic',
              reservedSize: 1,
              encoding: C2paDynamicAssertionEncoding.cbor,
              callback: (request) async => C2paDynamicAssertionOutput.cbor(
                label: request.label,
                data: 0,
              ),
            ),
          );

      await expectLater(
        builder.build(),
        throwsA(
          isA<C2paValidationException>().having(
            (error) => error.results!.activeManifest!.failure.single.code,
            'status',
            ValidationCode.manifestUpdateInvalid.value,
          ),
        ),
      );
    });

    test(
      'update and edit parent failures have typed status mappings',
      () async {
        await expectLater(
          _builder(intent: const BuilderIntent.update()).build(),
          throwsA(
            isA<C2paValidationException>().having(
              (error) => error.results!.activeManifest!.failure.single.code,
              'status',
              ValidationCode.manifestUpdateWrongParents.value,
            ),
          ),
        );
        await expectLater(
          _builder(
            intent: const BuilderIntent.edit(),
            ingredients: [
              _parentIngredient(),
              _parentIngredient(id: 'p2'),
            ],
          ).build(),
          throwsA(
            isA<C2paValidationException>().having(
              (error) => error.results!.activeManifest!.failure.single.code,
              'status',
              ValidationCode.manifestMultipleParents.value,
            ),
          ),
        );
      },
    );

    test(
      'redaction rejects self, missing, actions, and hard bindings',
      () async {
        final parent = _parentIngredient(
          manifestBytes: _manifestBox('urn:c2pa:parent', const [
            'com.example.allowed',
          ]),
        );

        Future<void> expectCode(String uri, ValidationCode code) async {
          await expectLater(
            _builder(
              intent: const BuilderIntent.edit(),
              ingredients: [parent],
              redactions: [uri],
            ).build(),
            throwsA(
              isA<C2paValidationException>().having(
                (error) => error.results!.activeManifest!.failure.single.code,
                'status',
                code.value,
              ),
            ),
          );
        }

        await expectCode(
          'self#jumbf=/c2pa/urn%3Ac2pa%3Adynamic/c2pa.assertions/example',
          ValidationCode.assertionSelfRedacted,
        );
        await expectCode(
          'self#jumbf=/c2pa/missing/c2pa.assertions/example',
          ValidationCode.assertionNotRedacted,
        );
        await expectCode(
          'self#jumbf=/c2pa/urn%3Ac2pa%3Aparent/'
          'c2pa.assertions/c2pa.actions.v2',
          ValidationCode.assertionActionRedacted,
        );
        await expectCode(
          'self#jumbf=/c2pa/urn%3Ac2pa%3Aparent/'
          'c2pa.assertions/c2pa.hash.data',
          ValidationCode.assertionDataHashRedacted,
        );
      },
    );

    test('legal redactions require a matching redacted action', () async {
      const uri =
          'self#jumbf=/c2pa/urn%3Ac2pa%3Aparent/'
          'c2pa.assertions/com.example.allowed';
      final parent = _parentIngredient(
        manifestBytes: _manifestBox('urn:c2pa:parent', const [
          'com.example.allowed',
        ]),
      );
      await expectLater(
        _builder(
          intent: const BuilderIntent.edit(),
          ingredients: [parent],
          redactions: const [uri],
        ).build(),
        throwsA(
          isA<C2paValidationException>().having(
            (error) => error.results!.activeManifest!.failure.single.code,
            'status',
            ValidationCode.assertionActionRedactionMismatch.value,
          ),
        ),
      );

      final manifest = await _builder(
        intent: const BuilderIntent.edit(),
        ingredients: [parent],
        redactions: const [uri],
        actions: [
          C2paAction(
            action: C2paActionNames.redacted,
            parameters: ActionParameters(redacted: uri),
          ),
        ],
      ).build();
      expect(manifest, isNotEmpty);
    });
  });
}

C2paBuilder _builder({
  BuilderIntent intent = const BuilderIntent.create(
    DigitalSourceType.digitalCapture,
  ),
  Iterable<AssertionDefinition> assertions = const [],
  Iterable<BuilderIngredient> ingredients = const [],
  Iterable<String> redactions = const [],
  Iterable<C2paAction> actions = const [],
  int reservedSignatureSize = 0,
}) => C2paBuilder(
  definition: ManifestDefinition(
    label: 'urn:c2pa:dynamic',
    intent: intent,
    generatorInfo: ClaimGeneratorInfo(name: 'dynamic-test'),
    format: 'application/c2pa',
    instanceId: 'xmp:iid:dynamic',
    assertions: assertions,
    ingredients: ingredients,
    redactions: redactions,
    actions: actions,
  ),
  context: C2paContext(
    signer: CallbackC2paSigner(
      algorithm: 'ed25519',
      callback: (_) async => Uint8List(64),
      reservedSignatureSize: reservedSignatureSize,
    ),
  ),
  signingAlgorithm: 'ed25519',
  x5chain: [
    Uint8List.fromList([1]),
  ],
);

BuilderIngredient _parentIngredient({
  String id = 'parent',
  Uint8List? manifestBytes,
}) => BuilderIngredient(
  id: id,
  assertion: IngredientAssertion(
    version: IngredientAssertionVersion.v3,
    relationship: Relationship.parentOf,
    instanceId: id,
  ),
  manifestBoxes: [?manifestBytes],
);

Uint8List _manifestBox(String label, List<String> assertionLabels) =>
    JumbfSuperBoxNode(
      description: JumbfDescription.fromUuidHex(
        contentType: JumbfUuid.c2paManifest,
        label: label,
      ),
      children: [
        JumbfSuperBoxNode(
          description: JumbfDescription.fromUuidHex(
            contentType: JumbfUuid.c2paAssertionStore,
            label: 'c2pa.assertions',
          ),
          children: [
            for (final assertionLabel in assertionLabels)
              JumbfSuperBoxNode(
                description: JumbfDescription.fromUuidHex(
                  contentType: JumbfUuid.cbor,
                  label: assertionLabel,
                ),
                children: [JumbfCborNode(encodeCbor(0))],
              ),
          ],
        ),
      ],
    ).encode();

Uint8List _wave() {
  final bytes = Uint8List(48);
  final data = ByteData.sublistView(bytes);
  bytes.setRange(0, 4, 'RIFF'.codeUnits);
  data.setUint32(4, 40, Endian.little);
  bytes.setRange(8, 12, 'WAVE'.codeUnits);
  bytes.setRange(12, 16, 'fmt '.codeUnits);
  data.setUint32(16, 16, Endian.little);
  data.setUint16(20, 1, Endian.little);
  data.setUint16(22, 1, Endian.little);
  data.setUint32(24, 8000, Endian.little);
  data.setUint32(28, 8000, Endian.little);
  data.setUint16(32, 1, Endian.little);
  data.setUint16(34, 8, Endian.little);
  bytes.setRange(36, 40, 'data'.codeUnits);
  data.setUint32(40, 4, Endian.little);
  bytes.setRange(44, 48, [1, 2, 3, 4]);
  return bytes;
}

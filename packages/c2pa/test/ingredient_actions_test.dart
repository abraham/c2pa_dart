import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:c2pa_crypto/c2pa_crypto.dart';
import 'package:test/test.dart';

import 'x509_test_support.dart';

late TestCertificateChain _certificates;

void main() {
  setUpAll(() async {
    _certificates = await loadTestCertificateChain();
  });

  test('ingredient v1, v2, and v3 preserve typed and unknown fields', () {
    final reference = ClaimHashedUri(
      url: 'self#jumbf=/c2pa/parent',
      algorithm: 'sha256',
      hash: Uint8List(32),
    );
    final versions = [
      IngredientAssertion(
        version: IngredientAssertionVersion.v1,
        relationship: Relationship.parentOf,
        title: 'parent.jpg',
        format: 'image/jpeg',
        instanceId: 'parent-id',
        documentId: 'document-id',
        c2paManifest: reference,
        validationStatus: [
          ValidationIssue.known(
            code: ValidationCode.ingredientManifestValidated,
          ),
        ],
        unknownFields: const {'vendor.v1': true},
      ),
      IngredientAssertion(
        version: IngredientAssertionVersion.v2,
        relationship: Relationship.componentOf,
        title: 'component.bin',
        format: 'application/octet-stream',
        data: reference,
        description: 'component',
        informationalUri: 'https://example.test/component',
        assetTypes: [
          IngredientAssetType(
            type: 'c2pa.types.dataset',
            extra: const {'vendor': 1},
          ),
        ],
        unknownFields: const {'vendor.v2': 'kept'},
      ),
      IngredientAssertion(
        version: IngredientAssertionVersion.v3,
        relationship: Relationship.inputTo,
        title: 'input.jpg',
        format: 'image/jpeg',
        instanceId: 'input-id',
        activeManifest: reference,
        claimSignature: reference,
        validationResults: ValidationResults(
          activeManifest: StatusCodes(
            statuses: [
              ValidationIssue.known(
                code: ValidationCode.claimSignatureValidated,
              ),
            ],
          ),
        ),
        metadata: const {'review': 'approved'},
        unknownFields: const {
          'vendor.v3': [1, 2],
        },
      ),
    ];

    for (final ingredient in versions) {
      final decoded = IngredientAssertion.fromCbor(
        decodeCbor(encodeCbor(ingredient.toCborMap())),
        version: ingredient.version,
      );
      expect(decoded, ingredient, reason: ingredient.version.name);
    }
  });

  test('actions use canonical ingredientIds and read legacy links', () {
    final action = C2paAction(
      action: C2paActionNames.placed,
      when: DateTime.utc(2026, 1, 2, 3, 4, 5),
      softwareAgent: const ActionSoftwareAgentName('Editor 1.0'),
      sourceType: DigitalSourceType.composite,
      parameters: ActionParameters(
        ingredientIds: const ['ingredient-id'],
        description: 'placed layer',
        common: const {'strength': 0.5},
      ),
      actors: [ActionActor(identifier: 'did:example:actor')],
      regions: [
        ActionRegion(const {'type': 'spatial', 'x': 1}),
      ],
      related: [C2paAction(action: C2paActionNames.opened)],
      reason: 'com.example.reason',
      unknownFields: const {'vendor': true},
    );
    final assertion = ActionsAssertion(actions: [action]);
    final decoded = ActionsAssertion.fromCbor(
      decodeCbor(encodeCbor(assertion.toCborMap())),
      version: 2,
    );
    expect(decoded, assertion);
    expect(
      decoded.actions.single.parameters!.toCborMap().keys,
      contains('ingredientIds'),
    );

    final legacy = C2paAction.fromCbor({
      'action': C2paActionNames.opened,
      'parameters': {
        'org.cai.ingredientIds': ['legacy-id'],
      },
    });
    expect(legacy.parameters!.ingredientIds, ['legacy-id']);
    expect(
      legacy.parameters!.toCborMap(),
      containsPair('ingredientIds', ['legacy-id']),
    );
    expect(
      legacy.parameters!.toCborMap(),
      isNot(contains('org.cai.ingredientIds')),
    );
  });

  test('builder embeds parent ingredient and links actions', () async {
    final parentBytes = await _builder(_definition('parent')).build();
    final parentReader = await _reader(parentBytes);
    final parent = await BuilderIngredient.fromReader(
      reader: parentReader,
      relationship: Relationship.parentOf,
    );
    final child = _builder(
      _definition(
        'child',
        intent: const BuilderIntent.edit(),
        ingredients: [parent],
        actions: [
          C2paAction(
            action: C2paActionNames.edited,
            parameters: ActionParameters(ingredientIds: [parent.id]),
          ),
        ],
      ),
    );

    final reader = await _reader(await child.build());
    expect(reader.manifests, hasLength(2));
    expect(reader.activeManifest!.ingredients, hasLength(1));
    expect(
      reader.activeManifest!.ingredients.single.version,
      IngredientAssertionVersion.v3,
    );
    expect(reader.activeManifest!.actions.single.actions, hasLength(2));
    expect(
      reader.validationResults.ingredientDeltas!.single.validationDeltas.success
          .map((status) => status.code),
      contains(ValidationCode.ingredientManifestValidated.value),
    );
  });

  test(
    'builder accepts component/input and rejects parent/link violations',
    () async {
      final parentReader = await _reader(
        await _builder(_definition('source')).build(),
      );
      final component = await BuilderIngredient.fromReader(
        reader: parentReader,
        relationship: Relationship.componentOf,
      );
      final input = await BuilderIngredient.fromReader(
        reader: await _reader(await _builder(_definition('input')).build()),
        relationship: Relationship.inputTo,
      );
      expect(
        await _builder(
          _definition('composite', ingredients: [component, input]),
        ).build(),
        isNotEmpty,
      );
      await expectLater(
        _builder(
          _definition(
            'invalid-parent',
            ingredients: [
              await BuilderIngredient.fromReader(
                reader: parentReader,
                relationship: Relationship.parentOf,
              ),
            ],
          ),
        ).build(),
        throwsA(isA<C2paValidationException>()),
      );
      await expectLater(
        _builder(
          _definition(
            'invalid-link',
            ingredients: [component],
            actions: [
              C2paAction(
                action: C2paActionNames.placed,
                parameters: ActionParameters(
                  ingredientIds: const ['missing-id'],
                ),
              ),
            ],
          ),
        ).build(),
        throwsA(isA<C2paValidationException>()),
      );
    },
  );

  test('ingredient depth limits are routed to ingredient deltas', () async {
    final parentReader = await _reader(
      await _builder(_definition('depth-parent')).build(),
    );
    final parent = await BuilderIngredient.fromReader(
      reader: parentReader,
      relationship: Relationship.parentOf,
    );
    final childBytes = await _builder(
      _definition(
        'depth-child',
        intent: const BuilderIntent.edit(),
        ingredients: [parent],
      ),
    ).build();
    final reader = await C2paReader.fromSource(
      source: MemoryByteSource(childBytes),
      context: C2paContext(
        verifier: _DigestVerifier(_certificates.leafSpki),
        trust: _trust(),
        settings: const C2paSettings(maxIngredientDepth: 0),
      ),
    );
    expect(
      reader.validationResults.ingredientDeltas!.single.validationDeltas.failure
          .map((status) => status.code),
      contains(ValidationCode.ingredientManifestMismatch.value),
    );
  });

  test(
    'update intent accepts exactly one parent without a hard binding',
    () async {
      final parentReader = await _reader(
        await _builder(_definition('update-parent')).build(),
      );
      final parent = await BuilderIngredient.fromReader(
        reader: parentReader,
        relationship: Relationship.parentOf,
      );
      final reader = await _reader(
        await _builder(
          _definition(
            'update',
            intent: const BuilderIntent.update(),
            ingredients: [parent],
          ),
        ).build(),
      );
      expect(reader.activeManifest!.contentType, JumbfUuid.c2paUpdateManifest);
      expect(
        reader.validationResults.activeManifest!.failure.map(
          (status) => status.code,
        ),
        isNot(contains(ValidationCode.manifestUpdateInvalid.value)),
      );
    },
  );

  test('malformed ingredient manifest references are routed', () async {
    final baseReader = await _reader(
      await _builder(_definition('bad-ref-base')).build(),
    );
    final parent = await BuilderIngredient.fromReader(
      reader: baseReader,
      relationship: Relationship.parentOf,
    );
    final child = await _builder(
      _definition(
        'bad-ref-child',
        intent: const BuilderIntent.edit(),
        ingredients: [parent],
      ),
    ).build();
    final malformed = _redirectIngredient(
      child,
      'urn:c2pa:bad-ref-child',
      'self#jumbf=/not-c2pa/missing',
    );
    final reader = await _reader(malformed);
    expect(
      reader.validationResults.ingredientDeltas!
          .expand((delta) => delta.validationDeltas.all)
          .map((status) => status.code),
      contains(ValidationCode.ingredientManifestMissing.value),
    );
  });

  test('ingredient manifest cycles are detected without recursion', () async {
    final baseReader = await _reader(
      await _builder(_definition('cycle-base')).build(),
    );
    final base = await BuilderIngredient.fromReader(
      reader: baseReader,
      relationship: Relationship.parentOf,
    );
    final middleReader = await _reader(
      await _builder(
        _definition(
          'cycle-middle',
          intent: const BuilderIntent.edit(),
          ingredients: [base],
        ),
      ).build(),
    );
    final middle = await BuilderIngredient.fromReader(
      reader: middleReader,
      relationship: Relationship.parentOf,
    );
    final top = await _builder(
      _definition(
        'cycle-top',
        intent: const BuilderIntent.edit(),
        ingredients: [middle],
      ),
    ).build();
    final cycled = _redirectIngredient(
      top,
      'urn:c2pa:cycle-middle',
      'self#jumbf=/c2pa/urn:c2pa:cycle-top',
    );
    final reader = await _reader(cycled);
    expect(
      reader.validationResults.ingredientDeltas!
          .expand((delta) => delta.validationDeltas.failure)
          .map((status) => status.explanation),
      contains('Ingredient manifest cycle detected'),
    );
  });
}

ManifestDefinition _definition(
  String name, {
  BuilderIntent intent = const BuilderIntent.create(
    DigitalSourceType.digitalCapture,
  ),
  List<BuilderIngredient> ingredients = const [],
  List<C2paAction> actions = const [],
}) => ManifestDefinition(
  label: 'urn:c2pa:$name',
  intent: intent,
  generatorInfo: ClaimGeneratorInfo(name: 'ingredient-test', version: '1.0'),
  format: 'image/jpeg',
  instanceId: 'xmp:iid:$name',
  ingredients: ingredients,
  actions: actions,
);

C2paBuilder _builder(ManifestDefinition definition) => C2paBuilder(
  definition: definition,
  context: C2paContext(signer: _DigestSigner()),
  signingAlgorithm: 'ps256',
  x5chain: [_certificates.leaf, _certificates.intermediate],
);

Future<C2paReader> _reader(Uint8List bytes) => C2paReader.fromSource(
  source: MemoryByteSource(bytes),
  context: C2paContext(
    verifier: _DigestVerifier(_certificates.leafSpki),
    trust: _trust(),
  ),
);

final class _DigestSigner implements C2paSigner {
  @override
  String get algorithm => 'ps256';

  @override
  Future<Uint8List> sign(Uint8List data) async =>
      Uint8List.fromList(await HashAlgorithm.sha512.digest(data));
}

final class _DigestVerifier implements C2paVerifier {
  _DigestVerifier(this.expectedKey);
  final Uint8List expectedKey;

  @override
  Future<bool> verify({
    required String algorithm,
    required Uint8List data,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async =>
      algorithm == 'ps256' &&
      _equal(publicKey, expectedKey) &&
      _equal(signature, await HashAlgorithm.sha512.digest(data));
}

C2paTrustConfiguration _trust() => C2paTrustConfiguration(
  trustAnchors: [_certificates.root],
  evaluationTime: DateTime.utc(2027),
);

bool _equal(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

Uint8List _redirectIngredient(
  Uint8List storeBytes,
  String manifestLabel,
  String target,
) {
  JumbfNode rewrite(JumbfNode node, {String? owner}) {
    if (node is! JumbfSuperBoxNode) return node;
    final currentOwner =
        node.description.contentTypeHex == JumbfUuid.c2paManifest
        ? node.label
        : owner;
    if (currentOwner == manifestLabel &&
        node.label?.startsWith(IngredientAssertion.label) == true) {
      final value = Map<Object?, Object?>.from(
        decodeCbor((node.children.single as JumbfCborNode).payload) as Map,
      );
      final reference = Map<Object?, Object?>.from(
        value['activeManifest'] as Map,
      );
      reference['url'] = target;
      value['activeManifest'] = reference;
      return JumbfSuperBoxNode(
        description: node.description,
        children: [JumbfCborNode(encodeCbor(value))],
      );
    }
    return JumbfSuperBoxNode(
      description: node.description,
      children: node.children
          .map((child) => rewrite(child, owner: currentOwner))
          .toList(growable: false),
    );
  }

  return (rewrite(parseJumbf(storeBytes)) as JumbfSuperBoxNode).encode();
}

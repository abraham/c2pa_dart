import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_codec/c2pa_codec.dart';
import 'package:test/test.dart';

void main() {
  group('builder working archives', () {
    test(
      'JUMBF archive is deterministic and round-trips complete state',
      () async {
        final builder = _builder().withArchiveConfiguration(
          basePath: 'assets/resources',
          remoteManifestUrl: Uri.parse('https://example.test/manifest.c2pa'),
          noEmbed: true,
          extensions: {
            'future': {
              'bytes': Uint8List.fromList([9, 8, 7]),
            },
          },
        );

        final first = builder.toArchive();
        final second = builder.toArchive();
        expect(first, second);
        final root = parseJumbf(first);
        expect(root.label, 'c2pa.archive');

        final restored = await C2paBuilder.fromArchive(
          bytes: first,
          context: builder.context,
        );
        expect(restored.definition, builder.definition);
        expect(restored.signingAlgorithm, builder.signingAlgorithm);
        expect(restored.x5chain, builder.x5chain);
        expect(restored.archiveBasePath, 'assets/resources');
        expect(
          restored.remoteManifestUrl,
          Uri.parse('https://example.test/manifest.c2pa'),
        );
        expect(restored.noEmbed, isTrue);
        expect(
          restored.archiveExtensions['future'],
          containsPair('bytes', Uint8List.fromList([9, 8, 7])),
        );
        expect(
          () => restored.definition.resources.single.bytes[0] = 0,
          throwsUnsupportedError,
        );
      },
    );

    test('loads the vendored c2pa-rs legacy ZIP archive', () async {
      final bytes = await _fixture('old_format_archive.zip').readAsBytes();
      final restored = await C2paBuilder.fromArchive(
        bytes: bytes,
        context: C2paContext(),
      );

      expect(restored.definition.title, 'Test Old Format');
      expect(restored.definition.format, 'application/octet-stream');
      expect(
        restored.definition.instanceId,
        'xmp:iid:dc61d5a2-0e98-4d74-9355-dce72c091159',
      );
      expect(restored.noEmbed, isFalse);
    });

    test('rejects the vendored absolute base path', () async {
      final bytes = await _fixture('bad_path_archive.zip').readAsBytes();
      await expectLater(
        C2paBuilder.fromArchive(bytes: bytes, context: C2paContext()),
        throwsA(isA<C2paUnsafeArchivePathException>()),
      );
    });

    test(
      'enforces resource limits and duplicate labels while loading',
      () async {
        final archive = _builder().toArchive();
        await expectLater(
          C2paBuilder.fromArchive(
            bytes: archive,
            context: C2paContext(
              settings: const C2paSettings(maxResourceCount: 0),
            ),
          ),
          throwsA(isA<C2paArchiveResourceException>()),
        );

        final duplicate = _builder(
          resources: [
            ManifestResource(
              label: 'duplicate',
              format: 'text/plain',
              bytes: Uint8List.fromList([1]),
            ),
            ManifestResource(
              label: 'duplicate',
              format: 'text/plain',
              bytes: Uint8List.fromList([2]),
            ),
          ],
        ).toArchive();
        await expectLater(
          C2paBuilder.fromArchive(bytes: duplicate, context: C2paContext()),
          throwsA(isA<C2paArchiveResourceException>()),
        );
      },
    );

    test('external paths need a resolver and remain contained', () async {
      final bytes = _archiveWithExternalResource('nested/data.bin');
      await expectLater(
        C2paBuilder.fromArchive(bytes: bytes, context: C2paContext()),
        throwsA(isA<C2paArchiveResourceException>()),
      );

      C2paArchiveResourceRequest? request;
      final restored = await C2paBuilder.fromArchive(
        bytes: bytes,
        context: C2paContext(),
        options: C2paArchiveLoadOptions(
          resourceResolver: (value) {
            request = value;
            return Uint8List.fromList([4, 5, 6]);
          },
        ),
      );
      expect(request!.path, 'nested/data.bin');
      expect(request!.basePath, 'project');
      expect(restored.definition.resources.single.bytes, [4, 5, 6]);

      await expectLater(
        C2paBuilder.fromArchive(
          bytes: _archiveWithExternalResource('../escape.bin'),
          context: C2paContext(),
          options: C2paArchiveLoadOptions(
            resourceResolver: (_) => Uint8List(0),
          ),
        ),
        throwsA(isA<C2paUnsafeArchivePathException>()),
      );
    });

    test('initializes an edit builder from a Reader', () async {
      final source = _builder(
        assertions: [
          AssertionDefinition.cbor(
            label: 'com.example.unknown',
            data: {
              'future': Uint8List.fromList([1, 2, 3]),
            },
          ),
        ],
      );
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(await source.build()),
      );
      final edit = await C2paBuilder.fromReader(
        reader: reader,
        context: source.context,
        signingAlgorithm: 'ed25519',
        x5chain: source.x5chain,
      );

      expect(edit.definition.intent, const BuilderIntent.edit());
      expect(
        edit.definition.ingredients.single.assertion.relationship,
        Relationship.parentOf,
      );
      expect(
        edit.definition.assertions.map((item) => item.label),
        contains('com.example.unknown'),
      );
      expect(
        edit.definition.assertions.map((item) => item.label),
        isNot(contains('c2pa.hash.boxes')),
      );
      expect(await edit.build(), isNotEmpty);
    });
  });
}

C2paBuilder _builder({
  Iterable<AssertionDefinition> assertions = const [],
  Iterable<ManifestResource>? resources,
}) => C2paBuilder(
  definition: ManifestDefinition(
    label: 'urn:c2pa:archive-test',
    intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
    generatorInfo: ClaimGeneratorInfo(
      name: 'archive-test',
      version: '1',
      extra: const {'future': true},
    ),
    title: 'Archive test',
    format: 'application/c2pa',
    instanceId: 'xmp:iid:archive-test',
    assertions: assertions,
    resources:
        resources ??
        [
          ManifestResource(
            label: 'resource',
            format: 'application/octet-stream',
            bytes: Uint8List.fromList([1, 2, 3]),
          ),
        ],
    bmffExclusions: [BmffHashExclusion(xpath: '/uuid', exact: true)],
    bmffHashName: 'asset',
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

Uint8List _archiveWithExternalResource(String path) {
  final base = _builder(resources: const []).toArchive();
  final root = parseJumbf(base);
  final payload = (root.children.single as JumbfJsonNode).payload;
  final document = jsonDecode(utf8.decode(payload)) as Map<String, Object?>;
  final builder = document['builder']! as Map<String, Object?>;
  builder['basePath'] = 'project';
  builder['externalResources'] = [
    {
      'uri': 'self#jumbf=/c2pa/resource',
      'path': path,
      'format': 'application/octet-stream',
    },
  ];
  return JumbfSuperBoxNode(
    description: root.description,
    children: [
      JumbfJsonNode(Uint8List.fromList(utf8.encode(jsonEncode(document)))),
    ],
  ).encode();
}

File _fixture(String name) {
  final fromRoot = File(
    'packages/c2pa_testkit/test/fixtures/vendor/c2pa-rs-0.90.22/media/zip/$name',
  );
  return fromRoot.existsSync()
      ? fromRoot
      : File(
          '../c2pa_testkit/test/fixtures/vendor/c2pa-rs-0.90.22/media/zip/$name',
        );
}

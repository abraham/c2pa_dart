import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  test(
    'loads fixture index with source, license, metadata, and skips',
    () async {
      final index = await loadConformanceFixtureIndex(
        'test/goldens/conformance_index.json',
      );

      expect(index.schemaVersion, 1);
      expect(index.fixtures, hasLength(2));
      expect(index.fixtures.first.source.license, 'CC-BY-4.0');
      expect(index.fixtures.first.source.url, 'https://example.test/asset.jpg');
      expect(index.fixtures.first.metadata, {'profile': 'baseline'});
      expect(index.fixtures.first.isSkipped, isFalse);
      expect(index.fixtures.last.isSkipped, isTrue);
      expect(index.fixtures.last.skipReason, 'Unsupported test profile');
    },
  );

  test('validates schema, duplicates, source metadata, and skip reasons', () {
    expect(
      () => ConformanceFixtureIndex.fromJson({
        'schemaVersion': 0,
        'fixtures': <Object?>[],
      }),
      throwsArgumentError,
    );
    expect(
      () => ConformanceFixtureIndex.fromJson({
        'schemaVersion': 1,
        'fixtures': [_fixture('same'), _fixture('same')],
      }),
      throwsFormatException,
    );
    expect(
      () => ConformanceFixtureIndex.fromJson({
        'schemaVersion': 1,
        'fixtures': [
          {
            'id': 'missing-license',
            'asset': 'asset.jpg',
            'source': {'url': 'https://example.test/asset.jpg'},
          },
        ],
      }),
      throwsFormatException,
    );
    expect(
      () => ConformanceFixtureIndex.fromJson({
        'schemaVersion': 1,
        'fixtures': [
          {..._fixture('empty-skip'), 'skipReason': ''},
        ],
      }),
      throwsFormatException,
    );
    expect(
      () => ConformanceFixtureIndex.fromJson({
        'schemaVersion': 1,
        'fixtures': [
          {..._fixture('escape'), 'asset': '../outside.jpg'},
        ],
      }),
      throwsFormatException,
    );
  });

  test('loads and verifies the pinned vendor conformance corpus', () async {
    const indexPath = 'test/fixtures/vendor/conformance_index.json';
    final index = await loadConformanceFixtureIndex(indexPath);

    expect(index.schemaVersion, 1);
    expect(index.fixtures, hasLength(58));
    for (final fixture in index.fixtures) {
      final bytes = await loadConformanceFixtureAsset(indexPath, fixture);
      expect(bytes, isNotEmpty, reason: fixture.id);
    }

    final identityFixtures = index.fixtures
        .where((fixture) => fixture.asset.contains('/identity/'))
        .toList(growable: false);
    expect(identityFixtures, hasLength(33));
    for (final fixture in identityFixtures) {
      expect(fixture.source.license, 'MIT OR Apache-2.0');
      expect(
        fixture.source.url,
        contains('1a56d244ee77d7e58221eabebede4281d9e868a4'),
      );
      expect(fixture.metadata['size'], greaterThan(0));
      expect(fixture.metadata['sha256'], matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(
        fixture.asset,
        isNot(anyOf(endsWith('.key'), endsWith('.pem'), endsWith('.p12'))),
      );
    }

    final unsupported = index.fixtures
        .where((fixture) => fixture.isSkipped)
        .toList(growable: false);
    expect(unsupported, hasLength(3));
    for (final fixture in unsupported) {
      expect(fixture.skipReason, contains('Builder archive'));
      expect(fixture.metadata['issueCategory'], 'unsupported-builder-archive');
    }
  });
}

Map<String, Object?> _fixture(String id) => {
  'id': id,
  'asset': '$id.jpg',
  'source': {'url': 'https://example.test/$id.jpg', 'license': 'MIT'},
};

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_testkit/c2pa_testkit.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

void main() {
  const indexPath = 'test/fixtures/vendor/conformance_index.json';
  late ConformanceFixtureIndex index;

  setUpAll(() async {
    index = await loadConformanceFixtureIndex(indexPath);
  });

  test('reads the public claim-v1 interoperability JPEG', () async {
    final fixture = _fixture(index, 'public-v1-jpeg');
    final reader = await C2paReader.fromSource(
      source: MemoryByteSource(
        await loadConformanceFixtureAsset(indexPath, fixture),
      ),
      fileName: fixture.asset,
    );

    expect(reader.activeClaim, isA<ClaimV1>());
    expect(reader.activeManifest, isNotNull);
    expect(reader.activeManifest!.ingredients, hasLength(1));
  });

  test('matches c2pa-rs positive and negative JPEG outcomes', () async {
    final positive = _fixture(index, 'rust-ca-jpeg');
    final positiveReader = await C2paReader.fromSource(
      source: MemoryByteSource(
        await loadConformanceFixtureAsset(indexPath, positive),
      ),
      fileName: positive.asset,
    );
    expect(positiveReader.activeClaim, isA<ClaimV1>());
    expect(
      positiveReader.validationResults.activeManifest?.success.map(
        (issue) => issue.code,
      ),
      contains(ValidationCode.claimSignatureValidated.value),
    );

    final negative = _fixture(index, 'rust-invalid-datahash-jpeg');
    final negativeReader = await C2paReader.fromSource(
      source: MemoryByteSource(
        await loadConformanceFixtureAsset(indexPath, negative),
      ),
      fileName: negative.asset,
    );
    expect(
      negativeReader.validationResults.errors.map((issue) => issue.code),
      contains(ValidationCode.assertionDataHashMismatch.value),
    );
    expect(negativeReader.validationResults.state, ValidationState.invalid);
  });

  test('extracts upstream PNG and BMFF manifests', () async {
    for (final id in ['rust-embedded-png', 'rust-embedded-bmff']) {
      final fixture = _fixture(index, id);
      final reader = await C2paReader.fromSource(
        source: MemoryByteSource(
          await loadConformanceFixtureAsset(indexPath, fixture),
        ),
        fileName: fixture.asset,
      );
      expect(reader.manifestBytes, isNotEmpty, reason: id);
      expect(reader.activeManifest, isNotNull, reason: id);
    }
  });

  test('rejects deeply nested BMFF without exhausting parser limits', () async {
    final fixture = _fixture(index, 'rust-nested-bmff');
    await expectLater(
      C2paReader.fromSource(
        source: MemoryByteSource(
          await loadConformanceFixtureAsset(indexPath, fixture),
        ),
        fileName: fixture.asset,
      ),
      throwsA(isA<C2paException>()),
    );
  });
}

ConformanceFixture _fixture(ConformanceFixtureIndex index, String id) =>
    index.fixtures.singleWhere((fixture) => fixture.id == id);

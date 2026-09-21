@TestOn('vm')
library;

// ignore: implementation_imports
import 'package:c2pa/src/bmff_hash.dart';
// ignore: implementation_imports
import 'package:c2pa/src/reader.dart';
// ignore: implementation_imports
import 'package:c2pa/src/report.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _vendorRoot = 'test/fixtures/vendor';

/// BMFF hard bindings must be honoured at every assertion version.
///
/// The reader matched the hard binding against `c2pa.hash.bmff.v3` exactly,
/// but no producer in either the upstream or the public test corpus emits v3:
/// real MP4 assets carry `c2pa.hash.bmff` (v1) or `c2pa.hash.bmff.v2`. Those
/// labels were therefore not recognised as hard bindings at all, so every
/// BMFF asset failed with `claim.hardBindings.missing` and was reported
/// invalid — a false reject of a perfectly good file.
///
/// The defect survived because BMFF was exercised only through assets this
/// SDK wrote itself, which naturally use the v3 label it emits.
///
/// Expectations below are the values reported by c2patool v0.27.22
/// (c2pa v0.90.22) for the same assets.
void main() {
  group('label matching spans assertion versions', () {
    test('accepts every published version, with instance suffixes', () {
      for (final label in const [
        'c2pa.hash.bmff',
        'c2pa.hash.bmff.v2',
        'c2pa.hash.bmff.v3',
        'c2pa.hash.bmff__1',
        'c2pa.hash.bmff.v2__3',
      ]) {
        expect(
          BmffHashAssertion.matchesLabel(label),
          isTrue,
          reason: '$label is a BMFF hard binding',
        );
      }
    });

    test('rejects labels that merely share the prefix', () {
      for (final label in const [
        'c2pa.hash.data',
        'c2pa.hash.bmffx',
        'c2pa.hash.bmff.vx',
        'c2pa.hash.bmff.v',
      ]) {
        expect(
          BmffHashAssertion.matchesLabel(label),
          isFalse,
          reason: '$label is not a BMFF hard binding',
        );
      }
    });

    test('reports the version carried by the label', () {
      // The layout engine only emits box markers for versions above 1, so a
      // v1 binding hashed as if it were v3 produces the wrong digest.
      expect(BmffHashAssertion.versionFromLabel('c2pa.hash.bmff'), 1);
      expect(BmffHashAssertion.versionFromLabel('c2pa.hash.bmff.v2'), 2);
      expect(BmffHashAssertion.versionFromLabel('c2pa.hash.bmff.v3__2'), 3);
      expect(BmffHashAssertion.versionFromLabel('c2pa.hash.data'), isNull);
    });
  });

  test('a real v2 BMFF asset validates', () async {
    const asset = 'c2pa-rs-0.90.22/media/bmff/video1.mp4';
    final reader = await C2paReader.fromSource(
      source: MemoryByteSource(await loadFixtureBytes('$_vendorRoot/$asset')),
      fileName: asset,
    );
    final active = reader.validationResults.activeManifest!;
    final failures = active.failure.map((status) => status.code).toList();
    final successes = active.success.map((status) => status.code).toList();

    expect(
      failures,
      isNot(contains('claim.hardBindings.missing')),
      reason: 'the v2 binding must be recognised as a hard binding',
    );
    expect(successes, contains('assertion.bmffHash.match'));
    // The binding itself must be clean. Trust-related statuses are excluded
    // deliberately: this reader verifies trust by default while c2patool only
    // does so once anchors are supplied, so they are not a BMFF concern.
    expect(
      failures.where((code) => !code.startsWith('signingCredential.')),
      isEmpty,
    );
  });

  test('the BMFF binding stays visible in the assertion list', () async {
    // c2pa-rs hides `c2pa.hash.data` and `c2pa.hash.boxes` from a manifest's
    // public assertion list but deliberately keeps `c2pa.hash.bmff`.
    const asset = 'c2pa-rs-0.90.22/media/bmff/video1.mp4';
    final reader = await C2paReader.fromSource(
      source: MemoryByteSource(await loadFixtureBytes('$_vendorRoot/$asset')),
      fileName: asset,
    );
    final report = reader.toSdkJson();
    final manifests = report['manifests']! as Map<String, Object?>;
    final active =
        manifests[report['active_manifest']]! as Map<String, Object?>;
    final labels = active['assertions']! as List<Object?>;

    expect(
      labels
          .cast<Map<String, Object?>>()
          .map((assertion) => assertion['label'])
          .toList(),
      containsAll(<String>['c2pa.hash.bmff.v2', 'c2pa.actions.v2']),
    );
  });
}

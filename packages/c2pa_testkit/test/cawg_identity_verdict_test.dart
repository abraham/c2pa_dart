@TestOn('vm')
library;

import 'dart:convert';

import 'package:c2pa/c2pa.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _identityRoot = 'test/fixtures/vendor/c2pa-rs-0.90.22/identity';

/// CAWG identity failures must reach the manifest verdict.
///
/// These fixtures are upstream negative cases. c2pa-rs v0.90.22 reports every
/// one of them as `Invalid`. Before the identity statuses were merged into
/// [C2paManifestEntry.validationIssues] the reader reported them as valid,
/// which silently accepted identity assertions that are unbound or malformed.
void main() {
  group('CAWG identity failures drive the verdict', () {
    for (final fixture in const [
      (
        asset: 'validation_method/no_hard_binding.jpg',
        code: 'cawg.identity.hard_binding_missing',
      ),
      (
        asset: 'validation_method/malformed_cbor.jpg',
        code: 'cawg.identity.cbor.invalid',
      ),
      (
        asset: 'validation_method/pad1_invalid.jpg',
        code: 'cawg.identity.pad.invalid',
      ),
      (
        asset: 'validation_method/pad2_invalid.jpg',
        code: 'cawg.identity.pad.invalid',
      ),
      (
        asset: 'validation_method/duplicate_assertion_reference.jpg',
        code: 'cawg.identity.assertion.duplicate',
      ),
      (
        asset: 'validation_method/extra_assertion_claim_v1.jpg',
        code: 'cawg.identity.assertion.mismatch',
      ),
      (
        asset: 'claim_aggregation/ica_validation/invalid_cose_sign1.jpg',
        code: 'cawg.ica.invalid_cose_sign1',
      ),
      (
        asset: 'claim_aggregation/ica_validation/invalid_vc.jpg',
        code: 'cawg.ica.invalid_verifiable_credential',
      ),
      (
        asset: 'claim_aggregation/ica_validation/signature_mismatch.jpg',
        code: 'cawg.ica.signature_mismatch',
      ),
      (
        asset: 'claim_aggregation/ica_validation/unresolvable_did.jpg',
        code: 'cawg.ica.did_unavailable',
      ),
    ]) {
      test('${fixture.asset} is invalid with ${fixture.code}', () async {
        final reader = await _read(fixture.asset);
        final active = reader.validationResults.activeManifest;

        expect(
          active?.failure.map((status) => status.code),
          contains(fixture.code),
          reason: '${fixture.asset}: identity failure must be reported',
        );
        expect(
          reader.validationResults.state,
          ValidationState.invalid,
          reason: '${fixture.asset}: identity failure must invalidate',
        );
      });
    }

    test('a well-formed identity assertion still validates', () async {
      final reader = await _read(
        'claim_aggregation/ica_validation/success.jpg',
      );
      expect(
        reader.validationResults.activeManifest?.failure
            .map((status) => status.code)
            .where((code) => code.startsWith('cawg.')),
        isEmpty,
      );
      expect(reader.validationResults.state, isNot(ValidationState.invalid));
    });
  });

  group('identity reports are JSON encodable', () {
    for (final asset in const [
      'claim_aggregation/ica_validation/success.jpg',
      'claim_aggregation/adobe_connected_identities.jpg',
      'validation_method/no_hard_binding.jpg',
    ]) {
      test(asset, () async {
        final reader = await _read(asset);
        // A Uri or other opaque object reaching the summary used to throw here.
        expect(() => jsonEncode(reader.toSdkJson()), returnsNormally);
      });
    }
  });
}

Future<C2paReader> _read(String relativePath) async => C2paReader.fromSource(
  source: MemoryByteSource(
    await loadFixtureBytes('$_identityRoot/$relativePath'),
  ),
  fileName: relativePath,
);

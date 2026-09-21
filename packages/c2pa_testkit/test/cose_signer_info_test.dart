@TestOn('vm')
library;

// ignore: implementation_imports
import 'package:c2pa/src/reader.dart';
import 'package:c2pa_io/c2pa_io.dart';
import 'package:c2pa_testkit/c2pa_testkit_vm.dart';
import 'package:test/test.dart';

const _vendorRoot = 'test/fixtures/vendor';

/// Signer details must be recovered from real-world COSE_Sign1 envelopes.
///
/// Every expectation below is the value reported by c2patool v0.27.22
/// (c2pa v0.90.22) for the same asset.
///
/// Two defects made these assets report a null `signature_info` and a
/// `claimSignature.mismatch` failure:
///
///  * Early C2PA producers label the certificate chain with the text string
///    `"x5chain"` instead of the RFC 9360 integer label 33. The reader splits
///    text-labeled headers out of the COSE message before parsing it, so the
///    chain was discarded and every such asset was rejected as unsigned.
///  * The COSE CBOR decoder rejected header maps whose keys were not in
///    canonical order. Map ordering is an encoding rule; signatures are
///    verified over the bytes the signer produced, so rejecting these at
///    decode time discarded otherwise valid signatures.
void main() {
  group('legacy text-labeled x5chain resolves the signer', () {
    for (final fixture in const [
      (
        asset: 'c2pa-rs-0.90.22/media/png/exp-test1.png',
        algorithm: 'ps256',
        issuer: 'Adobe Inc.',
      ),
      (
        asset: 'c2pa-public-testfiles/claim-v1/jpeg/adobe-20220124-CA.jpg',
        algorithm: 'ps256',
        issuer: 'C2PA Test Signing Cert',
      ),
    ]) {
      test(fixture.asset, () async {
        final reader = await _read(fixture.asset);
        final info = reader.activeManifest?.signatureInfo;

        expect(
          info,
          isNotNull,
          reason: '${fixture.asset}: the x5chain must be recovered',
        );
        expect(info!.algorithm, fixture.algorithm);
        expect(info.issuer, fixture.issuer);
        expect(
          reader.validationResults.activeManifest?.failure.map(
            (status) => status.code,
          ),
          isNot(contains('claimSignature.mismatch')),
          reason: '${fixture.asset}: the signature must not be unparsable',
        );
      });
    }
  });

  test('issuer reports the signing certificate organization', () async {
    // The leaf of this chain is `CN=cai-prod, O=Adobe Inc.` issued by
    // `O=Adobe Systems Incorporated`. c2pa-rs reports the subject, so reading
    // the issuing CA here would silently misattribute the signer.
    final reader = await _read('c2pa-rs-0.90.22/media/png/exp-test1.png');
    final info = reader.activeManifest!.signatureInfo!;

    expect(info.issuer, 'Adobe Inc.');
    expect(info.issuer, isNot('Adobe Systems Incorporated'));
    expect(info.commonName, 'cai-prod');
  });

  // The CMS SignedData certificate set is an unauthenticated bag that real
  // timestamp authorities emit in chain order rather than sorted DER order.
  // Enforcing SET-OF ordering while parsing rejected the token outright, so
  // every timestamped asset reported timeStamp.malformed and no signing time.
  //
  // Expectations are taken from c2pa-rs v0.90.22 `sdk/tests/known_good`,
  // vendored here as the `.expected.json` goldens.
  group('RFC 3161 timestamps validate', () {
    for (final fixture in const [
      (
        asset: 'c2pa-rs-0.90.22/media/claim-v2/CA.jpg',
        time: '2024-08-06T21:53:37.000Z',
      ),
      (
        asset: 'c2pa-rs-0.90.22/media/invalid/XCA.jpg',
        time: '2024-08-06T21:53:37.000Z',
      ),
    ]) {
      test(fixture.asset, () async {
        final reader = await _read(fixture.asset);
        final active = reader.validationResults.activeManifest!;
        final codes = {
          ...active.success.map((status) => status.code),
          ...active.informational.map((status) => status.code),
          ...active.failure.map((status) => status.code),
        };

        expect(codes, contains('timeStamp.validated'));
        expect(codes, isNot(contains('timeStamp.malformed')));
        // The SDK defaults configure no timestamp trust anchors, so upstream
        // reports the authority as untrusted, informationally, and still
        // treats the asset as valid.
        expect(codes, contains('timeStamp.untrusted'));
        expect(
          active.failure.map((status) => status.code),
          isNot(contains('timeStamp.untrusted')),
        );
        expect(
          reader.activeManifest!.signatureInfo!.time?.toUtc().toIso8601String(),
          fixture.time,
        );
      });
    }
  });
}

Future<C2paReader> _read(String relativePath) async => C2paReader.fromSource(
  source: MemoryByteSource(
    await loadFixtureBytes('$_vendorRoot/$relativePath'),
  ),
  fileName: relativePath,
);

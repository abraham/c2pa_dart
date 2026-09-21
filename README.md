# c2pa_dart

A pure Dart implementation of the Coalition for Content Provenance and
Authenticity (C2PA) SDK surface. The SDK targets Dart VM, Flutter, and the web
without wrapping or linking to Rust. Platform cryptography may be used behind
Dart package APIs.

The compatibility baseline is
[`contentauth/c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
This repository is under active development; API and compatibility status may
change before `1.0`. See
[`tool/compatibility.json`](tool/compatibility.json) for the machine-readable
feature ledger.

## Packages

| Package | Purpose |
|---|---|
| [`c2pa`](https://pub.dev/packages/c2pa) | Reader, Builder, manifests, assertions, validation, reports, resources, CAWG, archives, and signing workflows |
| [`c2pa_io`](https://pub.dev/packages/c2pa_io) | Bounded random-access memory I/O, VM file adapters, and browser `Blob` I/O |
| [`c2pa_codec`](https://pub.dev/packages/c2pa_codec) | Deterministic and preserving CBOR, ISO boxes, JUMBF, Brotli decoding, and COSE structures |
| [`c2pa_crypto`](https://pub.dev/packages/c2pa_crypto) | SHA-2, COSE algorithms, X.509 paths, trust lists, timestamps, OCSP, CRLs, and asset hashing |
| [`c2pa_formats`](https://pub.dev/packages/c2pa_formats) | C2PA extraction, mutation, remote references, and hard-binding layouts for supported formats |
| [`c2pa_testkit`](https://pub.dev/packages/c2pa_testkit) | Fixtures, mutation/property campaigns, differential testing, and performance harnesses |
| [`c2patool_dart`](https://pub.dev/packages/c2patool_dart) | Secure VM command-line workflows built only on the public package APIs |

### Publication order

Publish packages in dependency order:

1. `c2pa_io`
2. `c2pa_codec`
3. `c2pa_crypto` and `c2pa_formats` (either order after `c2pa_codec`)
4. `c2pa`
5. `c2pa_testkit` and `c2patool_dart` (either order after `c2pa`)

All workspace packages use the same prerelease version and constrain sibling
packages with the matching caret constraint. Wait for each dependency version
to become available on pub.dev before publishing its dependents. Every published
package includes `LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE` and is offered
under `MIT OR Apache-2.0`. All packages publish source links to the canonical
[`abraham/c2pa_dart`](https://github.com/abraham/c2pa_dart) repository and use
its [shared issue tracker](https://github.com/abraham/c2pa_dart/issues).

## Quick usage

Examples use in-memory bytes and the platform-neutral API. VM applications can
import `package:c2pa_io/c2pa_io_vm.dart` for `FileByteSource`; browser
applications can import `package:c2pa_io/c2pa_io_web.dart` for
`BlobByteSource`.

### Read and validate

```dart
import 'package:c2pa/c2pa.dart';

final reader = await C2paReader.fromSource(
  source: MemoryByteSource(assetBytes),
  fileName: 'image.jpg',
  context: C2paContext(),
);

final active = reader.activeManifest;
final validation = reader.validationResults;
```

`C2paContext()` performs structural and cryptographic validation without
granting trust, fetching remote manifests, or using system trust anchors.

### Build and sign

Signing keys remain caller-owned. Supply a callback backed by your key store,
HSM, platform keystore, or signing service:

```dart
import 'dart:typed_data';

import 'package:c2pa/c2pa.dart';

final signer = CallbackC2paSigner(
  algorithm: 'ed25519',
  callback: (Uint8List payload) => externalSign(payload),
);

final builder = C2paBuilder(
  definition: ManifestDefinition(
    label: 'urn:example:manifest',
    intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
    generatorInfo: ClaimGeneratorInfo(name: 'example-app', version: '1.0'),
    format: 'application/c2pa',
    instanceId: 'xmp:iid:example',
  ),
  context: C2paContext(signer: signer),
  signingAlgorithm: 'ed25519',
  x5chain: certificateChainDer,
);

final manifestStore = await builder.build();
```

Embedded Data Hash and other fixed-reservation workflows require a
`C2paReservedSizeSigner` with an exact `reservedSignatureSize`.

### Configure trust explicitly

```dart
import 'package:c2pa/c2pa.dart';

final context = C2paContext(
  trust: C2paTrustConfiguration(
    verifyTrust: true,
    trustAnchors: [trustedRootDer],
    intermediates: intermediateCertificatesDer,
  ),
);
```

Trust anchors are DER bytes supplied by the caller. The SDK does not
automatically use the operating system trust store.

### Resolve remote manifests explicitly

```dart
import 'package:c2pa/c2pa.dart';

final policy = RemoteManifestPolicy(
  enabled: true,
  allowedSchemes: const {'https'},
  allowedHosts: const {'media.example'},
  maxRedirects: 2,
  maxBytes: 8 * 1024 * 1024,
);

final context = C2paContext(
  settings: const C2paSettings(allowNetworkAccess: true),
  remoteManifestPolicy: policy,
  remoteResolver: createC2paHttpRemoteResolver(policy: policy),
);
```

No resolver is installed by default. Both a resolver and an allow policy are
required; redirects, response sizes, schemes, hosts, ports, and local-address
access remain policy controlled.

### Export reports

```dart
final sdkJson = reader.toSdkJson();
final detailedJson = reader.toDetailedJson(
  options: const C2paJsonOptions(binaryOutput: C2paBinaryOutput.base64),
);
final crJson = reader.encodeCrJson(
  options: const C2paJsonOptions(pretty: true),
);
```

SDK JSON, detailed JSON, and crJSON 2.3.0 keep structural validity,
cryptographic validity, trust, and revocation outcomes distinct.

### Save and restore a working archive

```dart
final archiveBytes = builder.toArchive();

final restored = await C2paBuilder.fromArchive(
  bytes: archiveBytes,
  context: C2paContext(signer: signer),
);
```

External archive resources require an explicit
`C2paArchiveLoadOptions.resourceResolver`. Archive paths are validated before
resource access.

### Validate a CAWG identity assertion

```dart
Future<CawgIdentityValidationResult> validateIdentity({
  required CawgIdentityAssertion assertion,
  required Iterable<ClaimHashedUri> claimAssertions,
  required C2paContext context,
}) {
  return const CawgIdentityValidator().validate(
    assertionLabel: 'cawg.identity',
    assertion: assertion,
    claimAssertions: claimAssertions,
    context: context,
  );
}
```

CAWG credential trust uses `C2paContext.cawgTrust`; DID web resolution also
requires a caller-provided resolver and policy.

## Compatibility matrix

Statuses match the compatibility ledger: **complete** means the tracked
baseline surface is implemented; **partial** means useful production paths
exist but baseline parity is not yet claimed.

| Capability | Status | Notes |
|---|---|---|
| Random-access I/O | Complete | Memory on all platforms, `RandomAccessFile` on VM, `Blob` on web |
| Deterministic CBOR, ISO boxes, JUMBF, COSE structures | Complete | Strict bounds and typed parse failures |
| Claims | Complete | Claim v1 read/validate; claim v2 create/read/validate |
| Standard assertions | Complete | Typed standard assertions plus opaque extension preservation |
| Reader | Complete | Embedded, sidecar, remote, archive, resource, CAWG, fragmented BMFF, and compressed read/validate paths |
| Builder | Complete | Standalone, sidecar, embedded, collection, fragmented BMFF, archive, dynamic assertion, and timestamp workflows |
| Compressed manifests | Partial | Bounded Brotli decode/validation is complete; generation is not implemented |
| Remote manifests | Complete | Opt-in resolver and restrictive policy required |
| Reports | Complete | SDK JSON, detailed JSON, and crJSON 2.3.0 |
| X.509, trust lists, OCSP, and CRLs | Complete | Trust and network transports remain caller configured |
| RFC 3161 timestamps | Complete | Parsing, verification, supplied tokens, and asynchronous TSA callbacks |
| CAWG identity | Complete | CAWG 1.1 plus the tracked compatibility mode |
| Working archives | Complete | Native JUMBF archives and supported legacy imports |
| CLI | Complete | Inspect, validate, extract, sign, archive, mutation, remote, and fragmented BMFF workflows |

### Asset formats

| Format | Read/extract | Write/mutate | Status and scope |
|---|---|---|---|
| Standalone C2PA | Yes | Yes | Complete |
| JPEG | Yes | Yes | Partial baseline parity |
| PNG | Yes | Yes | Partial baseline parity |
| TIFF / DNG | Yes | Yes | Partial baseline parity |
| GIF | Yes | Yes | Partial baseline parity |
| RIFF: WebP, WAV, AVI | Yes | Yes | Partial baseline parity |
| MP3 | Yes | Yes | Partial baseline parity |
| FLAC | Yes | Yes | Partial baseline parity |
| SVG | Yes | Yes | Partial baseline parity |
| ISO BMFF | Yes | Yes | Partial; includes fragmented BMFF workflows |
| JPEG XL | Yes | Yes | Partial baseline parity |
| ZIP-family documents | Yes | Yes | Partial baseline parity and collection layouts |
| PDF | Complete | Partial | Reading is complete in the ledger; mutation parity is not claimed |

### Cryptographic algorithms

| Area | Algorithms | Support |
|---|---|---|
| Hashing | SHA-256, SHA-384, SHA-512 | Digesting and C2PA hard bindings |
| ECDSA COSE | ES256, ES384, ES512 | Signing through configured backends/callbacks and verification |
| RSA-PSS COSE | PS256, PS384, PS512 | Signing through configured backends/callbacks and verification |
| EdDSA COSE | Ed25519 | Signing through configured backends/callbacks and verification |
| Certificates | X.509 path/profile validation | Explicit anchors, policies, EKUs, name constraints, and depth limits |
| Revocation/time | OCSP, CRLs, RFC 3161 | Parsing and validation; fetching/transport is opt-in |

Algorithm availability can still depend on the configured cryptographic
backend and runtime.

## Security defaults and known limitations

- Network access, remote-manifest fetching, OCSP fetching, and DID web
  resolution are disabled unless explicitly configured.
- No system trust store is consulted implicitly. Supply trust anchors or an
  explicit platform provider.
- A valid signature is not automatically trusted. Validation reports preserve
  that distinction.
- Remote policies default to deny and should use narrow HTTPS host allowlists,
  bounded redirects, and bounded response sizes.
- Resource counts, byte sizes, recursion, box counts, ingredient depth, and
  Brotli expansion are bounded by `C2paSettings`.
- Compressed C2PA manifests are decode-only in this release. Builders do not
  generate Brotli-compressed manifest stores.
- Format support marked partial should be validated against the application's
  own corpus before destructive mutation. Preserve originals when updating
  assets.
- The VM file sink stages beside its destination and commits with a filesystem
  rename. Replacement atomicity follows the host filesystem and operating
  system semantics.
- All package barrels have browser compile coverage. ISO BMFF 64-bit offsets
  use checked `BigInt` and byte-level operations so JavaScript precision does
  not alter on-wire values.
- Actual WebCrypto and browser behavior depends on the deployed browser.
- The CLI never enables network or platform trust implicitly. Flutter consumes
  the pure-Dart packages directly.

## Validation

From the repository root:

```sh
dart pub get
dart format --output=none --set-exit-if-changed packages tool
dart analyze
dart run tool/check_compatibility.dart
dart run tool/test_all.dart
(cd packages/c2pa_io && dart compile js tool/web_compile_smoke.dart -o .dart_tool/web-smoke.js)
(cd packages/c2pa_codec && dart compile js tool/web_compile_smoke.dart -o .dart_tool/web-smoke.js)
(cd packages/c2pa_crypto && dart compile js tool/web_compile_smoke.dart -o .dart_tool/web-smoke.js)
```

CI runs formatting, analysis, the compatibility ledger, and every package test
on pinned Dart for Linux, macOS, and Windows. It also runs Chrome tests and
web-safe package-barrel compiles on Linux, plus a representative Flutter stable
analysis/test job.

The conformance corpus is pinned under
`packages/c2pa_testkit/test/fixtures/vendor`. Its `provenance.json` records the
immutable upstream revision, original path, license, size, and SHA-256 digest
of every imported file. Upstream private keys are not vendored.

## License

Licensed under **MIT OR Apache-2.0**, at your option. See
[`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT), and
[`LICENSE-APACHE`](LICENSE-APACHE). Copyright is held by contributors to
c2pa_dart.

Third-party vendored material remains under its documented upstream terms.

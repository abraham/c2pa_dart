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
to become available on pub.dev before publishing its dependents.
`scripts/publish.sh` automates this ordering and waiting; see
[Releasing](#releasing). Every published
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

`x5chain` is a `List<Uint8List>` holding one DER certificate per entry, signing
certificate first, then each issuer. It is not a single concatenated DER blob.

Embedded Data Hash and other fixed-reservation workflows require a
`C2paReservedSizeSigner` with an exact `reservedSignatureSize`.

### Record ingredients

Ingredients carry the provenance of the assets a new manifest was derived from.
Reading one validates it, and its manifest store is carried into the new claim:

```dart
final parent = await BuilderIngredient.fromSource(
  source: MemoryByteSource(parentBytes),
  relationship: Relationship.parentOf,
  fileName: 'parent.jpg',
  context: C2paContext(),
);

final definition = ManifestDefinition(
  label: 'urn:example:derived',
  intent: const BuilderIntent.create(DigitalSourceType.digitalCapture),
  generatorInfo: ClaimGeneratorInfo(name: 'example-app', version: '1.0'),
  format: 'image/jpeg',
  instanceId: 'xmp:iid:derived',
  ingredients: [parent],
);
```

Use `Relationship.parentOf` for the asset being edited and
`Relationship.componentOf` for assets composited into it. Validation statuses
an ingredient already attests are reported as per-ingredient deltas rather than
being re-attributed to the active manifest.

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

### Use the command line

`c2patool_dart` exposes the same workflows without writing Dart:

```sh
dart pub global activate c2patool_dart

c2patool inspect image.jpg --format detailed --pretty
c2patool validate image.jpg
c2patool extract image.jpg --manifest-output manifest.c2pa --resources ./out
c2patool remove image.jpg --output stripped.jpg
```

The package installs an executable named `c2patool`, which is also the name of
the reference `c2pa-rs` tool; install only one of them globally, or run this
one through `dart run c2patool_dart:c2patool`.

`inspect` and `validate` report structural and cryptographic outcomes without
granting trust, and `validate` additionally exits non-zero when the asset is
invalid. Signing, archive, remote, and fragmented BMFF workflows are available
as `sign`, `archive-save`, `archive-load`, `remote`, `replace`,
`fragment-sign`, and `fragment-inspect`. Run `c2patool <command> --help` for
each command's options, including the `--trust-anchor`, `--trust-list-file`,
and bounded `--max-*` resource limits. The CLI never enables network access or
platform trust implicitly.

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
| Ingredients | Complete | Ingredient v1/v2/v3 read, build, validation deltas, and redaction |
| Compressed manifests | Partial | Bounded Brotli decode/validation is complete; generation is not implemented |
| Remote manifests | Complete | Opt-in resolver and restrictive policy required |
| Reports | Complete | SDK JSON, detailed JSON, and crJSON 2.3.0 |
| X.509, trust lists, OCSP, and CRLs | Complete | Trust and network transports remain caller configured |
| RFC 3161 timestamps | Complete | Parsing, verification, supplied tokens, and asynchronous TSA callbacks |
| CAWG identity | Complete | CAWG 1.1 plus the tracked compatibility mode |
| Working archives | Complete | Native JUMBF archives and supported legacy imports |
| CLI | Complete | Inspect, validate, extract, sign, archive, mutation, remote, and fragmented BMFF workflows |
| Testkit | Complete | Fixtures, mutation campaigns, differential runners, and the c2pa-rs conformance gate |

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
- Every package barrel that targets the web (`c2pa`, `c2pa_io`, `c2pa_codec`,
  `c2pa_crypto`, `c2pa_formats`, and `c2pa_testkit`) has browser compile
  coverage in CI. `c2patool_dart` is a VM-only CLI. ISO BMFF 64-bit offsets
  use checked `BigInt` and byte-level operations so JavaScript precision does
  not alter on-wire values.
- Actual WebCrypto and browser behavior depends on the deployed browser.
- The CLI never enables network or platform trust implicitly. Flutter consumes
  the pure-Dart packages directly.

## Validation

From the repository root:

```sh
dart pub get
dart format --output=none --set-exit-if-changed packages tool test
dart analyze
dart run tool/check_compatibility.dart
dart run tool/test_all.dart
scripts/web-compile.sh
scripts/lint-commits.sh
```

CI runs five jobs: `commits` (commit message conventions, described below),
`dart` (formatting, analysis, the compatibility ledger, shell script linting,
and every package test on pinned Dart for Linux, macOS, and Windows), `browser`
(Chrome tests and web-safe barrel compiles), `flutter` (a representative
Flutter stable analysis/test job), and `c2pa-rs conformance`, described below.

### Scripts

Anything CI does beyond a single command lives in `scripts/`, so the workflow
and a developer machine run the same code instead of two copies that drift
apart. Every script accepts `--help`, resolves paths relative to the repository
root, and can be run from any directory.

| Script | Purpose |
| --- | --- |
| `conformance.sh` | Runs the c2pa-rs conformance gate, fetching the reference build and corpus if they are not supplied |
| `fetch-oracle.sh` | Downloads, checksum-verifies, and extracts the pinned `c2patool` reference build |
| `fetch-corpus.sh` | Fetches the pinned public test corpus commit |
| `conformance-pins.sh` | Reads `conformance_pins.json` and emits the pins CI consumes |
| `web-compile.sh` | Compiles every web-targeting package barrel to JavaScript |
| `browser-test.sh` | Runs the `c2pa_crypto` browser suites on Chrome |
| `test-packages.sh` | Runs package test suites under whichever SDK is on `PATH` |
| `lint-commits.sh` | Checks that new commit messages follow Conventional Commits |
| `update-changelogs.sh` | Routes the commits made since the last release into the changelogs |
| `bump-version.sh` | Sets one version across all seven packages, their sibling constraints, and their changelogs |
| `publish.sh` | Validates and publishes the workspace to pub.dev in dependency order |

`lib.sh` holds the shared helpers and is sourced rather than executed.

### Commit messages

Commits follow [Conventional Commits
v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>[optional scope][optional !]: <description>

[optional body]

[optional footer(s)]
```

Enforcement is [commitlint](https://commitlint.js.org) rather than something
written here, because the rules are the one part of this that other projects
have already settled. It is a pinned dev dependency, so it needs an install
before first use:

```sh
npm ci
```

The `commits` CI job then runs `scripts/lint-commits.sh`:

```sh
scripts/lint-commits.sh                  # this branch against its base
scripts/lint-commits.sh --base origin/main
scripts/lint-commits.sh --range HEAD~3..HEAD
```

The rules live in `commitlint.config.mjs`, which extends
`@commitlint/config-conventional`. The types are that baseline's set, unchanged:
`build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`,
`style`, and `test`. The specification permits any noun as a type, but an open
set cannot catch `feature:` written where `feat:` was meant, which is the
mistake worth catching.

Two of the inherited defaults are stricter than the specification, and are kept
because consistency is the point: the type must be lower case, where the
specification treats types as case insensitive, and the description may not end
in a full stop, which the specification does not mention at all. The subject
limit is 100 characters, also a convention rather than a rule.

The scope is optional, but when present it must name a workspace package or the
workspace itself. Each package may be written in full or by its short form, so
`fix(c2pa_codec):` and `fix(codec):` are the same thing, and `root` covers
changes that belong to no package, such as CI, tooling, and documentation:

```
c2pa            c2pa_io      c2pa_codec   c2pa_crypto
c2pa_formats    c2pa_testkit c2patool_dart
io   codec   crypto   formats   testkit   c2patool
root
```

The specification leaves scopes open ended, but an open set here would be
worse than no set at all: the changelog tooling routes by scope, so an invented
one is accepted and then reaches the root changelog alone, which looks exactly
like it worked. Rejecting it is the only way that mistake becomes visible.

A change touching several packages may list them, using commitlint's default
delimiters, so `fix(codec,io):`, `fix(codec, io):`, and `fix(codec/io):` all
reach both packages. Every part has to name something, so `fix(codec,bogus):`
is still rejected. A change that applies to every package is better left
unscoped.

That list is not written down twice. `commitlint.config.mjs` derives it from
the `workspace:` list in `pubspec.yaml`, so adding a package cannot leave the
commit rules behind, and `test/changelog_test.dart` runs commitlint's own
resolved configuration and asserts it matches what the changelog tool will
route, so the two cannot drift apart unnoticed. The same suite runs commitlint
against sample messages, so a rule that stops working fails the build rather
than going unnoticed.

Only the commits a branch introduces are checked, measured from the merge base
with the target branch, so history predating the convention stays out of scope.
Merge commits are skipped because their messages are generated rather than
written.

Breaking changes are marked with `!` before the colon, or with an uppercase
`BREAKING CHANGE:` footer; a lower case footer token does not count, because
the specification requires that one to be uppercase.

### Changelogs

`scripts/update-changelogs.sh` collects the commits made since the most recent
release and writes them into the section for the current version. A release is
a `build` commit whose description is nothing but the version, such as
`build: 0.1.0-dev.2`, which is what the release flow below produces. Requiring
the version keeps an ordinary build change, such as `build: raise the lint
version`, from being mistaken for a boundary and truncating the next changelog.

Routing follows the scope. The root `CHANGELOG.md` receives everything. A
package changelog receives the commits that are unscoped or scoped to that
package, so `fix:` reaches every package, `fix(codec):` reaches `c2pa_codec`
and the root, `fix(codec,io):` reaches both of those, and `fix(root):` reaches
the root alone. Entries always name the package in full, whichever form the
commit used, so one package reads the same way throughout a changelog.

```sh
scripts/update-changelogs.sh --dry-run   # show what would be written
scripts/update-changelogs.sh             # write the sections
```

It refuses to overwrite a section that already has notes unless `--force` is
passed, and it plans every file before writing any of them, so a refusal leaves
the tree untouched rather than half updated. The placeholder that
`bump-version.sh` leaves behind does not count as notes.

### Releasing

`scripts/bump-version.sh <version>` updates every package version, every
sibling caret constraint, and every `CHANGELOG.md` in one step; it refuses to
run if the workspace is not already internally consistent, so a partial bump
cannot be the starting point for a release.

`scripts/publish.sh` then validates and uploads. It defaults to a dry run
because publishing is irreversible, and requires an explicit `--publish` to
upload anything:

```sh
scripts/bump-version.sh 0.1.0-dev.2   # set the version everywhere
scripts/update-changelogs.sh          # fill in the entries, then edit them
scripts/publish.sh                    # validate everything, upload nothing
scripts/publish.sh --publish --tag    # upload in dependency order, then tag
git commit -m "build: 0.1.0-dev.2"    # marks where the next changelog starts
```

It checks that all packages agree on the version, that each has a changelog
section for it, and that the working tree is clean; publishes in dependency
order; and waits for each package to become resolvable on pub.dev before
uploading its dependents. `--from <package>` resumes a partially completed
release.

## Conformance with c2pa-rs

Those tests read assets this SDK also wrote, so on their own they can only
prove self-consistency. The `c2pa-rs conformance` CI job closes that gap: it
reads a corpus signed by other producers with both this SDK and a pinned
`c2patool` reference build, and fails if any asset is reported differently.

Run it locally against the same pins. With no arguments the script fetches and
verifies the reference build and corpus itself, so this reproduces the CI job
exactly:

```sh
scripts/conformance.sh
```

Pass `--oracle` and `--corpus` to reuse copies you already have, or
`--strict-trust` to include trust-store-dependent statuses.

`tool/conformance_pins.json` is the single source of truth for the reference
build, its checksum, the corpus commit, and the number of assets each corpus
must contain; CI reads it rather than restating it. Moving a pin is a
deliberate, reviewable change to that file.

Statuses that depend on a trust store are excluded from scoring by default,
because `c2patool` ships one and the `c2pa-rs` SDK does not, so they measure
configuration rather than conformance. Pass `--strict-trust` to include them.

An asset may be exempted through `knownDivergences`, but the gate fails if an
exempted asset starts agreeing or if an entry matches no asset, so the
allowlist cannot quietly rot.

The `vendored` corpus is checked in under
`packages/c2pa_testkit/test/fixtures/vendor`. Its `provenance.json` records the
immutable upstream revision, original path, license, size, and SHA-256 digest
of every imported file, and the files are never edited in place. Upstream
private keys are not vendored.

## License

Licensed under **MIT OR Apache-2.0**, at your option. See
[`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT), and
[`LICENSE-APACHE`](LICENSE-APACHE). Copyright is held by contributors to
c2pa_dart.

Third-party vendored material remains under its documented upstream terms.

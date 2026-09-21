# c2pa_crypto

Cryptographic building blocks for C2PA: SHA-2 hashing, COSE signing and
verification adapters, X.509 path/profile validation, trust lists, RFC 3161
timestamps, OCSP, CRLs, and asset hashing.

## Platforms

The package supports Dart VM, Flutter, and web. Backend and algorithm
availability can vary by runtime; browser deployments depend on available
WebCrypto behavior.

```dart
import 'package:c2pa_crypto/c2pa_crypto.dart';

final digest = await HashAlgorithm.sha256.digest([1, 2, 3]);
print(digest.length); // 32
```

See
[`example/hash.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_crypto/example/hash.dart).

## Security and defaults

This package never fetches certificates, trust lists, timestamps, OCSP, or
CRLs by itself. Trust anchors, intermediates, validation time, revocation
material, and signing callbacks are caller supplied. A valid signature is not
equivalent to a trusted signer. Keep private keys in a platform keystore, HSM,
or external service rather than application memory where practical.

## Package relationships

`c2pa_crypto` depends on `c2pa_codec` and `c2pa_io`. The high-level `c2pa`
package uses it for claim signatures, hard bindings, trust, and revocation.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
Supported C2PA algorithms include SHA-256/384/512, ES256/384/512,
PS256/384/512, and Ed25519, subject to backend support. This package does not
provide an operating-system trust-store policy or network transport.

Licensed under **MIT OR Apache-2.0**, at your option. See
[`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_crypto/LICENSE),
[`LICENSE-MIT`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_crypto/LICENSE-MIT),
and
[`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2pa_crypto/LICENSE-APACHE).
Copyright is held by contributors to
c2pa_dart.

# c2patool_dart

`c2patool_dart` is the VM command-line companion to the pure Dart C2PA SDK.
It depends only on public workspace APIs and keeps command-line policy,
filesystem access, and subprocess handling out of the core packages.

## Platforms and installation

The CLI supports the Dart VM on macOS, Linux, and Windows. It is not a browser
or Flutter UI package. Local-key signing requires a compatible OpenSSL
executable; inspection and validation do not.

```console
dart run c2patool_dart:c2patool --help
dart run c2patool_dart:c2patool inspect photo.jpg --pretty
dart run c2patool_dart:c2patool validate photo.jpg --format crjson
dart run c2patool_dart:c2patool extract photo.jpg \
  --manifest-output photo.c2pa --resources extracted
```

## Signing

A definition is a JSON object containing `label`, `format`, `instance_id`,
and optional `title`, `claim_generator_info`, `intent`, `actions`,
`assertions`, `redactions`, `resources`, and `ingredients`. Resource and
ingredient manifest paths are resolved beneath the definition's directory and
cannot escape it. Ingredients use an `id`, an optional `version` (`1`, `2`, or
`3`), an `assertion` object accepted by `IngredientAssertion.fromCbor`, and
optional `manifest` or `manifests` paths.

```json
{
  "label": "urn:example:manifest",
  "format": "image/jpeg",
  "instance_id": "xmp:iid:example",
  "claim_generator_info": {"name": "example", "version": "1"},
  "intent": {"type": "create", "sourceType": "digitalCapture"},
  "actions": [{"action": "c2pa.created"}],
  "assertions": [
    {"label": "org.example.note", "encoding": "json", "data": {"ok": true}}
  ],
  "resources": [
    {"label": "thumbnail", "format": "image/jpeg", "path": "thumb.jpg"}
  ]
}
```

Local keys are delegated to OpenSSL without reading key material into Dart:

```console
c2patool sign --manifest manifest.json --input input.jpg --output signed.jpg \
  --key private.pem --cert leaf.pem --cert intermediate.pem --algorithm es256
```

`--openssl` accepts either an explicit absolute executable path or a bare
executable name. Bare names are resolved from absolute `PATH` entries only;
empty and relative entries are ignored, so the current directory never takes
precedence implicitly. Default signature reservations are the fixed algorithm
widths for ECDSA and Ed25519, and a conservative 512 bytes for RSA-PSS. Override
the estimate with `--reserve-size` when using RSA keys larger than 4096 bits.
Ed25519 uses `openssl pkeyutl -sign -rawin` and sends the payload directly on
stdin. OpenSSL releases that reject non-seekable one-shot Ed25519 input trigger
a narrowly matched fallback: the payload is written under a cryptographically
random, owner-only directory, verified immediately before OpenSSL starts, and
removed only while its ownership marker and contents still match. Set
the `LocalKeyC2paSigner` constructor's `ed25519TemporaryRoot` option, or the
CLI's `--ed25519-temp-root`, to place fallback directories under a
caller-controlled secure root; otherwise the operating-system temporary root
is used. The configured root must already exist and must not be a symlink.
Replaced, linked, or otherwise unverifiable paths are deliberately left in
place rather than risking deletion of an unowned file.

For an HSM or signing service, use `--signer-command` and repeatable
`--signer-arg`. The process is started directly, never through a shell. It
receives the exact signing payload on stdin, writes only the raw signature on
stdout, and may write bounded diagnostics to stderr. The environment variable
`C2PA_SIGNING_ALGORITHM` identifies the requested algorithm. Timeouts and
output limits are enforced. Use `--reserve-size` when fixed-width embedded or
fragmented workflows need a size that cannot be inferred.

Use `--sidecar` or `--no-embed` to write a standalone manifest. With
`--remote-url`, also provide `--asset-output`; URL metadata is applied before
the returned asset is hashed.

Commands never replace an existing output unless `--force` is supplied.
Input and output paths must always differ.

Working archives use `archive-save` and `archive-load`. Embedded manifests can
be changed with `remove` and `replace`, and provenance URLs with `remote`.
`fragment-sign` and `fragment-inspect` orchestrate the SDK's fragmented BMFF
APIs.

Compressed manifests can be inspected and validated, including bounded Brotli
decoding. Signing and mutation commands do not generate compressed manifest
stores, so compressed-manifest support is partial rather than full parity.

## Security policy

- Network access is off unless `--allow-network` and at least one
  `--allow-host` are supplied.
- No operating-system trust store is used. Local bounded PEM files must be
  configured explicitly with `--trust-anchor`, `--trust-list-file`,
  `--cawg-trust-anchor`, or `--cawg-trust-list-file`. Remote trust-list
  fetching is intentionally unsupported.
- An explicit `--manifest` passed to an inspection command takes precedence
  over any manifest embedded in the asset. The asset MIME type and file name
  are still used for binding validation.
- Inputs, manifests, resources, network responses, signer output, and signer
  diagnostics are bounded.
- Outputs use the SDK's staged atomic file sink. Extraction and archive
  resource paths reject absolute paths and traversal.
- Exit codes are stable: `0` success, `64` usage, `65` validation,
  `74` I/O, `75` signing, and `77` policy/network.

## Package relationships

The CLI builds on the public APIs of `c2pa`, `c2pa_io`, `c2pa_formats`, and
`c2pa_crypto`; it does not bypass SDK validation or container handling.
Applications that need an API rather than a process should depend on `c2pa`
directly.

## Compatibility and limitations

The compatibility target is
[`c2pa-rs` `c2pa-v0.90.22`](https://github.com/contentauth/c2pa-rs/tree/c2pa-v0.90.22).
Standalone C2PA support is complete for that tracked baseline, but most asset
format mutation paths have partial parity and should be tested against the
application's corpus. Compressed manifests are inspect/validate only; the CLI
does not generate Brotli-compressed stores. Remote trust-list fetching is not
implemented, and the CLI never selects a system trust store implicitly.

See
[`example/c2patool_dart.dart`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2patool_dart/example/c2patool_dart.dart)
for invoking the CLI API from Dart.

Licensed under the **MIT License** ([`LICENSE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2patool_dart/LICENSE)).
As an alternative, you may instead use this package under the **Apache
License, Version 2.0**
([`LICENSE-APACHE`](https://github.com/abraham/c2pa_dart/blob/main/packages/c2patool_dart/LICENSE-APACHE)), so the package is offered
as `MIT OR Apache-2.0`, at your option. Copyright is held by contributors to
c2pa_dart.

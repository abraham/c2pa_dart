# Vendored Brotli decoder

This directory contains a locally adapted copy of the pure-Dart Brotli
decoder from [`tiagohm/brotli`](https://github.com/tiagohm/brotli), commit
`6e241e59831600b5e468620b2a35ba62205fd3bf`.

Copyright © 2019–2023 tiagohm. The source is licensed under the MIT License;
see [`LICENSE`](LICENSE).

The c2pa_codec adaptation:

- adds Dart 3 type annotations required by strict analysis;
- adds an internal bounded-output decode entry point;
- exposes no upstream codec or streaming API publicly.

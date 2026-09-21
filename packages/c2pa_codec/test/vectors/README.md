# Brotli test-vector provenance

The dictionary-word vector in `brotli_test.dart` is copied from the tests in
[`tiagohm/brotli`](https://github.com/tiagohm/brotli) commit
`6e241e59831600b5e468620b2a35ba62205fd3bf`. It is covered by the MIT license
retained at `lib/src/brotli_vendor/LICENSE`.

The generic text, repeated-output, and JUMBF vectors were generated from their
literal uncompressed bytes using the reference Brotli command-line encoder at
quality 11. Their expected uncompressed forms are constructed or stated
directly in the tests.

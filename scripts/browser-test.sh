#!/usr/bin/env bash
# Runs the c2pa_crypto test suites that must also pass in a browser.
#
# These cover the code whose behaviour differs most between the VM and the web:
# PointyCastle backends, certificate handling, and the network-facing revocation
# and timestamp parsers.
#
# Usage:
#   scripts/browser-test.sh [--platform <platform>]

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

platform='chrome'
while [ $# -gt 0 ]; do
  case "$1" in
    --platform)
      [ $# -ge 2 ] || die '--platform requires a value'
      platform="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,10p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Listed explicitly rather than running the whole suite: the remaining
# c2pa_crypto tests depend on dart:io and cannot run in a browser.
readonly SUITES=(
  test/asset_hash_test.dart
  test/crl_test.dart
  test/ocsp_test.dart
  test/path_validation_test.dart
  test/timestamp_test.dart
  test/trust_list_test.dart
  test/pointycastle_backend_test.dart
  test/x509_certificate_test.dart
)

cd "${REPO_ROOT}/packages/c2pa_crypto" || die 'cannot enter packages/c2pa_crypto'
for suite in "${SUITES[@]}"; do
  [ -f "${suite}" ] || die "missing browser suite: ${suite}"
done

log "running ${#SUITES[@]} c2pa_crypto suites on ${platform}"
# Run suites sequentially (-j 1): pointycastle_backend_test.dart does
# multiple RSA-PSS key generations, which is CPU-heavy under dart2js and
# can starve other suites' shared browser event loop long enough to trip
# package:test's suite-load timeout when run concurrently.
exec dart test --platform "${platform}" -j 1 "${SUITES[@]}"

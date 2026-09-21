#!/usr/bin/env bash
# Runs the c2pa-rs conformance gate.
#
# Reads a corpus signed by other producers with both this SDK and a pinned
# c2patool reference build, and fails if any asset is reported differently.
# Every other test in this repository reads assets this SDK also wrote, so this
# is the only check that catches the SDK agreeing with itself while disagreeing
# with the specification.
#
# Usage:
#   scripts/conformance.sh [--oracle <path>] [--corpus <path>]
#                          [--json <path>] [--strict-trust]
#
# The oracle and corpus are downloaded automatically when not supplied, so a
# bare `scripts/conformance.sh` is enough to reproduce CI locally.

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

oracle=''
corpus=''
json=''
strict_trust=''
while [ $# -gt 0 ]; do
  case "$1" in
    --oracle)
      [ $# -ge 2 ] || die '--oracle requires a value'
      oracle="$2"
      shift 2
      ;;
    --corpus)
      [ $# -ge 2 ] || die '--corpus requires a value'
      corpus="$2"
      shift 2
      ;;
    --json)
      [ $# -ge 2 ] || die '--json requires a value'
      json="$2"
      shift 2
      ;;
    --strict-trust)
      strict_trust='--strict-trust'
      shift
      ;;
    -h | --help)
      sed -n '2,16p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${oracle}" ] || oracle="$("$(dirname "${BASH_SOURCE[0]}")/fetch-oracle.sh")"
[ -n "${corpus}" ] || corpus="$("$(dirname "${BASH_SOURCE[0]}")/fetch-corpus.sh")"

vendored="$(pin '.corpora.vendored.path')"

cd "${REPO_ROOT}/packages/c2pa_testkit" || die 'cannot enter packages/c2pa_testkit'
exec dart run tool/conformance.dart \
  --oracle "${oracle}" \
  --corpus "public=${corpus}" \
  --corpus "vendored=${vendored}" \
  ${json:+--json "${json}"} \
  ${strict_trust}

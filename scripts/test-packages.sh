#!/usr/bin/env bash
# Runs package test suites under whichever SDK is on PATH.
#
# Used by the Flutter job to confirm the pure-Dart packages still resolve and
# pass when a Flutter SDK supplies the Dart toolchain. c2pa_testkit and
# c2patool_dart are excluded by default because they are development tooling
# rather than part of the consumer-facing surface that job checks.
#
# Usage:
#   scripts/test-packages.sh [package...]

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

packages=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      sed -n '2,11p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    -*) die "unknown argument: $1" ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done

if [ ${#packages[@]} -eq 0 ]; then
  packages=(c2pa_io c2pa_codec c2pa_crypto c2pa_formats c2pa)
fi

failed=()
for package in "${packages[@]}"; do
  directory="${REPO_ROOT}/packages/${package}"
  [ -d "${directory}" ] || die "no such package: ${package}"
  log "testing ${package}"
  # Keep going so one failure does not hide the state of the rest.
  if ! (cd "${directory}" && dart test); then
    failed+=("${package}")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  die "failing package(s): ${failed[*]}"
fi

log "tested ${#packages[@]} package(s)"

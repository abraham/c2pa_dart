#!/usr/bin/env bash
# Compiles every web-targeting package barrel to JavaScript.
#
# Guards the web support claimed in the README. A dart:io import pulled into
# the c2pa or c2pa_formats barrel would otherwise break web consumers with
# nothing in the test suite to catch it, because the tests run on the VM.
#
# Usage:
#   scripts/web-compile.sh [package...]

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

packages=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      sed -n '2,10p' "${BASH_SOURCE[0]}"
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
  packages=("${C2PA_WEB_PACKAGES[@]}")
fi

for package in "${packages[@]}"; do
  smoke="${REPO_ROOT}/packages/${package}/tool/web_compile_smoke.dart"
  [ -f "${smoke}" ] || die "${package} has no tool/web_compile_smoke.dart"
  log "compiling ${package} barrel to JavaScript"
  (
    cd "${REPO_ROOT}/packages/${package}" || die "cannot enter ${package}"
    dart compile js tool/web_compile_smoke.dart \
      -o .dart_tool/ci/web_compile_smoke.js
  )
done

log "compiled ${#packages[@]} package barrel(s)"

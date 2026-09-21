#!/usr/bin/env bash
# Emits the conformance pins as `key=value` lines.
#
# The pins file is the single source of truth for what this SDK is compared
# against, so CI reads it through this script rather than restating the values
# in the workflow, where they could silently drift.
#
# Usage:
#   scripts/conformance-pins.sh [--target <oracle-target>]
#
# In CI the output is appended to $GITHUB_OUTPUT; locally it goes to stdout,
# which also makes it usable as `eval "$(scripts/conformance-pins.sh)"`.

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

target=''
while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      [ $# -ge 2 ] || die '--target requires a value'
      target="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,12p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${target}" ] || target="$(host_oracle_target)"

if ! pin_archive "${target}" asset >/dev/null 2>&1; then
  die "no oracle archive pinned for target '${target}'"
fi

emit() {
  printf '%s=%s\n' "$1" "$2"
}

{
  emit target "${target}"
  emit version "$(pin '.oracle.version')"
  emit tag "$(pin '.oracle.releaseTag')"
  emit asset "$(pin_archive "${target}" asset)"
  emit sha256 "$(pin_archive "${target}" sha256)"
  emit binary "$(pin_archive "${target}" binaryPath)"
  emit binarysha "$(pin_archive "${target}" binarySha256)"
  emit repository "$(pin '.corpora.public.repository')"
  emit commit "$(pin '.corpora.public.commit')"
  emit vendored "$(pin '.corpora.vendored.path')"
} >>"${GITHUB_OUTPUT:-/dev/stdout}"

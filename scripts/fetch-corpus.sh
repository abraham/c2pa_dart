#!/usr/bin/env bash
# Checks out the pinned public C2PA test corpus.
#
# Fetches only the pinned commit: the corpus is large and its history is
# irrelevant to the gate. Re-running is cheap because an existing checkout at
# the right commit is left alone.
#
# Usage:
#   scripts/fetch-corpus.sh [--dir <path>]
#
# Prints the absolute path of the checkout on stdout.

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir=''
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      [ $# -ge 2 ] || die '--dir requires a value'
      dir="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,12p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${dir}" ] || dir="$(work_dir)/corpus"

require_command git

repository="$(pin '.corpora.public.repository')"
commit="$(pin '.corpora.public.commit')"

if [ "$(git -C "${dir}" rev-parse HEAD 2>/dev/null || true)" = "${commit}" ]; then
  log "reusing corpus checkout at ${commit}"
  (cd "${dir}" && pwd)
  exit 0
fi

log "fetching corpus ${commit}"
rm -rf "${dir}"
mkdir -p "${dir}"
git -C "${dir}" init --quiet .
git -C "${dir}" remote add origin "${repository}"
git -C "${dir}" fetch --quiet --depth 1 origin "${commit}"
git -C "${dir}" checkout --quiet FETCH_HEAD

(cd "${dir}" && pwd)

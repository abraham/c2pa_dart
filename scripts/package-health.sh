#!/usr/bin/env bash
# Validates every package the way pub.dev will, before anything is published.
#
# Two checks the `dart` job cannot make. `dart pub publish --dry-run` validates
# the archive pub.dev would actually receive, and pana scores the package with
# pub.dev's own scoring library. Neither is implied by a clean analyze: an
# example named something pana does not look for, or a LICENSE file holding a
# dual-license pointer rather than license text, are both invisible to the
# analyzer and both silently cost points on the published page.
#
# Only the sections that can be scored before the first release are enforced.
# Sibling packages are constrained against pub.dev, so until `c2pa_io` and the
# rest are live, pana cannot resolve a dependent and `platform`, `analysis`,
# and `dependency` fail for reasons that say nothing about this commit. They
# are printed but not gated; the `dart` job already covers that ground locally,
# and `scripts/publish.sh` re-checks everything at release.
#
# `dart pub publish --dry-run` treats a modified checked-in file as a warning
# and warnings exit non-zero, so on a dirty tree it reports the tree rather
# than the package. That half is skipped when the tree is dirty, which costs
# nothing on CI and leaves the pana half usable while editing.
#
# Usage:
#   scripts/package-health.sh [package...]
#
# Examples:
#   scripts/package-health.sh            # every workspace package
#   scripts/package-health.sh c2pa_io    # just one

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

# Sections whose score cannot depend on a sibling being live on pub.dev.
readonly REQUIRED_SECTIONS=(convention documentation)

packages=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      sed -n '2,29p' "${BASH_SOURCE[0]}"
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
  packages=("${C2PA_PACKAGES[@]}")
fi

require_command dart
require_command jq

cd "${REPO_ROOT}" || die 'cannot enter the repository root'

# See the note at the top: a dirty tree makes the dry run report the tree.
dry_run='yes'
if [ -n "$(git status --porcelain)" ]; then
  dry_run=''
  log 'working tree is dirty; skipping publish --dry-run, running pana only'
fi

# pana is a scoring tool rather than a dependency of the workspace, so it is
# activated on demand instead of being pinned into a pubspec.
if ! dart pub global list 2>/dev/null | grep -q '^pana '; then
  log 'activating pana'
  dart pub global activate pana >/dev/null
fi

report_dir="$(mktemp -d)"
trap 'rm -rf "${report_dir}"' EXIT

failed=()

for package in "${packages[@]}"; do
  [ -d "packages/${package}" ] || die "no such package: packages/${package}"

  # Exits 65 on warnings, not just errors, so a stale pubspec or a missing
  # LICENSE fails here rather than on the day someone runs publish.sh.
  if [ -n "${dry_run}" ]; then
    log "publish dry run: ${package}"
    if ! dart pub publish --dry-run --directory "packages/${package}"; then
      failed+=("${package} (publish --dry-run)")
      continue
    fi
  fi

  # --no-dartdoc keeps this to the checks being gated. Dartdoc coverage is
  # scored by pub.dev but is not enforced here, and running it would add
  # minutes per package for a number this script ignores.
  #
  # pana writes its resolution log to stderr, and on a package it cannot
  # resolve that is megabytes of solver trace. It is kept next to the report
  # and only shown when this package actually fails.
  log "pana: ${package}"
  report="${report_dir}/${package}.json"
  pana_log="${report_dir}/${package}.log"
  if ! dart pub global run pana \
    --no-warning \
    --no-dartdoc \
    --project-root "${REPO_ROOT}" \
    --json "packages/${package}" >"${report}" 2>"${pana_log}"; then
    tail -n 20 "${pana_log}" >&2
    failed+=("${package} (pana did not complete)")
    continue
  fi

  if ! jq -e '.report.sections' "${report}" >/dev/null 2>&1; then
    failed+=("${package} (pana produced no report)")
    continue
  fi

  jq -r '.report.sections[]
    | "    \(.grantedPoints)/\(.maxPoints)  \(.id)  \(.title)"' "${report}" >&2

  # Report every failing required section at once; fixing them one CI run at a
  # time is the slowest possible way to learn what pub.dev thinks.
  short=''
  for section in "${REQUIRED_SECTIONS[@]}"; do
    if ! jq -e --arg s "${section}" \
      '.report.sections[] | select(.id == $s)' "${report}" >/dev/null 2>&1; then
      die "pana reported no '${section}' section for ${package}"
    fi
    if ! jq -e --arg s "${section}" \
      '.report.sections[]
       | select(.id == $s)
       | select(.grantedPoints >= .maxPoints)' "${report}" >/dev/null 2>&1; then
      short="yes"
      printf 'error: %s scored below maximum on the %s section:\n' \
        "${package}" "${section}" >&2
      jq -r --arg s "${section}" \
        '.report.sections[] | select(.id == $s) | .summary' "${report}" >&2
    fi
  done
  [ -z "${short}" ] || failed+=("${package} (pana)")
done

if [ ${#failed[@]} -gt 0 ]; then
  for entry in "${failed[@]}"; do
    printf 'error: %s\n' "${entry}" >&2
  done
  die "${#failed[@]} package check(s) failed"
fi

log "validated ${#packages[@]} package(s)"

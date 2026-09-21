#!/usr/bin/env bash
# Checks that commit messages follow Conventional Commits v1.0.0.
#
# Only the commits a change actually introduces are checked, never the whole
# history: the rules were adopted partway through the project, so rewriting
# published history is not an option and older commits are out of scope.
#
# The range is resolved from the GitHub event when one is present, and from the
# default branch otherwise, so a local run checks the same commits CI will.
#
# Usage:
#   scripts/lint-commits.sh [--range <range>] [--base <ref>] [--] [dart args...]
#
# Examples:
#   scripts/lint-commits.sh                     # this branch against its base
#   scripts/lint-commits.sh --range HEAD~3..HEAD
#   scripts/lint-commits.sh --base origin/main

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

range=''
base=''
passthrough=()
while [ $# -gt 0 ]; do
  case "$1" in
    --range)
      [ $# -ge 2 ] || die '--range requires a value'
      range="$2"
      shift 2
      ;;
    --base)
      [ $# -ge 2 ] || die '--base requires a value'
      base="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,18p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    --)
      shift
      passthrough+=("$@")
      break
      ;;
    *)
      passthrough+=("$1")
      shift
      ;;
  esac
done

require_command git
require_command dart

cd "${REPO_ROOT}" || die 'cannot enter the repository root'

[ -z "${range}" ] || [ -z "${base}" ] || die 'pass either --range or --base, not both'

# True when the argument names something git can resolve to a commit.
resolves() {
  git rev-parse --verify --quiet "$1^{commit}" >/dev/null 2>&1
}

if [ -z "${range}" ]; then
  if [ -z "${base}" ]; then
    if [ -n "${GITHUB_BASE_REF:-}" ]; then
      # Pull request: everything this branch adds on top of the target branch.
      base="origin/${GITHUB_BASE_REF}"
    elif [ -n "${GITHUB_EVENT_BEFORE:-}" ] &&
      [ "${GITHUB_EVENT_BEFORE}" != "0000000000000000000000000000000000000000" ] &&
      resolves "${GITHUB_EVENT_BEFORE}"; then
      # Push to an existing branch: exactly the commits being pushed. A new
      # branch reports an all-zero "before" and a force push can report a commit
      # that is no longer reachable, so both fall through to the default branch.
      base="${GITHUB_EVENT_BEFORE}"
    else
      for candidate in origin/main origin/master main master; do
        if resolves "${candidate}"; then
          base="${candidate}"
          break
        fi
      done
    fi
  fi

  if [ -z "${base}" ]; then
    die 'could not determine a base revision; pass --range or --base'
  fi

  resolves "${base}" || die "base revision does not exist: ${base}
Fetch it first, for example: git fetch origin ${base#origin/}"

  # The merge base, not the branch tip, so commits already on the base branch
  # are not re-checked when the branch is behind.
  merge_base="$(git merge-base "${base}" HEAD 2>/dev/null || true)"
  if [ -z "${merge_base}" ]; then
    die "no common ancestor between ${base} and HEAD; the history may be shallow.
Check out with fetch-depth: 0 or pass an explicit --range."
  fi

  if [ "${merge_base}" = "$(git rev-parse HEAD)" ]; then
    log 'no commits to check; HEAD is already contained in the base'
    exit 0
  fi

  range="${merge_base}..HEAD"
fi

log "checking commits in ${range}"
dart run tool/lint_commits.dart --range "${range}" "${passthrough[@]}"

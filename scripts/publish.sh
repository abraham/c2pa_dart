#!/usr/bin/env bash
# Publishes the workspace to pub.dev in dependency order.
#
# Defaults to a dry run. Publishing is effectively irreversible, so actually
# uploading requires an explicit --publish.
#
# Packages must go up in dependency order and each one must be live before its
# dependents are uploaded, because pub resolves the sibling caret constraints
# against pub.dev rather than against the local workspace.
#
# Usage:
#   scripts/publish.sh [--publish] [--skip-checks] [--tag] [--from <package>]
#
# Examples:
#   scripts/publish.sh                 # validate everything, upload nothing
#   scripts/publish.sh --publish --tag # upload, then tag the release
#   scripts/publish.sh --publish --from c2pa   # resume a partial release

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

publish=''
skip_checks=''
tag=''
from=''
while [ $# -gt 0 ]; do
  case "$1" in
    --publish)
      publish='yes'
      shift
      ;;
    --skip-checks)
      skip_checks='yes'
      shift
      ;;
    --tag)
      tag='yes'
      shift
      ;;
    --from)
      [ $# -ge 2 ] || die '--from requires a value'
      from="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,19p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_command dart
require_command git
require_command curl
require_command jq

# An unrecognised --from would skip every package and report success, so it is
# checked before anything else runs.
if [ -n "${from}" ]; then
  matched=''
  for package in "${C2PA_PACKAGES[@]}"; do
    [ "${package}" = "${from}" ] && matched='yes'
  done
  [ -n "${matched}" ] || die "--from ${from} is not a workspace package"
fi

cd "${REPO_ROOT}" || die 'cannot enter the repository root'

version="$(grep -m1 '^version: ' packages/c2pa/pubspec.yaml | awk '{print $2}')"
[ -n "${version}" ] || die 'could not read the workspace version'

for package in "${C2PA_PACKAGES[@]}"; do
  found="$(grep -m1 '^version: ' "packages/${package}/pubspec.yaml" | awk '{print $2}')"
  [ "${found}" = "${version}" ] ||
    die "${package} is ${found}, expected ${version}; run scripts/bump-version.sh"
done

# An unreleased CHANGELOG section is a pub.dev warning and, more importantly,
# means nobody wrote down what changed.
for package in "${C2PA_PACKAGES[@]}"; do
  grep -q "^## ${version}\$" "packages/${package}/CHANGELOG.md" ||
    die "packages/${package}/CHANGELOG.md has no '## ${version}' section"
done

if [ -n "$(git status --porcelain)" ]; then
  die 'the working tree is dirty; commit or stash before publishing'
fi

log "publishing version ${version}"

if [ -z "${skip_checks}" ]; then
  log 'running workspace checks'
  dart pub get >/dev/null
  dart format --output=none --set-exit-if-changed packages tool scripts >/dev/null
  dart analyze
  dart run tool/check_compatibility.dart
  dart run tool/test_all.dart
else
  log 'skipping workspace checks'
fi

# True when pub.dev already serves this version of a package.
published() {
  local package="$1"
  curl --fail --silent --show-error --location \
    "https://pub.dev/api/packages/${package}" 2>/dev/null |
    jq -e --arg v "${version}" '.versions[]?.version | select(. == $v)' >/dev/null 2>&1
}

# pub.dev needs a moment before a freshly uploaded version can be resolved as a
# dependency, so dependents wait rather than failing to resolve.
await_publication() {
  local package="$1" attempt=0
  while [ "${attempt}" -lt 60 ]; do
    if published "${package}"; then
      log "${package} ${version} is live"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 10
  done
  die "${package} ${version} did not appear on pub.dev within 10 minutes"
}

started=''
[ -n "${from}" ] || started='yes'

for package in "${C2PA_PACKAGES[@]}"; do
  if [ -z "${started}" ]; then
    if [ "${package}" = "${from}" ]; then
      started='yes'
    else
      log "skipping ${package} (before --from ${from})"
      continue
    fi
  fi

  if published "${package}"; then
    log "${package} ${version} is already published, skipping"
    continue
  fi

  if [ -z "${publish}" ]; then
    log "dry run: ${package}"
    dart pub publish --dry-run --directory "packages/${package}"
    continue
  fi

  log "publishing ${package}"
  dart pub publish --force --directory "packages/${package}"
  await_publication "${package}"
done

if [ -z "${publish}" ]; then
  log "dry run complete; re-run with --publish to upload ${version}"
  [ -z "${tag}" ] || log 'note: --tag has no effect in a dry run'
  exit 0
fi

if [ -n "${tag}" ]; then
  if git rev-parse "v${version}" >/dev/null 2>&1; then
    log "tag v${version} already exists"
  else
    git tag -a "v${version}" -m "c2pa_dart ${version}"
    log "created tag v${version}; push it with: git push origin v${version}"
  fi
fi

log "published ${version}"

#!/usr/bin/env bash
# Sets one version across every package in the workspace.
#
# All seven packages share a version and constrain their siblings with the
# matching caret, so a partial bump produces a workspace that resolves locally
# but is unpublishable. This updates every place the version appears at once:
#
#   * the `version:` field of each package
#   * every sibling `^<version>` dependency constraint
#   * a new CHANGELOG section per package
#
# Usage:
#   scripts/bump-version.sh <version> [--allow-downgrade] [--no-changelog]
#
# Example:
#   scripts/bump-version.sh 0.1.0-dev.2

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

version=''
allow_downgrade=''
write_changelog='yes'
while [ $# -gt 0 ]; do
  case "$1" in
    --allow-downgrade)
      allow_downgrade='yes'
      shift
      ;;
    --no-changelog)
      write_changelog=''
      shift
      ;;
    -h | --help)
      sed -n '2,17p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    -*) die "unknown argument: $1" ;;
    *)
      [ -z "${version}" ] || die 'only one version may be given'
      version="$1"
      shift
      ;;
  esac
done

[ -n "${version}" ] || die 'usage: scripts/bump-version.sh <version>'

# Semantic version with an optional prerelease, which is the shape pub accepts
# and the shape a caret constraint can be built from.
if ! printf '%s' "${version}" |
  grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  die "not a valid semantic version: ${version}"
fi

current="$(grep -m1 '^version: ' "${REPO_ROOT}/packages/c2pa/pubspec.yaml" | awk '{print $2}')"
[ -n "${current}" ] || die 'could not read the current version'

# Every package must already agree, otherwise the "current" version being
# replaced is a guess and some constraints would be left behind.
for package in "${C2PA_PACKAGES[@]}"; do
  found="$(grep -m1 '^version: ' "${REPO_ROOT}/packages/${package}/pubspec.yaml" | awk '{print $2}')"
  [ "${found}" = "${current}" ] ||
    die "packages disagree on the current version: c2pa is ${current}, ${package} is ${found}"
done

# Sibling constraints must already match for the same reason. One pinned at
# some other version survives the rewrite untouched and then surfaces only as
# an opaque resolution failure, after every file has already been modified.
for package in "${C2PA_PACKAGES[@]}"; do
  pubspec="${REPO_ROOT}/packages/${package}/pubspec.yaml"
  while IFS= read -r line; do
    constraint="${line##*: ^}"
    [ "${constraint}" = "${current}" ] ||
      die "${package} constrains a sibling at ^${constraint}, not ^${current}:${line}"
  done < <(grep -E '^  (c2pa|c2pa_[a-z_]+|c2patool_dart): \^' "${pubspec}" || true)
done

[ "${version}" != "${current}" ] || die "already at ${version}"

if [ -z "${allow_downgrade}" ]; then
  lowest="$(printf '%s\n%s\n' "${current}" "${version}" | sort -V | head -1)"
  if [ "${lowest}" = "${version}" ]; then
    die "${version} is not newer than ${current}; pass --allow-downgrade to override"
  fi
fi

log "bumping ${current} -> ${version}"

for package in "${C2PA_PACKAGES[@]}"; do
  pubspec="${REPO_ROOT}/packages/${package}/pubspec.yaml"

  # Anchored so only the package's own version is touched, never a dependency
  # constraint that happens to contain the same string.
  python3 - "${pubspec}" "${current}" "${version}" <<'PY'
import re
import sys

path, current, version = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as handle:
    text = handle.read()

updated, count = re.subn(
    rf'^version: {re.escape(current)}$',
    f'version: {version}',
    text,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f'{path}: expected one version field, replaced {count}')

# Sibling constraints only: an unrelated dependency pinned at the same version
# must not be rewritten.
updated, _ = re.subn(
    rf'^(  (?:c2pa|c2pa_[a-z_]+|c2patool_dart): \^){re.escape(current)}$',
    rf'\g<1>{version}',
    updated,
    flags=re.MULTILINE,
)

with open(path, 'w') as handle:
    handle.write(updated)
PY

  if [ -n "${write_changelog}" ]; then
    changelog="${REPO_ROOT}/packages/${package}/CHANGELOG.md"
    if grep -q "^## ${version}\$" "${changelog}" 2>/dev/null; then
      log "${package}: CHANGELOG already has ${version}"
    else
      printf '## %s\n\n- Describe the changes in this release.\n\n%s' \
        "${version}" "$(cat "${changelog}")" >"${changelog}.tmp"
      mv "${changelog}.tmp" "${changelog}"
    fi
  fi
done

# Leaving a stale lockfile behind would make the next command resolve against
# the previous version.
log 'refreshing the workspace lockfile'
(cd "${REPO_ROOT}" && dart pub get >/dev/null)

remaining="$(grep -rln "\^${current}\$" "${REPO_ROOT}"/packages/*/pubspec.yaml 2>/dev/null || true)"
[ -z "${remaining}" ] || die "sibling constraints still reference ${current}:
${remaining}"

log "every package is now ${version}"
if [ -n "${write_changelog}" ]; then
  log 'edit each CHANGELOG.md before publishing'
fi

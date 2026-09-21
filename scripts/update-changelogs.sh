#!/usr/bin/env bash
# Adds the commits made since the last release to the changelogs.
#
# The range starts after the newest release commit, which is a `build` commit
# whose description is just the version, such as `build: 0.1.0-dev.2`. That is
# what marks where the previous changelog stopped.
#
# The root CHANGELOG.md receives every commit. A package changelog receives the
# commits that are unscoped or scoped to that package, so `fix(codec):` reaches
# c2pa_codec and the root, `fix:` reaches everything, and `ci(ci):` reaches the
# root alone.
#
# Entries are written into the section for the current workspace version, which
# scripts/bump-version.sh creates. The usual order is bump, then this, then
# edit whatever needs a human sentence.
#
# Usage:
#   scripts/update-changelogs.sh [--dry-run] [--force]
#                                [--since <ref>] [--version <version>]
#
# Examples:
#   scripts/update-changelogs.sh --dry-run    # show what would be written
#   scripts/update-changelogs.sh              # write the sections
#   scripts/update-changelogs.sh --since v0.1.0-dev.1

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
  -h | --help)
    sed -n '2,24p' "${BASH_SOURCE[0]}"
    exit 0
    ;;
esac

require_command git
require_command dart

cd "${REPO_ROOT}" || die 'cannot enter the repository root'

dart run tool/update_changelogs.dart "$@"

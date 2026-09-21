#!/usr/bin/env bash
# Shared helpers for the scripts in this directory.
#
# Sourced, never executed. Every script here is expected to work both on a CI
# runner and on a developer machine, so anything platform-specific belongs in
# here rather than being repeated with a subtle difference each time.

set -euo pipefail

# Absolute path to the repository root, regardless of the caller's directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT

readonly CONFORMANCE_PINS="${REPO_ROOT}/packages/c2pa_testkit/tool/conformance_pins.json"

log() {
  printf '==> %s\n' "$*" >&2
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but was not found on PATH"
}

# Prints the SHA-256 of a file.
#
# GNU coreutils and macOS ship different tools for this, and the conformance
# oracle is checksum-verified on both, so the difference is resolved once here.
sha256_of() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    die 'neither sha256sum nor shasum is available'
  fi
}

# Fails unless a file matches an expected SHA-256.
verify_sha256() {
  local expected="$1" file="$2" actual
  [ -f "$file" ] || die "cannot verify missing file: $file"
  actual="$(sha256_of "$file")"
  if [ "$actual" != "$expected" ]; then
    die "checksum mismatch for ${file}
  expected ${expected}
  actual   ${actual}"
  fi
}

# The release target matching the current machine.
#
# The oracle is a per-platform binary, so the pins file records one archive per
# target and callers resolve the right one instead of hardcoding Linux.
host_oracle_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}" in
    Darwin) echo 'universal-apple-darwin' ;;
    Linux)
      case "${arch}" in
        x86_64 | amd64) echo 'x86_64-unknown-linux-gnu' ;;
        *) die "no pinned c2patool build for Linux ${arch}" ;;
      esac
      ;;
    *) die "no pinned c2patool build for ${os}" ;;
  esac
}

# Reads one value out of the conformance pins file.
pin() {
  require_command jq
  jq -re "$1" "${CONFORMANCE_PINS}"
}

# Reads one value for a specific oracle target.
pin_archive() {
  local target="$1" field="$2"
  require_command jq
  jq -re --arg t "${target}" --arg f "${field}" '.oracle.archives[$t][$f]' \
    "${CONFORMANCE_PINS}"
}

# Where downloaded build inputs are kept.
#
# Honours RUNNER_TEMP so CI can cache the directory between runs, and falls
# back to a gitignored path locally.
work_dir() {
  echo "${CONFORMANCE_WORK_DIR:-${RUNNER_TEMP:-${REPO_ROOT}/.dart_tool/conformance}}"
}

# Packages in dependency order: every package appears after everything it
# depends on. Publishing and per-package loops both rely on this order.
# shellcheck disable=SC2034  # used by the scripts that source this file
readonly C2PA_PACKAGES=(
  c2pa_io
  c2pa_codec
  c2pa_crypto
  c2pa_formats
  c2pa
  c2pa_testkit
  c2patool_dart
)

# Packages whose barrels are expected to compile for the web.
# c2patool_dart is a VM-only CLI and is deliberately absent.
# shellcheck disable=SC2034  # used by the scripts that source this file
readonly C2PA_WEB_PACKAGES=(
  c2pa_io
  c2pa_codec
  c2pa_crypto
  c2pa_formats
  c2pa
  c2pa_testkit
)

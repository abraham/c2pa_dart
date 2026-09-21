#!/usr/bin/env bash
# Ensures a checksum-verified c2patool reference build is available.
#
# Downloads the pinned release archive when it is missing, then verifies the
# extracted binary. The verification is unconditional and deliberately so: CI
# restores this directory from a workflow cache, and a workflow cache is
# writable from any branch, so a restored binary is not trusted until it has
# been checked against the pin.
#
# Usage:
#   scripts/fetch-oracle.sh [--dir <path>] [--target <oracle-target>]
#
# Prints the absolute path of the verified binary on stdout.

# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir=''
target=''
while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      [ $# -ge 2 ] || die '--dir requires a value'
      dir="$2"
      shift 2
      ;;
    --target)
      [ $# -ge 2 ] || die '--target requires a value'
      target="$2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,13p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${target}" ] || target="$(host_oracle_target)"
[ -n "${dir}" ] || dir="$(work_dir)/oracle"

require_command curl

tag="$(pin '.oracle.releaseTag')"
asset="$(pin_archive "${target}" asset)"
archive_sha="$(pin_archive "${target}" sha256)"
binary_path="$(pin_archive "${target}" binaryPath)"
binary_sha="$(pin_archive "${target}" binarySha256)"

mkdir -p "${dir}"
binary="${dir}/${binary_path}"

if [ ! -f "${binary}" ]; then
  archive="${dir}/${asset}"
  log "downloading ${asset}"
  curl --fail --silent --show-error --location --retry 3 \
    -o "${archive}" \
    "https://github.com/contentauth/c2pa-rs/releases/download/${tag}/${asset}"

  # Verify the archive before unpacking it, so nothing unexpected is ever
  # written to disk.
  verify_sha256 "${archive_sha}" "${archive}"

  case "${asset}" in
    *.tar.gz) tar -xzf "${archive}" -C "${dir}" ;;
    *.zip)
      require_command unzip
      unzip -q -o "${archive}" -d "${dir}"
      ;;
    *) die "unsupported archive format: ${asset}" ;;
  esac
  rm -f "${archive}"
else
  log "reusing cached c2patool"
fi

verify_sha256 "${binary_sha}" "${binary}"
chmod +x "${binary}"

log "verified c2patool $(pin '.oracle.version') (${target})"
echo "${binary}"

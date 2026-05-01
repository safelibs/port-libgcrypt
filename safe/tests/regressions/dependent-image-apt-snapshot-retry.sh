#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DEPENDENT_IMAGE="${REPO_DIR}/safe/scripts/build-dependent-image.sh"

fail() {
  echo "dependent-image-apt-snapshot-retry: $*" >&2
  exit 1
}

dockerfile="$("${BUILD_DEPENDENT_IMAGE}" --print-dockerfile)"
script_text="$(<"${BUILD_DEPENDENT_IMAGE}")"

require_pattern() {
  local pattern="$1"
  grep -Fq -- "${pattern}" <<<"${dockerfile}" \
    || fail "rendered Dockerfile is missing: ${pattern}"
}

reject_pattern() {
  local pattern="$1"
  if grep -Fq -- "${pattern}" <<<"${dockerfile}"; then
    fail "rendered Dockerfile must not contain: ${pattern}"
  fi
}

require_script_pattern() {
  local pattern="$1"
  grep -Fq -- "${pattern}" <<<"${script_text}" \
    || fail "build-dependent-image script is missing: ${pattern}"
}

reject_script_pattern() {
  local pattern="$1"
  if grep -Fq -- "${pattern}" <<<"${script_text}"; then
    fail "build-dependent-image script must not contain: ${pattern}"
  fi
}

require_pattern "apt_bootstrap_ca_certificates_from_snapshot()"
require_pattern "apt_install_locked_packages_from_snapshot()"
require_pattern "Acquire::Retries=8"
require_pattern "Acquire::ForceIPv4=true"
require_pattern "Acquire::Queue-Mode=access"
require_pattern "Acquire::https::Pipeline-Depth=0"
require_pattern "Acquire::https::Timeout=20"
require_pattern "APT::Update::Error-Mode=any"
require_pattern "for attempt in 1 2 3 4 5 6 7 8; do"
require_pattern "apt-cache policy ca-certificates | grep -F '20240203' >/dev/null"
require_pattern "ca-certificates=20240203"
require_pattern "locked_packages_visible()"
require_pattern 'apt-cache policy "${package}" | grep -F " ${version}" >/dev/null'
require_pattern "install_locked_packages_once()"
require_pattern 'apt_install_locked_packages_from_snapshot || {'
require_pattern "pinned Ubuntu snapshot unavailable for locked dependent package closure"
require_pattern "python3 safe/tests/dependents/validate-installed-packages.py"
require_pattern "rm -rf /var/lib/apt/lists/*"

require_script_pattern "current_phase_tag()"
require_script_pattern "--print-phase-tag"
require_script_pattern "--print-dockerfile"

reject_pattern "install_locked_packages_from_local_debs()"
reject_pattern "locked-debs"
reject_pattern "write_archive_fallback_sources()"
reject_pattern "apt_bootstrap_ca_certificates_from_archive()"
reject_pattern ".apt-archive-fallback"
reject_pattern "archive.ubuntu.com"
reject_pattern "security.ubuntu.com"
reject_pattern "launchpad"
reject_pattern "ppa.launchpadcontent.net"

reject_script_pattern "prepare_locked_deb_fallback()"
reject_script_pattern "snapshot_index_reachable()"
reject_script_pattern "LIBGCRYPT_DEPENDENT_LOCKED_DEB_FALLBACK"
reject_script_pattern "LIBGCRYPT_DEPENDENT_LOCKED_DEB_CACHE"
reject_script_pattern "LIBGCRYPT_DEPENDENT_PACKAGE_MIRRORS"
reject_script_pattern "dependent-deb-cache"
reject_script_pattern "build_linux_libc_dev"
reject_script_pattern "minimal Linux UAPI"
reject_script_pattern "linux/falloc.h"
reject_script_pattern "linux/limits.h"
reject_script_pattern "x86_64-linux-gnu/asm/socket.h"
reject_script_pattern "mirrors.edge.kernel.org"
reject_script_pattern "ftp.up.pt"
reject_script_pattern "mirrors.united.cd"
reject_script_pattern "ppa.launchpadcontent.net"
reject_script_pattern "launchpad.net/ubuntu/+archive/primary/+files"
reject_script_pattern "apt-get\", \"download\""
reject_script_pattern "\"dpkg-deb\", \"-R\""
reject_script_pattern "\"dpkg-deb\", \"--build\""
reject_script_pattern "\"dpkg-deb\", \"--fsys-tarfile\""
reject_script_pattern "without live package contents"
reject_script_pattern "committed-lock .deb fallback"
reject_script_pattern "locked .deb fallback"

echo "dependent-image-apt-snapshot-retry: ok"

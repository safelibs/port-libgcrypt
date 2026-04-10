#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
DIST_DIR="${SAFE_DIR}/dist"

usage() {
  cat <<'EOF'
Usage: build-debs.sh
EOF
}

fail() {
  echo "build-debs: $*" >&2
  exit 1
}

if [[ "$#" -ne 0 ]]; then
  usage >&2
  exit 1
fi

cleanup_cargo_home=
workspace_owner=
if [[ -z "${CARGO_HOME:-}" ]]; then
  CARGO_HOME="$(mktemp -d)"
  export CARGO_HOME
  cleanup_cargo_home=1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  workspace_owner="$(stat -c '%u:%g' "${SAFE_DIR}")"
fi

cleanup() {
  [[ -n "${cleanup_cargo_home}" ]] && rm -rf "${CARGO_HOME}"
  if [[ -n "${workspace_owner}" ]]; then
    chown -R "${workspace_owner}" "${SAFE_DIR}/target" "${SAFE_DIR}/dist" "${SAFE_DIR}/debian" 2>/dev/null || true
  fi
}

trap cleanup EXIT

mkdir -p "${CARGO_HOME}"
if find "${CARGO_HOME}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  fail "CARGO_HOME must be an empty directory"
fi

export CARGO_NET_OFFLINE=true
version="$(dpkg-parsechangelog -l"${SAFE_DIR}/debian/changelog" -SVersion)"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.deb
rm -f "${REPO_DIR}"/libgcrypt20-dev_"${version}"_*.deb
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.buildinfo
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.changes

(
  cd "${SAFE_DIR}"
  dpkg-buildpackage -b -us -uc
)

shopt -s nullglob
artifacts=(
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.deb
  "${REPO_DIR}"/libgcrypt20-dev_"${version}"_*.deb
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.buildinfo
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.changes
)
shopt -u nullglob

if [[ "${#artifacts[@]}" -eq 0 ]]; then
  fail "dpkg-buildpackage did not produce any artifacts for ${version}"
fi

cp -f -- "${artifacts[@]}" "${DIST_DIR}/"
echo "build-debs: wrote artifacts to ${DIST_DIR}"

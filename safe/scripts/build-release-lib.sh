#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INVOCATION_PWD="${PWD}"
# shellcheck source=./cargo-target-root.sh
source "${SCRIPT_DIR}/cargo-target-root.sh"
TARGET_ROOT="$(resolve_target_root "${SAFE_DIR}" "${INVOCATION_PWD}")"
RELEASE_DIR="${TARGET_ROOT}/release"
STATICLIB="${RELEASE_DIR}/libgcrypt.a"
SHAREDLIB="${RELEASE_DIR}/libgcrypt.so"
VERSION_SCRIPT="${SAFE_DIR}/abi/libgcrypt.vers"

fail() {
  echo "build-release-lib: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

main() {
  local tmp_shared

  "${SCRIPT_DIR}/check-rust-toolchain.sh"
  require_file "${STATICLIB}"
  require_file "${VERSION_SCRIPT}"

  tmp_shared="$(mktemp "${SHAREDLIB}.tmp.XXXXXX")"
  cc -shared -o "${tmp_shared}" \
    "-Wl,--version-script=${VERSION_SCRIPT}" \
    -Wl,-soname,libgcrypt.so.20 \
    -Wl,--no-gc-sections \
    -Wl,--whole-archive "${STATICLIB}" \
    -Wl,--no-whole-archive \
    -lgpg-error -lgmp -lpthread -lm -lc -lgcc_s
  mv -f "${tmp_shared}" "${SHAREDLIB}"
}

main "$@"

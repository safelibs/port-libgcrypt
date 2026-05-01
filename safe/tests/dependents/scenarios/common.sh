#!/usr/bin/env bash
set -euo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPENDENTS_DIR="$(cd "${SCENARIO_DIR}/.." && pwd)"
SAFE_DIR="$(cd "${DEPENDENTS_DIR}/../.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
FIXTURE_DIR="${DEPENDENTS_DIR}/fixtures"

fail() {
  echo "dependent scenario: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing fixture: $1"
}

assert_uses_selected_libgcrypt() {
  local label=$1
  local binary=$2
  local trace loaded real

  [[ -n "${LIBGCRYPT_EXPECTED_REALPATH:-}" ]] \
    || fail "LIBGCRYPT_EXPECTED_REALPATH is not set"

  trace="$(LD_TRACE_LOADED_OBJECTS=1 "$binary" 2>/dev/null || true)"
  loaded="$(
    awk '
      /libgcrypt[.]so[.]20/ {
        for (i = 1; i <= NF; i++) {
          if ($i ~ "^/") {
            print $i
            exit
          }
        }
      }
    ' <<<"${trace}"
  )"
  [[ -n "${loaded}" ]] || {
    printf '%s\n' "${trace}" >&2
    fail "${label} did not load libgcrypt.so.20"
  }

  real="$(readlink -f "${loaded}")"
  [[ "${real}" == "${LIBGCRYPT_EXPECTED_REALPATH}" ]] || {
    printf '%s\n' "${trace}" >&2
    fail "${label} loaded ${real}, expected ${LIBGCRYPT_EXPECTED_REALPATH}"
  }
}

new_private_dir() {
  local dir
  dir="$(mktemp -d)"
  chmod 700 "${dir}"
  printf '%s\n' "${dir}"
}

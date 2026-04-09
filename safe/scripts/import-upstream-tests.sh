#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
ORIGINAL_DIR="${REPO_DIR}/original/libgcrypt20-1.10.3"
UPSTREAM_SOURCE_DIR="${ORIGINAL_DIR}/tests"
COMPAT_SOURCE_DIR="${ORIGINAL_DIR}/compat"
TARGET_UPSTREAM_DIR="${SAFE_DIR}/tests/upstream"
TARGET_COMPAT_DIR="${SAFE_DIR}/tests/compat"
PHASE1_DIR="${SAFE_DIR}/tests/original-build"
CONFIG_SOURCE="${PHASE1_DIR}/config.h"
WRAPPER_BASIC_SOURCE="${PHASE1_DIR}/basic-disable-all-hwf"
WRAPPER_HASH_SOURCE="${PHASE1_DIR}/hashtest-256g"
BUILD_VARS_SOURCE="${PHASE1_DIR}/test-build-vars.mk"
TMPDIR_IMPORT=""

fail() {
  echo "import-upstream-tests: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TMPDIR_IMPORT}" && -d "${TMPDIR_IMPORT}" ]]; then
    rm -rf "${TMPDIR_IMPORT}"
  fi
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

require_dir() {
  [[ -d "$1" ]] || fail "missing directory: $1"
}

require_pattern() {
  local path="$1"
  local pattern="$2"
  grep -Fq -- "${pattern}" "${path}" || fail "missing pattern in ${path}: ${pattern}"
}

verify_phase1_sources() {
  require_file "${BUILD_VARS_SOURCE}"
  require_file "${CONFIG_SOURCE}"
  require_file "${WRAPPER_BASIC_SOURCE}"
  require_file "${WRAPPER_HASH_SOURCE}"

  # shellcheck disable=SC1090
  . "${BUILD_VARS_SOURCE}"
  [[ "${EXEEXT}" == "" ]] || fail "unexpected EXEEXT in ${BUILD_VARS_SOURCE}: ${EXEEXT}"
  [[ "${RUN_LARGE_DATA_TESTS}" == "yes" ]] || fail "unexpected RUN_LARGE_DATA_TESTS in ${BUILD_VARS_SOURCE}: ${RUN_LARGE_DATA_TESTS}"
  [[ "${TESTS_ENVIRONMENT}" == "GCRYPT_IN_REGRESSION_TEST=1" ]] || fail "unexpected TESTS_ENVIRONMENT in ${BUILD_VARS_SOURCE}: ${TESTS_ENVIRONMENT}"
  [[ "${COMPAT_LINUX_SOURCES}" == "compat.c" ]] || fail "unexpected COMPAT_LINUX_SOURCES in ${BUILD_VARS_SOURCE}: ${COMPAT_LINUX_SOURCES}"
}

write_minimal_g10lib() {
  local destination="$1"
  cat >"${destination}" <<'EOF'
/* Minimal compat-build subset derived from
   original/libgcrypt20-1.10.3/src/g10lib.h.

   The imported Linux test harness only needs compat/compat.c to include
   this header so the upstream relative include layout still works.  */

#ifndef G10LIB_H
#define G10LIB_H 1

#ifndef _GCRYPT_IN_LIBGCRYPT
#error something is wrong with config.h
#endif

#endif /* G10LIB_H */
EOF
}

build_expected_tree() {
  local root="$1"

  mkdir -p "${root}/upstream" "${root}/compat/include/src"
  cp -a "${UPSTREAM_SOURCE_DIR}/." "${root}/upstream/"
  cp -a "${COMPAT_SOURCE_DIR}/." "${root}/compat/"
  cp "${CONFIG_SOURCE}" "${root}/upstream/config.h"
  cp "${WRAPPER_BASIC_SOURCE}" "${root}/upstream/basic-disable-all-hwf"
  cp "${WRAPPER_HASH_SOURCE}" "${root}/upstream/hashtest-256g"
  chmod +x "${root}/upstream/basic-disable-all-hwf" "${root}/upstream/hashtest-256g"
  write_minimal_g10lib "${root}/compat/include/src/g10lib.h"
}

verify_tree_matches() {
  local expected="$1"
  local actual="$2"

  require_dir "${actual}"
  if ! diff -ruN "${expected}" "${actual}" >/dev/null; then
    diff -ruN "${expected}" "${actual}" >&2 || true
    fail "drift detected under ${actual}"
  fi
}

replace_tree() {
  local expected="$1"
  local actual="$2"

  rm -rf "${actual}"
  mkdir -p "$(dirname "${actual}")"
  cp -a "${expected}" "${actual}"
}

verify_import_inventory() {
  require_file "${TARGET_UPSTREAM_DIR}/Makefile.am"
  require_file "${TARGET_UPSTREAM_DIR}/testdrv.c"

  require_pattern "${TARGET_UPSTREAM_DIR}/Makefile.am" "tests_sh = basic-disable-all-hwf"
  require_pattern "${TARGET_UPSTREAM_DIR}/Makefile.am" "tests_sh_last = hashtest-256g"
  require_pattern "${TARGET_UPSTREAM_DIR}/Makefile.am" "EXTRA_PROGRAMS = testapi pkbench"
  require_pattern "${TARGET_UPSTREAM_DIR}/Makefile.am" "fipsdrv rsacvt genhashdata gchash"
  require_pattern "${TARGET_UPSTREAM_DIR}/testdrv.c" "{ \"basic-disable-all-hwf\", \"basic\", \"--disable-hwf all\" }"
  require_pattern "${TARGET_UPSTREAM_DIR}/testdrv.c" "{ \"hashtest-256g\",  \"hashtest\", \"--gigs 256 SHA1 SHA256 SHA512 SM3\","

  require_file "${TARGET_UPSTREAM_DIR}/config.h"
  require_file "${TARGET_UPSTREAM_DIR}/basic-disable-all-hwf"
  require_file "${TARGET_UPSTREAM_DIR}/hashtest-256g"
  require_file "${TARGET_COMPAT_DIR}/compat.c"
  require_file "${TARGET_COMPAT_DIR}/libcompat.h"
  require_file "${TARGET_COMPAT_DIR}/include/src/g10lib.h"
  [[ -x "${TARGET_UPSTREAM_DIR}/basic-disable-all-hwf" ]] || fail "wrapper is not executable: ${TARGET_UPSTREAM_DIR}/basic-disable-all-hwf"
  [[ -x "${TARGET_UPSTREAM_DIR}/hashtest-256g" ]] || fail "wrapper is not executable: ${TARGET_UPSTREAM_DIR}/hashtest-256g"
}

main() {
  local verify_only=0

  if [[ "${1:-}" == "--verify" ]]; then
    verify_only=1
    shift
  fi
  [[ "$#" -eq 0 ]] || fail "usage: import-upstream-tests.sh [--verify]"

  require_dir "${UPSTREAM_SOURCE_DIR}"
  require_dir "${COMPAT_SOURCE_DIR}"
  verify_phase1_sources

  TMPDIR_IMPORT="$(mktemp -d "${SAFE_DIR}/target/bootstrap/import-upstream.XXXXXX")"
  trap cleanup EXIT

  build_expected_tree "${TMPDIR_IMPORT}"

  if [[ "${verify_only}" -eq 1 ]]; then
    verify_tree_matches "${TMPDIR_IMPORT}/upstream" "${TARGET_UPSTREAM_DIR}"
    verify_tree_matches "${TMPDIR_IMPORT}/compat" "${TARGET_COMPAT_DIR}"
    verify_import_inventory
    echo "import-upstream-tests: verified"
    return 0
  fi

  replace_tree "${TMPDIR_IMPORT}/upstream" "${TARGET_UPSTREAM_DIR}"
  replace_tree "${TMPDIR_IMPORT}/compat" "${TARGET_COMPAT_DIR}"
  verify_import_inventory
  echo "import-upstream-tests: synchronized"
}

main "$@"

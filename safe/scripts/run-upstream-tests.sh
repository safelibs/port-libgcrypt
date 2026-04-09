#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
GENERATED_DIR="${SAFE_DIR}/target/bootstrap/generated"
STAGE_ROOT="${SAFE_DIR}/target/bootstrap/staging"
STAGE_PREFIX="${STAGE_ROOT}/usr"
STAGE_LIBDIR="${STAGE_PREFIX}/lib/${MULTIARCH}"
HARNESS_ROOT="${SAFE_DIR}/target/bootstrap/upstream-harness"
UPSTREAM_DIR="${SAFE_DIR}/tests/upstream"
COMPAT_DIR="${SAFE_DIR}/tests/compat"
COMPAT_INCLUDE_DIR="${COMPAT_DIR}/include/src"
CONFIG_H="${UPSTREAM_DIR}/config.h"
BUILD_VARS="${SAFE_DIR}/tests/original-build/test-build-vars.mk"
WRAPPER_BASIC="${UPSTREAM_DIR}/basic-disable-all-hwf"
WRAPPER_HASH="${UPSTREAM_DIR}/hashtest-256g"

REQUIRED_HELPERS=(testdrv fipsdrv rsacvt genhashdata gchash pkbench)
BUILT_HELPERS=()
TESTDRV_LINES=()
INCLUDE_LONG=0

fail() {
  echo "run-upstream-tests: $*" >&2
  exit 1
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

stage_install_tree() {
  mkdir -p "${STAGE_LIBDIR}" "${STAGE_PREFIX}/include" "${STAGE_LIBDIR}/pkgconfig" "${STAGE_PREFIX}/bin" "${STAGE_PREFIX}/share/aclocal"
  cp "${SAFE_DIR}/target/release/libgcrypt.so" "${STAGE_LIBDIR}/libgcrypt.so.20"
  ln -sfn "libgcrypt.so.20" "${STAGE_LIBDIR}/libgcrypt.so"
  cp "${SAFE_DIR}/target/release/libgcrypt.a" "${STAGE_LIBDIR}/libgcrypt.a"
  cp "${GENERATED_DIR}/include/gcrypt.h" "${STAGE_PREFIX}/include/gcrypt.h"
  cp "${GENERATED_DIR}/pkgconfig/libgcrypt.pc" "${STAGE_LIBDIR}/pkgconfig/libgcrypt.pc"
  cp "${GENERATED_DIR}/bin/libgcrypt-config" "${STAGE_PREFIX}/bin/libgcrypt-config"
  cp "${SAFE_DIR}/abi/libgcrypt.m4" "${STAGE_PREFIX}/share/aclocal/libgcrypt.m4"
  chmod +x "${STAGE_PREFIX}/bin/libgcrypt-config"
}

prepare_harness_tree() {
  local src_stage upstream_stage compat_stage build_stage

  src_stage="${HARNESS_ROOT}/src"
  upstream_stage="${HARNESS_ROOT}/upstream"
  compat_stage="${HARNESS_ROOT}/compat"
  build_stage="${HARNESS_ROOT}/build"

  rm -rf "${HARNESS_ROOT}"
  mkdir -p "${src_stage}" "${upstream_stage}" "${compat_stage}" "${build_stage}"

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${upstream_stage}/$(basename "${file}")"
    if [[ "${file}" != *.c ]]; then
      ln -s "${file}" "${build_stage}/$(basename "${file}")"
    fi
  done < <(find "${UPSTREAM_DIR}" -maxdepth 1 -type f -print0)

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${compat_stage}/$(basename "${file}")"
  done < <(find "${COMPAT_DIR}" -maxdepth 1 -type f -print0)

  ln -s "${GENERATED_DIR}/include/gcrypt.h" "${src_stage}/gcrypt.h"
  while IFS= read -r -d '' file; do
    ln -s "${file}" "${src_stage}/$(basename "${file}")"
  done < <(find "${COMPAT_INCLUDE_DIR}" -maxdepth 1 -type f -print0)
}

maybe_disable_new_dtags_flag() {
  local tmpdir probe_c probe_bin

  [[ -n "${LD_LIBRARY_PATH:-}" ]] || return 0

  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/dtags.XXXXXX")"
  probe_c="${tmpdir}/probe.c"
  probe_bin="${tmpdir}/probe"
  cat >"${probe_c}" <<'EOF'
int main(void) { return 0; }
EOF

  if cc "${probe_c}" -Wl,--disable-new-dtags -o "${probe_bin}" >/dev/null 2>&1; then
    printf '%s\n' "-Wl,--disable-new-dtags"
  fi
  rm -rf "${tmpdir}"
}

common_compile_args() {
  local extra_link
  extra_link="$(maybe_disable_new_dtags_flag || true)"

  printf '%s\n' \
    -DHAVE_CONFIG_H=1 \
    -DHAVE_PTHREAD=1 \
    -DHAVE_CLOCK_GETTIME=1 \
    -DPACKAGE_BUGREPORT=\"devnull@example.org\" \
    -I"${HARNESS_ROOT}/upstream" \
    -I"${HARNESS_ROOT}/src" \
    -I"${HARNESS_ROOT}/compat" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    ${extra_link:+${extra_link}} \
    -pthread
}

compile_compat_object() {
  mapfile -t compile_args < <(common_compile_args)
  cc \
    "${compile_args[@]}" \
    -c "${HARNESS_ROOT}/compat/compat.c" \
    -o "${HARNESS_ROOT}/build/compat.o"
}

needs_compat_object() {
  [[ ! -f "${HARNESS_ROOT}/build/compat.o" || "${HARNESS_ROOT}/compat/compat.c" -nt "${HARNESS_ROOT}/build/compat.o" || "${HARNESS_ROOT}/src/g10lib.h" -nt "${HARNESS_ROOT}/build/compat.o" || "${HARNESS_ROOT}/upstream/config.h" -nt "${HARNESS_ROOT}/build/compat.o" ]]
}

binary_name() {
  case "$1" in
    basic-disable-all-hwf) printf '%s\n' "basic" ;;
    hashtest-256g) printf '%s\n' "hashtest" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

source_name() {
  binary_name "$1"
}

compile_binary() {
  local requested_name="$1"
  local binary source output

  binary="$(binary_name "${requested_name}")"
  source="$(source_name "${requested_name}")"
  output="${HARNESS_ROOT}/build/${binary}"

  require_file "${HARNESS_ROOT}/upstream/${source}.c"
  if needs_compat_object; then
    compile_compat_object
  fi

  mapfile -t compile_args < <(common_compile_args)
  if [[ ! -x "${output}" || "${HARNESS_ROOT}/upstream/${source}.c" -nt "${output}" || "${HARNESS_ROOT}/build/compat.o" -nt "${output}" || "${HARNESS_ROOT}/src/gcrypt.h" -nt "${output}" || "${HARNESS_ROOT}/upstream/config.h" -nt "${output}" ]]; then
    if [[ "${binary}" == "testdrv" ]]; then
      cc \
        "${compile_args[@]}" \
        -DTESTDRV_EXEEXT="\"\"" \
        "${HARNESS_ROOT}/upstream/${source}.c" \
        "${HARNESS_ROOT}/build/compat.o" \
        -lgcrypt -lgpg-error \
        -o "${output}"
    else
      cc \
        "${compile_args[@]}" \
        "${HARNESS_ROOT}/upstream/${source}.c" \
        "${HARNESS_ROOT}/build/compat.o" \
        -lgcrypt -lgpg-error \
        -o "${output}"
    fi
  fi
}

compile_required_helpers() {
  local helper

  BUILT_HELPERS=()
  for helper in "${REQUIRED_HELPERS[@]}"; do
    compile_binary "${helper}"
    BUILT_HELPERS+=("${helper}")
  done
}

load_testdrv_inventory() {
  local line

  compile_binary "testdrv"
  TESTDRV_LINES=()
  while IFS= read -r line; do
    TESTDRV_LINES+=("${line}")
  done < <(cd "${HARNESS_ROOT}/build" && ./testdrv --list)
  [[ "${#TESTDRV_LINES[@]}" -gt 0 ]] || fail "testdrv inventory is empty"
}

is_long_test() {
  local test_name="$1"
  local line

  for line in "${TESTDRV_LINES[@]}"; do
    if [[ "${line%% *}" == "${test_name}" ]]; then
      [[ "${line}" == *"[long]"* ]]
      return $?
    fi
  done

  return 1
}

ordered_tests_from_testdrv() {
  local include_long="$1"
  local line name

  for line in "${TESTDRV_LINES[@]}"; do
    name="${line%% *}"
    if [[ "${line}" == *"[long]"* && "${include_long}" -eq 0 ]]; then
      continue
    fi
    printf '%s\n' "${name}"
  done
}

verify_phase1_build_vars() {
  require_file "${BUILD_VARS}"
  # shellcheck disable=SC1090
  . "${BUILD_VARS}"
  [[ "${EXEEXT}" == "" ]] || fail "unexpected EXEEXT in ${BUILD_VARS}: ${EXEEXT}"
  [[ "${RUN_LARGE_DATA_TESTS}" == "yes" ]] || fail "unexpected RUN_LARGE_DATA_TESTS in ${BUILD_VARS}: ${RUN_LARGE_DATA_TESTS}"
  [[ "${TESTS_ENVIRONMENT}" == "GCRYPT_IN_REGRESSION_TEST=1" ]] || fail "unexpected TESTS_ENVIRONMENT in ${BUILD_VARS}: ${TESTS_ENVIRONMENT}"
  [[ "${COMPAT_LINUX_SOURCES}" == "compat.c" ]] || fail "unexpected COMPAT_LINUX_SOURCES in ${BUILD_VARS}: ${COMPAT_LINUX_SOURCES}"
}

verify_imported_tree() {
  require_dir "${UPSTREAM_DIR}"
  require_dir "${COMPAT_DIR}"
  require_dir "${COMPAT_INCLUDE_DIR}"
  require_file "${CONFIG_H}"
  require_file "${WRAPPER_BASIC}"
  require_file "${WRAPPER_HASH}"
  require_file "${COMPAT_DIR}/compat.c"
  require_file "${COMPAT_DIR}/libcompat.h"
  require_file "${COMPAT_INCLUDE_DIR}/g10lib.h"
  require_file "${UPSTREAM_DIR}/Makefile.am"
  require_file "${UPSTREAM_DIR}/testdrv.c"
  [[ -x "${WRAPPER_BASIC}" ]] || fail "wrapper is not executable: ${WRAPPER_BASIC}"
  [[ -x "${WRAPPER_HASH}" ]] || fail "wrapper is not executable: ${WRAPPER_HASH}"

  require_pattern "${UPSTREAM_DIR}/Makefile.am" "tests_sh = basic-disable-all-hwf"
  require_pattern "${UPSTREAM_DIR}/Makefile.am" "tests_sh_last = hashtest-256g"
  require_pattern "${UPSTREAM_DIR}/Makefile.am" "EXTRA_PROGRAMS = testapi pkbench"
  require_pattern "${UPSTREAM_DIR}/Makefile.am" "fipsdrv rsacvt genhashdata gchash"
  require_pattern "${UPSTREAM_DIR}/testdrv.c" "{ \"basic-disable-all-hwf\", \"basic\", \"--disable-hwf all\" }"
  require_pattern "${UPSTREAM_DIR}/testdrv.c" "{ \"hashtest-256g\",  \"hashtest\", \"--gigs 256 SHA1 SHA256 SHA512 SM3\","
}

verify_plumbing() {
  local helper

  verify_phase1_build_vars
  verify_imported_tree
  require_file "${GENERATED_DIR}/include/gcrypt.h"
  require_file "${HARNESS_ROOT}/src/gcrypt.h"
  require_file "${HARNESS_ROOT}/src/g10lib.h"
  require_file "${HARNESS_ROOT}/upstream/config.h"
  require_file "${HARNESS_ROOT}/build/basic-disable-all-hwf"
  require_file "${HARNESS_ROOT}/build/hashtest-256g"
  require_file "${HARNESS_ROOT}/build/compat.o"

  [[ "$(readlink -f "${HARNESS_ROOT}/src/gcrypt.h")" == "${GENERATED_DIR}/include/gcrypt.h" ]] || fail "staged gcrypt.h does not point at generated header"
  [[ "$(readlink -f "${HARNESS_ROOT}/src/g10lib.h")" == "${COMPAT_INCLUDE_DIR}/g10lib.h" ]] || fail "staged g10lib.h does not point at compat include tree"
  [[ "$(readlink -f "${HARNESS_ROOT}/upstream/config.h")" == "${CONFIG_H}" ]] || fail "staged config.h does not point at committed imported config"
  [[ "$(readlink -f "${HARNESS_ROOT}/build/basic-disable-all-hwf")" == "${WRAPPER_BASIC}" ]] || fail "staged basic-disable-all-hwf does not point at committed wrapper"
  [[ "$(readlink -f "${HARNESS_ROOT}/build/hashtest-256g")" == "${WRAPPER_HASH}" ]] || fail "staged hashtest-256g does not point at committed wrapper"
  [[ "$(readlink -f "${HARNESS_ROOT}/compat/compat.c")" == "${COMPAT_DIR}/compat.c" ]] || fail "staged compat.c does not point at committed compat source"
  [[ "$(readlink -f "${HARNESS_ROOT}/compat/libcompat.h")" == "${COMPAT_DIR}/libcompat.h" ]] || fail "staged libcompat.h does not point at committed compat header"

  for helper in "${REQUIRED_HELPERS[@]}"; do
    require_file "${HARNESS_ROOT}/build/${helper}"
    echo "run-upstream-tests: helper-target=${helper} source=$(readlink -f "${HARNESS_ROOT}/upstream/${helper}.c")"
  done
  echo "run-upstream-tests: plumbing generated-header=$(readlink -f "${HARNESS_ROOT}/src/gcrypt.h")"
  echo "run-upstream-tests: plumbing compat-header=$(readlink -f "${HARNESS_ROOT}/src/g10lib.h")"
  echo "run-upstream-tests: plumbing config=$(readlink -f "${HARNESS_ROOT}/upstream/config.h")"
  echo "run-upstream-tests: plumbing wrapper-basic=$(readlink -f "${HARNESS_ROOT}/build/basic-disable-all-hwf")"
  echo "run-upstream-tests: plumbing wrapper-hashtest=$(readlink -f "${HARNESS_ROOT}/build/hashtest-256g")"
}

run_one_test() {
  local test_name="$1"

  if [[ "${INCLUDE_LONG}" -eq 0 ]] && is_long_test "${test_name}"; then
    echo "run-upstream-tests: skipping long-running test ${test_name}; pass --long to include it"
    return 0
  fi

  compile_binary "${test_name}"
  (
    cd "${HARNESS_ROOT}/build"
    GCRYPT_IN_REGRESSION_TEST=1 \
    LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "./${test_name}"
  )
}

main() {
  local verify_plumbing_mode=0
  local tests=()
  local test_name

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --verify-plumbing)
        verify_plumbing_mode=1
        ;;
      --long)
        INCLUDE_LONG=1
        ;;
      --)
        shift
        while [[ "$#" -gt 0 ]]; do
          tests+=("$1")
          shift
        done
        break
        ;;
      -*)
        fail "unknown option: $1"
        ;;
      *)
        tests+=("$1")
        ;;
    esac
    shift
  done

  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --offline
  verify_phase1_build_vars
  verify_imported_tree
  stage_install_tree
  prepare_harness_tree
  compile_required_helpers
  load_testdrv_inventory

  if [[ "${verify_plumbing_mode}" -eq 1 ]]; then
    verify_plumbing
    if [[ "${#tests[@]}" -eq 0 ]]; then
      echo "run-upstream-tests: plumbing verified"
      return 0
    fi
  fi

  if [[ "${#tests[@]}" -eq 0 ]]; then
    while IFS= read -r test_name; do
      tests+=("${test_name}")
    done < <(ordered_tests_from_testdrv "${INCLUDE_LONG}")
  fi

  for test_name in "${tests[@]}"; do
    run_one_test "${test_name}"
  done

  echo "run-upstream-tests: ok (${tests[*]})"
}

main "$@"

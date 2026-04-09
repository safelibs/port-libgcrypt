#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
ORIGINAL_DIR="${REPO_DIR}/original/libgcrypt20-1.10.3"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
GENERATED_DIR="${SAFE_DIR}/target/bootstrap/generated"
STAGE_ROOT="${SAFE_DIR}/target/bootstrap/staging"
STAGE_PREFIX="${STAGE_ROOT}/usr"
STAGE_LIBDIR="${STAGE_PREFIX}/lib/${MULTIARCH}"
HARNESS_ROOT="${SAFE_DIR}/target/bootstrap/original-harness"
CONFIG_H="${SAFE_DIR}/tests/original-build/config.h"
BUILD_VARS="${SAFE_DIR}/tests/original-build/test-build-vars.mk"
WRAPPER_BASIC="${SAFE_DIR}/tests/original-build/basic-disable-all-hwf"
WRAPPER_HASH="${SAFE_DIR}/tests/original-build/hashtest-256g"

fail() {
  echo "run-original-tests: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
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
  local src_stage tests_stage compat_stage build_stage

  src_stage="${HARNESS_ROOT}/src"
  tests_stage="${HARNESS_ROOT}/tests"
  compat_stage="${HARNESS_ROOT}/compat"
  build_stage="${HARNESS_ROOT}/build"

  rm -rf "${HARNESS_ROOT}"
  mkdir -p "${src_stage}" "${tests_stage}" "${compat_stage}" "${build_stage}"

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${src_stage}/$(basename "${file}")"
  done < <(find "${ORIGINAL_DIR}/src" -maxdepth 1 -type f -print0)

  cp "${GENERATED_DIR}/include/gcrypt.h" "${src_stage}/gcrypt.h"

  ln -s "${ORIGINAL_DIR}/compat/compat.c" "${compat_stage}/compat.c"
  ln -s "${ORIGINAL_DIR}/compat/libcompat.h" "${compat_stage}/libcompat.h"
  ln -s "${ORIGINAL_DIR}/tests/t-common.h" "${tests_stage}/t-common.h"
  ln -s "${ORIGINAL_DIR}/tests/stopwatch.h" "${tests_stage}/stopwatch.h"
  ln -s "${WRAPPER_BASIC}" "${tests_stage}/basic-disable-all-hwf"
  ln -s "${WRAPPER_HASH}" "${tests_stage}/hashtest-256g"
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

compile_compat_object() {
  cc \
    -DHAVE_CONFIG_H=1 \
    -I"${SAFE_DIR}/tests/original-build" \
    -I"${HARNESS_ROOT}/src" \
    -I"${HARNESS_ROOT}/compat" \
    -c "${HARNESS_ROOT}/compat/compat.c" \
    -o "${HARNESS_ROOT}/build/compat.o"
}

compile_test() {
  local test_name source_path output_path extra_link
  test_name="$1"
  source_path="${HARNESS_ROOT}/tests/${test_name}.c"
  output_path="${HARNESS_ROOT}/build/${test_name}"
  extra_link="$(maybe_disable_new_dtags_flag || true)"

  cc \
    -DHAVE_CONFIG_H=1 \
    -I"${SAFE_DIR}/tests/original-build" \
    -I"${HARNESS_ROOT}/tests" \
    -I"${HARNESS_ROOT}/src" \
    "${source_path}" \
    "${HARNESS_ROOT}/build/compat.o" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    ${extra_link:+${extra_link}} \
    -lgcrypt -lgpg-error \
    -o "${output_path}"
}

run_test() {
  local test_name
  test_name="$1"
  GCRYPT_IN_REGRESSION_TEST=1 \
  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
    "${HARNESS_ROOT}/build/${test_name}"
}

verify_plumbing() {
  require_file "${CONFIG_H}"
  require_file "${BUILD_VARS}"
  require_file "${WRAPPER_BASIC}"
  require_file "${WRAPPER_HASH}"
  require_file "${ORIGINAL_DIR}/compat/compat.c"
  require_file "${ORIGINAL_DIR}/tests/version.c"
  require_file "${ORIGINAL_DIR}/tests/t-secmem.c"

  # shellcheck disable=SC1090
  . "${BUILD_VARS}"
  [[ "${EXEEXT}" == "" ]] || fail "unexpected EXEEXT in ${BUILD_VARS}: ${EXEEXT}"
  [[ "${RUN_LARGE_DATA_TESTS}" == "yes" ]] || fail "unexpected RUN_LARGE_DATA_TESTS in ${BUILD_VARS}: ${RUN_LARGE_DATA_TESTS}"
  [[ "${COMPAT_LINUX_SOURCES}" == "compat.c" ]] || fail "unexpected compat source set: ${COMPAT_LINUX_SOURCES}"

  echo "run-original-tests: plumbing config=${CONFIG_H}"
  echo "run-original-tests: plumbing vars=${BUILD_VARS}"
  echo "run-original-tests: plumbing generated-header=${GENERATED_DIR}/include/gcrypt.h"
  echo "run-original-tests: plumbing wrapper-basic=$(readlink -f "${HARNESS_ROOT}/tests/basic-disable-all-hwf")"
  echo "run-original-tests: plumbing wrapper-hashtest=$(readlink -f "${HARNESS_ROOT}/tests/hashtest-256g")"
  echo "run-original-tests: plumbing compat-source=$(readlink -f "${HARNESS_ROOT}/compat/compat.c")"
  echo "run-original-tests: plumbing version-source=$(readlink -f "${HARNESS_ROOT}/tests/version.c")"
  echo "run-original-tests: plumbing t-secmem-source=$(readlink -f "${HARNESS_ROOT}/tests/t-secmem.c")"
}

main() {
  local verify_plumbing_mode=0
  local tests=()

  if [[ "${1:-}" == "--verify-plumbing" ]]; then
    verify_plumbing_mode=1
    shift
  fi

  if [[ "$#" -eq 0 ]]; then
    tests=(version t-secmem)
  else
    tests=("$@")
  fi

  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --offline
  stage_install_tree
  prepare_harness_tree

  for test_name in "${tests[@]}"; do
    require_file "${ORIGINAL_DIR}/tests/${test_name}.c"
    ln -s "${ORIGINAL_DIR}/tests/${test_name}.c" "${HARNESS_ROOT}/tests/${test_name}.c"
  done

  if [[ "${verify_plumbing_mode}" -eq 1 ]]; then
    verify_plumbing
  fi

  compile_compat_object

  for test_name in "${tests[@]}"; do
    compile_test "${test_name}"
    run_test "${test_name}"
  done

  echo "run-original-tests: ok (${tests[*]})"
}

main "$@"

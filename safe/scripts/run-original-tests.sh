#!/usr/bin/env bash
set -euo pipefail
PS4='+ \\'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
INVOCATION_PWD="${PWD}"
# shellcheck source=./cargo-target-root.sh
source "${SCRIPT_DIR}/cargo-target-root.sh"
TARGET_ROOT="$(resolve_target_root "${SAFE_DIR}" "${INVOCATION_PWD}")"
BOOTSTRAP_ROOT="${TARGET_ROOT}/bootstrap"
ORIGINAL_DIR="${REPO_DIR}/original/libgcrypt20-1.10.3"
DEFAULT_TESTS_MAKEFILE="${ORIGINAL_DIR}/tests/Makefile.am"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
GENERATED_DIR="${BOOTSTRAP_ROOT}/generated"
STAGE_ROOT="${BOOTSTRAP_ROOT}/staging"
STAGE_PREFIX="${STAGE_ROOT}/usr"
STAGE_LIBDIR="${STAGE_PREFIX}/lib/${MULTIARCH}"
RELEASE_DIR="${TARGET_ROOT}/release"
HARNESS_ROOT="${BOOTSTRAP_ROOT}/original-harness"
CONFIG_H="${SAFE_DIR}/tests/original-build/config.h"
BUILD_VARS="${SAFE_DIR}/tests/original-build/test-build-vars.mk"
WRAPPER_BASIC="${SAFE_DIR}/tests/original-build/basic-disable-all-hwf"
WRAPPER_HASH="${SAFE_DIR}/tests/original-build/hashtest-256g"

EXEEXT=""
RUN_LARGE_DATA_TESTS=""
TESTS_ENVIRONMENT=""
COMPAT_LINUX_SOURCES=""
LDADD_FOR_TESTS_KLUDGE=""
LINKER_KLUDGE_FLAGS=()
TEST_CMD=()

fail() {
  echo "run-original-tests: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

tests_makefile_path() {
  printf '%s\n' "${LIBGCRYPT_ORIGINAL_TESTS_MAKEFILE:-${DEFAULT_TESTS_MAKEFILE}}"
}

load_build_vars() {
  require_file "${BUILD_VARS}"

  EXEEXT=""
  RUN_LARGE_DATA_TESTS=""
  TESTS_ENVIRONMENT=""
  COMPAT_LINUX_SOURCES=""
  LDADD_FOR_TESTS_KLUDGE=""
  LINKER_KLUDGE_FLAGS=()

  # shellcheck disable=SC1090
  . "${BUILD_VARS}"

  if [[ -n "${LDADD_FOR_TESTS_KLUDGE}" ]]; then
    read -r -a LINKER_KLUDGE_FLAGS <<<"${LDADD_FOR_TESTS_KLUDGE}"
  fi
}

load_tests_inventory() {
  local makefile_path="$1"
  require_file "${makefile_path}"

  python3 - "${makefile_path}" <<'PY'
from pathlib import Path
import re
import sys

allowed = {"USE_RSA", "USE_DSA", "USE_ECC"}
target_vars = ("tests_bin", "tests_sh", "tests_bin_last", "tests_sh_last")
text = Path(sys.argv[1]).read_text().splitlines()
assignments = []
active_stack = [True]
cond_stack = []
current = None
current_active = True

for raw in text:
    line = raw.split("#", 1)[0].rstrip()
    stripped = line.strip()

    if current is not None:
        piece = stripped.rstrip("\\").strip()
        if piece:
            current = f"{current} {piece}".strip()
        if not stripped.endswith("\\"):
            assignments.append((current_active, current))
            current = None
        continue

    if not stripped:
        continue
    if stripped.startswith("if "):
        cond = stripped[3:].strip()
        cond_enabled = cond in allowed
        cond_stack.append(cond_enabled)
        active_stack.append(active_stack[-1] and cond_enabled)
        continue
    if stripped == "else":
        if len(active_stack) == 1:
            raise SystemExit("unbalanced else in Makefile.am inventory parser")
        parent_active = active_stack[-2]
        cond_enabled = cond_stack[-1]
        active_stack[-1] = parent_active and (not cond_enabled)
        continue
    if stripped == "endif":
        if len(active_stack) == 1:
            raise SystemExit("unbalanced endif in Makefile.am inventory parser")
        active_stack.pop()
        cond_stack.pop()
        continue

    piece = stripped.rstrip("\\").strip()
    if stripped.endswith("\\"):
        current = piece
        current_active = active_stack[-1]
    else:
        assignments.append((active_stack[-1], piece))

if current is not None:
    assignments.append((current_active, current))

variables = {name: [] for name in target_vars}
pattern = re.compile(r"^(tests_bin|tests_sh|tests_bin_last|tests_sh_last)\s*(\+?=)\s*(.*)$")

for active, stmt in assignments:
    match = pattern.match(stmt)
    if not match:
        continue
    if not active:
        continue
    name, operator, value = match.groups()
    tokens = value.split()
    if operator == "=":
        variables[name] = tokens
    else:
        variables[name].extend(tokens)

inventory = (
    variables["tests_bin"]
    + variables["tests_sh"]
    + variables["tests_bin_last"]
    + variables["tests_sh_last"]
)
for entry in inventory:
    print(entry)
PY
}

stage_install_tree() {
  mkdir -p "${STAGE_LIBDIR}" "${STAGE_PREFIX}/include" "${STAGE_LIBDIR}/pkgconfig" "${STAGE_PREFIX}/bin" "${STAGE_PREFIX}/share/aclocal"
  cp "${RELEASE_DIR}/libgcrypt.so" "${STAGE_LIBDIR}/libgcrypt.so.20"
  ln -sfn "libgcrypt.so.20" "${STAGE_LIBDIR}/libgcrypt.so"
  cp "${RELEASE_DIR}/libgcrypt.a" "${STAGE_LIBDIR}/libgcrypt.a"
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

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${tests_stage}/$(basename "${file}")"
    ln -s "${file}" "${build_stage}/$(basename "${file}")"
  done < <(find "${ORIGINAL_DIR}/tests" -maxdepth 1 -type f ! -name '*.c' -print0)

  ln -s "${WRAPPER_BASIC}" "${tests_stage}/basic-disable-all-hwf"
  ln -s "${WRAPPER_HASH}" "${tests_stage}/hashtest-256g"
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

source_test_name() {
  case "$1" in
    basic-disable-all-hwf) printf '%s\n' "basic" ;;
    hashtest-256g) printf '%s\n' "hashtest" ;;
    testapi:version | testapi:sexp) printf '%s\n' "testapi" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

binary_test_name() {
  case "$1" in
    basic-disable-all-hwf) printf '%s\n' "basic" ;;
    hashtest-256g) printf '%s\n' "hashtest" ;;
    testapi:version | testapi:sexp) printf '%s\n' "testapi" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

is_helper_entry() {
  case "$1" in
    testapi:version | testapi:sexp) return 0 ;;
    *) return 1 ;;
  esac
}

is_wrapper_entry() {
  case "$1" in
    basic-disable-all-hwf | hashtest-256g) return 0 ;;
    *) return 1 ;;
  esac
}

inventory_contains() {
  local needle="$1"
  shift
  local entry
  for entry in "$@"; do
    if [[ "${entry}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

validate_requested_test() {
  local test_name="$1"
  shift

  case "${test_name}" in
    testapi)
      fail "testapi is helper-only; use testapi:version or testapi:sexp"
      ;;
    testapi:version | testapi:sexp)
      return 0
      ;;
  esac

  inventory_contains "${test_name}" "$@" || fail "unknown test entry: ${test_name}"
}

build_command_for_test() {
  local test_name="$1"
  local binary_name
  binary_name="$(binary_test_name "${test_name}")"

  case "${test_name}" in
    basic)
      TEST_CMD=("./${binary_name}${EXEEXT}")
      ;;
    basic-disable-all-hwf)
      TEST_CMD=("./${binary_name}${EXEEXT}" "--disable-hwf" "all")
      ;;
    hashtest-256g)
      TEST_CMD=("./${binary_name}${EXEEXT}" "--gigs" "256" "SHA1" "SHA256" "SHA512" "SM3")
      ;;
    testapi:version)
      TEST_CMD=("./${binary_name}${EXEEXT}" "version")
      ;;
    testapi:sexp)
      TEST_CMD=("./${binary_name}${EXEEXT}" "sexp")
      ;;
    *)
      TEST_CMD=("./${binary_name}${EXEEXT}")
      ;;
  esac
}

print_command_line() {
  local first=1
  local part

  for part in "${TEST_CMD[@]}"; do
    if [[ "${first}" -eq 1 ]]; then
      printf '%s' "${part}"
      first=0
    else
      printf ' %s' "${part}"
    fi
  done
  printf '\n'
}

compile_test() {
  local test_name="$1"
  local source_name binary_name source_path output_path

  source_name="$(source_test_name "${test_name}")"
  binary_name="$(binary_test_name "${test_name}")"
  source_path="${HARNESS_ROOT}/tests/${source_name}.c"
  output_path="${HARNESS_ROOT}/build/${binary_name}${EXEEXT}"

  require_file "${source_path}"

  if [[ ! -x "${output_path}" ]]; then
    cc \
      -DHAVE_CONFIG_H=1 \
      -I"${SAFE_DIR}/tests/original-build" \
      -I"${HARNESS_ROOT}/tests" \
      -I"${HARNESS_ROOT}/src" \
      -I"${HARNESS_ROOT}/compat" \
      "${source_path}" \
      "${HARNESS_ROOT}/build/compat.o" \
      -L"${STAGE_LIBDIR}" \
      -Wl,-rpath,"${STAGE_LIBDIR}" \
      "${LINKER_KLUDGE_FLAGS[@]}" \
      -pthread \
      -lgcrypt -lgpg-error \
      -o "${output_path}"
  fi

  if is_wrapper_entry "${test_name}"; then
    ln -sfn "../tests/${test_name}" "${HARNESS_ROOT}/build/${test_name}"
  fi
}

run_test() {
  local test_name="$1"
  build_command_for_test "${test_name}"

  (
    cd "${HARNESS_ROOT}/build"
    GCRYPT_IN_REGRESSION_TEST=1 \
    LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "${TEST_CMD[@]}"
  )
}

verify_plumbing() {
  local makefile_path="$1"

  require_file "${makefile_path}"
  require_file "${CONFIG_H}"
  require_file "${BUILD_VARS}"
  require_file "${WRAPPER_BASIC}"
  require_file "${WRAPPER_HASH}"
  require_file "${ORIGINAL_DIR}/compat/compat.c"
  require_file "${ORIGINAL_DIR}/tests/version.c"
  require_file "${ORIGINAL_DIR}/tests/t-secmem.c"

  [[ "${EXEEXT}" == "" ]] || fail "unexpected EXEEXT in ${BUILD_VARS}: ${EXEEXT}"
  [[ "${RUN_LARGE_DATA_TESTS}" == "yes" ]] || fail "unexpected RUN_LARGE_DATA_TESTS in ${BUILD_VARS}: ${RUN_LARGE_DATA_TESTS}"
  [[ "${TESTS_ENVIRONMENT}" == "GCRYPT_IN_REGRESSION_TEST=1" ]] || fail "unexpected TESTS_ENVIRONMENT in ${BUILD_VARS}: ${TESTS_ENVIRONMENT}"
  [[ "${COMPAT_LINUX_SOURCES}" == "compat.c" ]] || fail "unexpected compat source set: ${COMPAT_LINUX_SOURCES}"
  [[ "${LDADD_FOR_TESTS_KLUDGE}" == "-Wl,--disable-new-dtags" ]] || fail "unexpected LDADD_FOR_TESTS_KLUDGE in ${BUILD_VARS}: ${LDADD_FOR_TESTS_KLUDGE}"

  echo "run-original-tests: plumbing inventory-makefile=$(readlink -f "${makefile_path}")"
  echo "run-original-tests: plumbing config=${CONFIG_H}"
  echo "run-original-tests: plumbing vars=${BUILD_VARS}"
  echo "run-original-tests: plumbing generated-header=${GENERATED_DIR}/include/gcrypt.h"
  echo "run-original-tests: plumbing wrapper-basic=$(readlink -f "${HARNESS_ROOT}/tests/basic-disable-all-hwf")"
  echo "run-original-tests: plumbing wrapper-hashtest=$(readlink -f "${HARNESS_ROOT}/tests/hashtest-256g")"
  echo "run-original-tests: plumbing compat-source=$(readlink -f "${HARNESS_ROOT}/compat/compat.c")"
  echo "run-original-tests: plumbing version-source=$(readlink -f "${HARNESS_ROOT}/tests/version.c")"
  echo "run-original-tests: plumbing t-secmem-source=$(readlink -f "${HARNESS_ROOT}/tests/t-secmem.c")"
}

prepare_runtime() {
  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --offline
  "${SCRIPT_DIR}/build-release-lib.sh"
  stage_install_tree
  prepare_harness_tree
}

main() {
  local verify_plumbing_mode=0
  local list_mode=0
  local all_mode=0
  local dry_run_mode=0
  local used_default_subset=0
  local makefile_path
  local local_source_name
  local test_name
  local -a requested_tests=()
  local -a tests=()
  local -a inventory=()

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --verify-plumbing)
        verify_plumbing_mode=1
        ;;
      --list)
        list_mode=1
        ;;
      --all)
        all_mode=1
        ;;
      --dry-run)
        dry_run_mode=1
        ;;
      --)
        shift
        while [[ "$#" -gt 0 ]]; do
          requested_tests+=("$1")
          shift
        done
        break
        ;;
      -*)
        fail "unknown option: $1"
        ;;
      *)
        requested_tests+=("$1")
        ;;
    esac
    shift
  done

  if [[ "${list_mode}" -eq 1 && ( "${all_mode}" -eq 1 || "${dry_run_mode}" -eq 1 || "${#requested_tests[@]}" -gt 0 ) ]]; then
    fail "--list does not accept --all, --dry-run, or explicit test names"
  fi

  makefile_path="$(tests_makefile_path)"
  mapfile -t inventory < <(load_tests_inventory "${makefile_path}")
  load_build_vars

  if [[ "${list_mode}" -eq 1 ]]; then
    if [[ "${verify_plumbing_mode}" -eq 1 ]]; then
      prepare_runtime
      verify_plumbing "${makefile_path}"
    fi
    printf '%s\n' "${inventory[@]}"
    return 0
  fi

  if [[ "${all_mode}" -eq 1 ]]; then
    tests=("${inventory[@]}")
  fi
  if [[ "${#requested_tests[@]}" -gt 0 ]]; then
    tests+=("${requested_tests[@]}")
  fi
  if [[ "${#tests[@]}" -eq 0 ]]; then
    tests=(version t-secmem)
    used_default_subset=1
  fi

  if [[ "${used_default_subset}" -eq 0 ]]; then
    for test_name in "${tests[@]}"; do
      validate_requested_test "${test_name}" "${inventory[@]}"
    done
  fi

  if [[ "${dry_run_mode}" -eq 1 && "${verify_plumbing_mode}" -eq 0 ]]; then
    for test_name in "${tests[@]}"; do
      build_command_for_test "${test_name}"
      print_command_line
    done
    return 0
  fi

  prepare_runtime

  if [[ "${verify_plumbing_mode}" -eq 1 ]]; then
    verify_plumbing "${makefile_path}"
  fi

  if [[ "${dry_run_mode}" -eq 1 ]]; then
    for test_name in "${tests[@]}"; do
      build_command_for_test "${test_name}"
      print_command_line
    done
    return 0
  fi

  compile_compat_object

  for test_name in "${tests[@]}"; do
    local_source_name="$(source_test_name "${test_name}")"
    require_file "${ORIGINAL_DIR}/tests/${local_source_name}.c"
    ln -sfn "${ORIGINAL_DIR}/tests/${local_source_name}.c" \
      "${HARNESS_ROOT}/tests/${local_source_name}.c"
    compile_test "${test_name}"
    run_test "${test_name}"
  done

  echo "run-original-tests: ok (${tests[*]})"
}

main "$@"

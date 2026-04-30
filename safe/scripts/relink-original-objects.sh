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
HARNESS_ROOT="${SAFE_DIR}/target/bootstrap/relink-original-objects"
AUTOMAKE_LIBDIR="$(automake --print-libdir)"
PACKAGE_VERSION="1.10.3"
VERSION_NUMBER_HEX="0x010a03"

fail() {
  echo "relink-original-objects: $*" >&2
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

render_original_header() {
  python3 - "${ORIGINAL_DIR}/src/gcrypt.h.in" "${HARNESS_ROOT}/src/gcrypt.h" <<'PY'
from pathlib import Path
import sys

template = Path(sys.argv[1]).read_text()
rendered = (
    template
    .replace("@configure_input@", "original/libgcrypt20-1.10.3/src/gcrypt.h.in")
    .replace("@VERSION@", "1.10.3")
    .replace("@VERSION_NUMBER@", "0x010a03")
)
Path(sys.argv[2]).write_text(rendered)
PY
}

prepare_harness_tree() {
  local src_stage tests_stage compat_stage build_stage obj_stage
  src_stage="${HARNESS_ROOT}/src"
  tests_stage="${HARNESS_ROOT}/tests"
  compat_stage="${HARNESS_ROOT}/compat"
  build_stage="${HARNESS_ROOT}/build"
  obj_stage="${HARNESS_ROOT}/obj"

  rm -rf "${HARNESS_ROOT}"
  mkdir -p "${src_stage}" "${tests_stage}" "${compat_stage}" "${build_stage}" "${obj_stage}"

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${src_stage}/$(basename "${file}")"
  done < <(find "${ORIGINAL_DIR}/src" -maxdepth 1 -type f -print0)
  render_original_header

  ln -s "${ORIGINAL_DIR}/compat/compat.c" "${compat_stage}/compat.c"
  ln -s "${ORIGINAL_DIR}/compat/libcompat.h" "${compat_stage}/libcompat.h"

  while IFS= read -r -d '' file; do
    ln -s "${file}" "${tests_stage}/$(basename "${file}")"
    if [[ "${file}" != *.c ]]; then
      ln -s "${file}" "${build_stage}/$(basename "${file}")"
    fi
  done < <(find "${ORIGINAL_DIR}/tests" -maxdepth 1 -type f -print0)
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
    -DUSE_RSA=1 \
    -DUSE_DSA=1 \
    -DUSE_ECC=1 \
    -DPACKAGE_BUGREPORT=\"devnull@example.org\" \
    -I"${SAFE_DIR}/tests/original-build" \
    -I"${HARNESS_ROOT}/tests" \
    -I"${HARNESS_ROOT}/src" \
    -I"${HARNESS_ROOT}/compat" \
    -pthread \
    ${extra_link:+${extra_link}}
}

compile_compat_object() {
  mapfile -t compile_args < <(common_compile_args)
  cc \
    "${compile_args[@]}" \
    -c "${HARNESS_ROOT}/compat/compat.c" \
    -o "${HARNESS_ROOT}/obj/compat.o"
}

compile_test_object() {
  local test_name="$1"
  local source_path object_path

  source_path="${HARNESS_ROOT}/tests/${test_name}.c"
  object_path="${HARNESS_ROOT}/obj/${test_name}.o"
  require_file "${source_path}"

  mapfile -t compile_args < <(common_compile_args)
  cc \
    "${compile_args[@]}" \
    -c "${source_path}" \
    -o "${object_path}"
}

link_test_binary() {
  local test_name="$1"
  local output_path

  output_path="${HARNESS_ROOT}/build/${test_name}"
  cc \
    "${HARNESS_ROOT}/obj/${test_name}.o" \
    "${HARNESS_ROOT}/obj/compat.o" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -pthread \
    -lgcrypt -lgpg-error \
    -o "${output_path}"
}

run_test_binary() {
  local test_name="$1"

  (
    cd "${HARNESS_ROOT}/build"
    GCRYPT_IN_REGRESSION_TEST=1 \
    LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "./${test_name}"
  )
}

run_testapi_binary() {
  (
    cd "${HARNESS_ROOT}/build"
    GCRYPT_IN_REGRESSION_TEST=1 \
    LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      ./testapi version "${PACKAGE_VERSION}"
    GCRYPT_IN_REGRESSION_TEST=1 \
    LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      ./testapi sexp
  )
}

load_relink_inventory() {
  python3 - "${ORIGINAL_DIR}/tests/Makefile.am" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text().splitlines()
current = None
buffer = []
values = []

def flush():
    global current, buffer, values
    if current not in {"tests_bin", "tests_bin_last"}:
        return
    joined = " ".join(buffer).replace("\\", " ")
    for token in joined.split():
        if token.startswith("$("):
            continue
        values.append(token)

for raw in text:
    line = raw.split("#", 1)[0].rstrip()
    if not line:
        continue
    match = re.match(r"^(tests_bin(?:_last)?)\s*(\+?=)\s*(.*)$", line)
    if match:
      flush()
      current = match.group(1)
      buffer = [match.group(3)]
      continue
    if current and (raw.startswith(" ") or raw.startswith("\t")):
      buffer.append(line)
      continue
    flush()
    current = None
    buffer = []

flush()
values.append("testapi")
print("\n".join(values))
PY
}

usage() {
  cat <<'EOF'
Usage: relink-original-objects.sh [--all] [test-name ...]
EOF
}

main() {
  local tests=()
  local requested=()
  local test_name

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --all)
        ;;
      --help|-h)
        usage
        return 0
        ;;
      --)
        shift
        while [[ "$#" -gt 0 ]]; do
          requested+=("$1")
          shift
        done
        break
        ;;
      -*)
        fail "unknown option: $1"
        ;;
      *)
        requested+=("$1")
        ;;
    esac
    shift
  done

  "${SCRIPT_DIR}/check-rust-toolchain.sh"
  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --locked --offline
  "${SCRIPT_DIR}/build-release-lib.sh"
  stage_install_tree
  prepare_harness_tree
  compile_compat_object

  while IFS= read -r test_name; do
    [[ -n "${test_name}" ]] || continue
    tests+=("${test_name}")
  done < <(load_relink_inventory)

  if [[ "${#requested[@]}" -gt 0 ]]; then
    tests=("${requested[@]}")
  fi

  [[ "${#tests[@]}" -gt 0 ]] || fail "test inventory is empty"

  for test_name in "${tests[@]}"; do
    compile_test_object "${test_name}"
    link_test_binary "${test_name}"
    if [[ "${test_name}" == "testapi" ]]; then
      run_testapi_binary
    else
      run_test_binary "${test_name}"
    fi
  done

  echo "relink-original-objects: ok (${tests[*]})"
}

main "$@"

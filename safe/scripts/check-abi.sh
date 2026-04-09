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
STAGE_PKGCONFIG="${STAGE_LIBDIR}/pkgconfig"
STAGE_INCLUDEDIR="${STAGE_PREFIX}/include"
STAGE_BINDIR="${STAGE_PREFIX}/bin"
STAGE_ACLOCAL="${STAGE_PREFIX}/share/aclocal"
RELEASE_LIBDIR="${SAFE_DIR}/target/release"

fail() {
  echo "check-abi: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

stage_install_tree() {
  mkdir -p "${STAGE_LIBDIR}" "${STAGE_PKGCONFIG}" "${STAGE_INCLUDEDIR}" "${STAGE_BINDIR}" "${STAGE_ACLOCAL}"

  require_file "${RELEASE_LIBDIR}/libgcrypt.so"
  require_file "${RELEASE_LIBDIR}/libgcrypt.a"
  require_file "${GENERATED_DIR}/include/gcrypt.h"
  require_file "${GENERATED_DIR}/pkgconfig/libgcrypt.pc"
  require_file "${GENERATED_DIR}/bin/libgcrypt-config"

  cp "${RELEASE_LIBDIR}/libgcrypt.so" "${STAGE_LIBDIR}/libgcrypt.so.20"
  ln -sfn "libgcrypt.so.20" "${STAGE_LIBDIR}/libgcrypt.so"
  cp "${RELEASE_LIBDIR}/libgcrypt.a" "${STAGE_LIBDIR}/libgcrypt.a"
  cp "${GENERATED_DIR}/include/gcrypt.h" "${STAGE_INCLUDEDIR}/gcrypt.h"
  cp "${GENERATED_DIR}/pkgconfig/libgcrypt.pc" "${STAGE_PKGCONFIG}/libgcrypt.pc"
  cp "${GENERATED_DIR}/bin/libgcrypt-config" "${STAGE_BINDIR}/libgcrypt-config"
  cp "${SAFE_DIR}/abi/libgcrypt.m4" "${STAGE_ACLOCAL}/libgcrypt.m4"
  chmod +x "${STAGE_BINDIR}/libgcrypt-config"
}

check_thread_header_smoke() {
  local tmpdir smoke_c smoke_bin
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-thread.XXXXXX")"
  smoke_c="${tmpdir}/thread-smoke.c"
  smoke_bin="${tmpdir}/thread-smoke"

  cat >"${smoke_c}" <<'EOF'
#include <gcrypt.h>
#include <stdio.h>

GCRY_THREAD_OPTION_PTH_IMPL;
GCRY_THREAD_OPTION_PTHREAD_IMPL;

static void smoke(gcry_md_hd_t hd) {
  gcry_cipher_reset(NULL);
  gcry_fast_random_poll();
  (void)gcry_fips_mode_active();
  if (hd) {
    gcry_md_putc(hd, 'x');
    gcry_md_final(hd);
  }
}

int main(void) {
  struct gcry_thread_cbs cbs = {
    GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)
  };
  struct gcry_md_handle handle = {0};
  gcry_kdf_thread_ops_t ops = {0};
  (void)cbs;
  (void)ops;
  smoke(&handle);
  return 0;
}
EOF

  cc \
    -I"${STAGE_INCLUDEDIR}" \
    "${smoke_c}" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error \
    -o "${smoke_bin}"

  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${smoke_bin}"
  rm -rf "${tmpdir}"
}

check_variadic_smoke() {
  local tmpdir smoke_c smoke_bin
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-varargs.XXXXXX")"
  smoke_c="${tmpdir}/variadic-smoke.c"
  smoke_bin="${tmpdir}/variadic-smoke"

  cat >"${smoke_c}" <<'EOF'
#include <gcrypt.h>
#include <stdio.h>

int main(void) {
  gcry_sexp_t sexp = NULL;
  size_t erroff = 0;

  (void)gcry_control(GCRYCTL_SET_VERBOSITY, 0);
  (void)gcry_sexp_build(&sexp, &erroff, "(data)");
  (void)gcry_sexp_vlist(NULL, NULL);
  (void)gcry_sexp_extract_param(sexp, NULL, "", NULL);
  gcry_log_debug("bootstrap smoke %d", 1);
  return 0;
}
EOF

  cc \
    -I"${STAGE_INCLUDEDIR}" \
    "${smoke_c}" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error \
    -o "${smoke_bin}"

  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${smoke_bin}"
  rm -rf "${tmpdir}"
}

check_thread_cbs_noop() {
  local tmpdir probe_c probe_bin
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-thread-cbs.XXXXXX")"
  probe_c="${tmpdir}/thread-cbs-noop.c"
  probe_bin="${tmpdir}/thread-cbs-noop"

  cat >"${probe_c}" <<'EOF'
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int
die(const char *message, int value)
{
  fprintf(stderr, "thread-cbs-noop: %s (%d)\n", message, value);
  return 1;
}

int
main(void)
{
  int rng = -1;

  if (gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("unexpected initialization before probe", 0);

  if (gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM))
    return die("SET_PREFERRED_RNG_TYPE failed", 0);

  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng))
    return die("GET_CURRENT_RNG_TYPE before noop failed", 0);
  if (rng != GCRY_RNG_TYPE_SYSTEM)
    return die("preferred RNG type was not applied", rng);

  if (gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread))
    return die("SET_THREAD_CBS failed", 0);

  if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("SET_THREAD_CBS did not force initialization", 0);

  rng = -1;
  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng))
    return die("GET_CURRENT_RNG_TYPE after noop failed", 0);
  if (rng != GCRY_RNG_TYPE_STANDARD)
    return die("SET_THREAD_CBS did not reset preferred RNG type", rng);

  if (strcmp(GCRYPT_VERSION, gcry_check_version(NULL)))
    return die("header/library version mismatch", 0);

  return 0;
}
EOF

  cc \
    -I"${STAGE_INCLUDEDIR}" \
    "${probe_c}" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error \
    -o "${probe_bin}"

  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"
  rm -rf "${tmpdir}"
}

check_symbol_inventory() {
  python3 - "${ORIGINAL_DIR}/src/libgcrypt.vers" "${STAGE_LIBDIR}/libgcrypt.so.20" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

expected_text = Path(sys.argv[1]).read_text()
match = re.search(r'GCRYPT_1\.6\s*\{(.*)local:', expected_text, re.S)
if not match:
    raise SystemExit("unable to parse expected version script")
expected = []
for token in re.split(r'[;\s]+', match.group(1)):
    token = token.strip()
    if token and token != "global:":
        expected.append(token)
expected_set = set(expected)

dyn = subprocess.check_output(
    ["readelf", "--dyn-syms", "--wide", sys.argv[2]],
    text=True,
)
actual_set = set()
for line in dyn.splitlines():
    if "@@GCRYPT_1.6" not in line and "@GCRYPT_1.6" not in line:
        continue
    name = line.split()[-1]
    actual_set.add(name.split("@", 1)[0])

missing = sorted(expected_set - actual_set)
extra = sorted(actual_set - expected_set)
if missing or extra:
    if missing:
        print("missing:", ", ".join(missing), file=sys.stderr)
    if extra:
        print("extra:", ", ".join(extra), file=sys.stderr)
    raise SystemExit(1)
if len(actual_set) != 217:
    raise SystemExit(f"expected 217 exports, saw {len(actual_set)}")
PY
}

main() {
  local thread_cbs_noop_mode=0

  if [[ "${1:-}" == "--bootstrap" ]]; then
    shift
  fi
  if [[ "${1:-}" == "--thread-cbs-noop" ]]; then
    thread_cbs_noop_mode=1
    shift
  fi

  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --offline
  stage_install_tree

  require_file "${STAGE_LIBDIR}/libgcrypt.so.20"
  require_file "${STAGE_LIBDIR}/libgcrypt.so"
  require_file "${STAGE_LIBDIR}/libgcrypt.a"
  require_file "${STAGE_INCLUDEDIR}/gcrypt.h"
  require_file "${STAGE_BINDIR}/libgcrypt-config"
  require_file "${STAGE_PKGCONFIG}/libgcrypt.pc"
  require_file "${STAGE_ACLOCAL}/libgcrypt.m4"

  readelf -d "${STAGE_LIBDIR}/libgcrypt.so.20" | grep -q 'SONAME.*libgcrypt.so.20' \
    || fail "shared object SONAME is not libgcrypt.so.20"
  grep -q '^GCRYPT_1.6' "${SAFE_DIR}/abi/libgcrypt.vers" \
    || fail "version script input does not define GCRYPT_1.6"

  grep -q 'struct gcry_thread_cbs' "${STAGE_INCLUDEDIR}/gcrypt.h" \
    || fail "generated header lost struct gcry_thread_cbs"
  grep -q 'GCRY_THREAD_OPTION_PTH_IMPL' "${STAGE_INCLUDEDIR}/gcrypt.h" \
    || fail "generated header lost GCRY_THREAD_OPTION_PTH_IMPL"
  grep -q 'GCRY_THREAD_OPTION_PTHREAD_IMPL' "${STAGE_INCLUDEDIR}/gcrypt.h" \
    || fail "generated header lost GCRY_THREAD_OPTION_PTHREAD_IMPL"
  grep -q 'typedef struct gcry_md_handle' "${STAGE_INCLUDEDIR}/gcrypt.h" \
    || fail "generated header lost gcry_md_handle layout"
  grep -q 'gcry_kdf_thread_ops_t' "${STAGE_INCLUDEDIR}/gcrypt.h" \
    || fail "generated header lost gcry_kdf_thread_ops_t"

  if [[ "${thread_cbs_noop_mode}" -eq 1 ]]; then
    check_thread_cbs_noop
    echo "check-abi: ok"
    return 0
  fi

  check_thread_header_smoke
  check_variadic_smoke

  local pc_libs config_libs
  pc_libs="$(PKG_CONFIG_LIBDIR="${STAGE_PKGCONFIG}" PKG_CONFIG_PATH= pkg-config --libs libgcrypt | xargs)"
  [[ "${pc_libs}" == *"-lgcrypt"* ]] || fail "pkg-config --libs does not include -lgcrypt"
  [[ "${pc_libs}" != *"-lgpg-error"* ]] || fail "pkg-config --libs unexpectedly includes -lgpg-error"

  config_libs="$("${STAGE_BINDIR}/libgcrypt-config" --libs | xargs)"
  [[ "${config_libs}" == "-lgcrypt" ]] || fail "libgcrypt-config --libs output mismatch: ${config_libs}"
  [[ "${config_libs}" != *"-L/usr/lib"* ]] || fail "libgcrypt-config emitted a standard -L path"
  [[ "${config_libs}" != *"-L/lib/"* ]] || fail "libgcrypt-config emitted a standard -L path"

  check_symbol_inventory || fail "exported symbol inventory mismatch"

  echo "check-abi: ok"
}

main "$@"

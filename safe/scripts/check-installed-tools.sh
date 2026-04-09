#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR=
FIXTURE_DIR="${SAFE_DIR}/tests/compat/tool-fixtures"
PUBLIC_SMOKE_SOURCE="${SAFE_DIR}/tests/compat/public-api-smoke.c"

usage() {
  cat <<'EOF'
Usage: check-installed-tools.sh --dist PATH
EOF
}

fail() {
  echo "check-installed-tools: $*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

[[ -n "${DIST_DIR}" ]] || fail "--dist is required"
[[ -d "${DIST_DIR}" ]] || fail "missing dist directory: ${DIST_DIR}"

shopt -s nullglob
runtime_debs=("${DIST_DIR}"/libgcrypt20_*.deb)
dev_debs=("${DIST_DIR}"/libgcrypt20-dev_*.deb)
shopt -u nullglob
[[ "${#runtime_debs[@]}" -eq 1 ]] || fail "expected exactly one runtime package"
[[ "${#dev_debs[@]}" -eq 1 ]] || fail "expected exactly one development package"

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

TMPDIR_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_ROOT}"' EXIT
SYSROOT="${TMPDIR_ROOT}/sysroot"
mkdir -p "${SYSROOT}"
dpkg-deb -x "${runtime_debs[0]}" "${SYSROOT}"
dpkg-deb -x "${dev_debs[0]}" "${SYSROOT}"

multiarch_dir="$(find "${SYSROOT}/usr/lib" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "${multiarch_dir}" ]] || fail "could not determine extracted multiarch directory"
MULTIARCH="$(basename "${multiarch_dir}")"
LIBDIR="${SYSROOT}/usr/lib/${MULTIARCH}"
INCLUDEDIR="${SYSROOT}/usr/include"
BINDIR="${SYSROOT}/usr/bin"
PKGCONFIGDIR="${LIBDIR}/pkgconfig"
ACLOCALDIR="${SYSROOT}/usr/share/aclocal"
SYSTEM_PKGCONFIG_PATHS="$(pkg-config --variable pc_path pkg-config)"
AUTOMAKE_LIBDIR="$(automake --print-libdir)"
UPSTREAM_LIBGCRYPT="${SAFE_SYSTEM_LIBGCRYPT_PATH:-$(ldconfig -p | awk '/libgcrypt.so\.20 .*=>/ && !found {print $NF; found=1} END {if (!found) exit 1}')}"

[[ -n "${UPSTREAM_LIBGCRYPT}" ]] || fail "could not locate the upstream libgcrypt runtime helper"

require_file "${BINDIR}/dumpsexp"
require_file "${BINDIR}/hmac256"
require_file "${BINDIR}/mpicalc"
require_file "${BINDIR}/libgcrypt-config"
require_file "${INCLUDEDIR}/gcrypt.h"
require_file "${PKGCONFIGDIR}/libgcrypt.pc"
require_file "${ACLOCALDIR}/libgcrypt.m4"
require_file "${FIXTURE_DIR}/sexp.txt"
require_file "${FIXTURE_DIR}/sexp.hex"
require_file "${FIXTURE_DIR}/hmac-text.txt"
require_file "${FIXTURE_DIR}/hmac-stdkey.bin"
require_file "${FIXTURE_DIR}/mpicalc-basic.txt"

run_with_sysroot() {
  (
    unset LD_PRELOAD
    export LD_LIBRARY_PATH="${LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
    export SAFE_SYSTEM_LIBGCRYPT_PATH="${UPSTREAM_LIBGCRYPT}"
    exec "$@"
  )
}

trim() {
  xargs <<<"$1"
}

check_dumpsexp() {
  local output

  run_with_sysroot "${BINDIR}/dumpsexp" --help >/dev/null
  output="$(run_with_sysroot "${BINDIR}/dumpsexp" --version)"
  grep -Fq 'dumpsexp (Libgcrypt) 1.10.3' <<<"${output}" || fail "unexpected dumpsexp --version output"

  output="$(run_with_sysroot "${BINDIR}/dumpsexp" <"${FIXTURE_DIR}/sexp.txt")"
  [[ "${output}" == '(data (flags raw) (value #01020304#) (label phase9))' ]] \
    || fail "dumpsexp parsed fixture output mismatch"

  output="$(run_with_sysroot "${BINDIR}/dumpsexp" --assume-hex <"${FIXTURE_DIR}/sexp.hex")"
  [[ "${output}" == '(data (flags raw) (value #01020304#) (label phase9))' ]] \
    || fail "dumpsexp --assume-hex output mismatch"
}

check_hmac256() {
  local output digest size

  output="$(run_with_sysroot "${BINDIR}/hmac256" --version)"
  grep -Fq 'hmac256 (Libgcrypt) 1.10.3' <<<"${output}" || fail "unexpected hmac256 --version output"

  output="$(run_with_sysroot "${BINDIR}/hmac256" phase9-text-key "${FIXTURE_DIR}/hmac-text.txt")"
  [[ "${output}" == "25a221fd3af10a866d233849e45d0abcd11fd18c41a1758610359a40ae41fcd3  ${FIXTURE_DIR}/hmac-text.txt" ]] \
    || fail "hmac256 text-mode output mismatch"

  run_with_sysroot "${BINDIR}/hmac256" --binary --stdkey "${FIXTURE_DIR}/hmac-stdkey.bin" >"${TMPDIR_ROOT}/hmac.bin"
  size="$(wc -c <"${TMPDIR_ROOT}/hmac.bin")"
  [[ "${size}" -eq 32 ]] || fail "hmac256 --binary output length mismatch"
  digest="$(python3 - "${TMPDIR_ROOT}/hmac.bin" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).read_bytes().hex())
PY
)"
  [[ "${digest}" == "43f70a0dee63c349701b9ae2cae46d5e98750a155fa0b95b9bd60ff0b5164a0b" ]] \
    || fail "hmac256 --binary digest mismatch"
}

check_mpicalc() {
  local output

  output="$(run_with_sysroot "${BINDIR}/mpicalc" --version)"
  grep -Fq 'mpicalc 2.0' <<<"${output}" || fail "unexpected mpicalc --version output"
  grep -Fq 'libgcrypt 1.10.3' <<<"${output}" || fail "unexpected mpicalc libgcrypt version"

  output="$(run_with_sysroot "${BINDIR}/mpicalc" --print-config)"
  grep -Fq 'version:1.10.3' <<<"${output}" || fail "mpicalc --print-config missing version"
  grep -Fq 'rng-type:standard:' <<<"${output}" \
    || fail "mpicalc --print-config missing rng-type"

  set +e
  run_with_sysroot "${BINDIR}/mpicalc" <"${FIXTURE_DIR}/mpicalc-basic.txt" >"${TMPDIR_ROOT}/mpicalc.out" 2>"${TMPDIR_ROOT}/mpicalc.err"
  rc=$?
  set -e
  [[ "${rc}" -eq 0 ]] || fail "mpicalc basic transcript exited with ${rc}"
  [[ "$(cat "${TMPDIR_ROOT}/mpicalc.out")" == '05' ]] || fail "mpicalc basic transcript stdout mismatch"
  [[ ! -s "${TMPDIR_ROOT}/mpicalc.err" ]] || fail "mpicalc basic transcript wrote to stderr"
}

compile_probe() {
  local output="$1"
  shift
  cc "$@" -o "${output}"
}

run_probe() {
  run_with_sysroot "$1"
}

check_pkg_config_surface() {
  local output="${TMPDIR_ROOT}/public-api-pkg-config"
  local cflags libs

  cflags="$(PKG_CONFIG_SYSROOT_DIR="${SYSROOT}" PKG_CONFIG_LIBDIR="${PKGCONFIGDIR}:${SYSTEM_PKGCONFIG_PATHS}" PKG_CONFIG_PATH= pkg-config --cflags libgcrypt)"
  libs="$(PKG_CONFIG_SYSROOT_DIR="${SYSROOT}" PKG_CONFIG_LIBDIR="${PKGCONFIGDIR}:${SYSTEM_PKGCONFIG_PATHS}" PKG_CONFIG_PATH= pkg-config --libs libgcrypt)"
  [[ "$(trim "${libs}")" == "-L${SYSROOT}/usr/lib/${MULTIARCH} -lgcrypt" ]] || fail "pkg-config --libs drifted"

  # shellcheck disable=SC2086
  compile_probe \
    "${output}" \
    ${cflags} \
    "${PUBLIC_SMOKE_SOURCE}" \
    -Wl,-rpath,"${LIBDIR}" \
    ${libs} \
    -lgpg-error
  run_probe "${output}"
}

check_libgcrypt_config_surface() {
  local output="${TMPDIR_ROOT}/public-api-config"
  local cflags libs

  cflags="$("${BINDIR}/libgcrypt-config" --cflags)"
  libs="$("${BINDIR}/libgcrypt-config" --libs)"
  [[ -z "$(trim "${cflags}")" ]] || fail "libgcrypt-config --cflags drifted"
  [[ "$(trim "${libs}")" == "-lgcrypt" ]] || fail "libgcrypt-config --libs drifted"

  # shellcheck disable=SC2086
  compile_probe \
    "${output}" \
    -I"${INCLUDEDIR}" \
    ${cflags} \
    "${PUBLIC_SMOKE_SOURCE}" \
    -L"${LIBDIR}" \
    -Wl,-rpath,"${LIBDIR}" \
    ${libs} \
    -lgpg-error
  run_probe "${output}"
}

check_libgcrypt_m4_surface() {
  local tmpdir configure_ac makefile_in makefile
  tmpdir="$(mktemp -d "${TMPDIR_ROOT}/m4.XXXXXX")"
  configure_ac="${tmpdir}/configure.ac"
  makefile_in="${tmpdir}/Makefile.in"
  makefile="${tmpdir}/Makefile"

  cat >"${configure_ac}" <<EOF
m4_include([${ACLOCALDIR}/libgcrypt.m4])
AC_INIT([libgcrypt-installed-smoke], [0.1])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR([.])
AC_CANONICAL_HOST
AC_PROG_CC
AM_PATH_LIBGCRYPT([1:1.10.3], [], [AC_MSG_ERROR([libgcrypt not found])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
EOF

  cat >"${makefile_in}" <<'EOF'
LIBGCRYPT_CFLAGS=@LIBGCRYPT_CFLAGS@
LIBGCRYPT_LIBS=@LIBGCRYPT_LIBS@
EOF

  cp "${AUTOMAKE_LIBDIR}/config.sub" "${tmpdir}/config.sub"
  cp "${AUTOMAKE_LIBDIR}/config.guess" "${tmpdir}/config.guess"
  (
    cd "${tmpdir}"
    PATH="${BINDIR}:${PATH}" LIBGCRYPT_CONFIG="${BINDIR}/libgcrypt-config" autoconf
    PATH="${BINDIR}:${PATH}" LIBGCRYPT_CONFIG="${BINDIR}/libgcrypt-config" ./configure >/dev/null
  )

  grep -Fxq 'LIBGCRYPT_CFLAGS=' "${makefile}" || fail "libgcrypt.m4 configure smoke produced unexpected CFLAGS"
  grep -Fxq 'LIBGCRYPT_LIBS=-lgcrypt' "${makefile}" || fail "libgcrypt.m4 configure smoke produced unexpected LIBS"
}

check_dumpsexp
check_hmac256
check_mpicalc
check_pkg_config_surface
check_libgcrypt_config_surface
check_libgcrypt_m4_surface

echo "check-installed-tools: ok"

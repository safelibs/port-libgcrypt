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
STAGE_PKGCONFIG="${STAGE_LIBDIR}/pkgconfig"
STAGE_INCLUDEDIR="${STAGE_PREFIX}/include"
STAGE_BINDIR="${STAGE_PREFIX}/bin"
STAGE_ACLOCAL="${STAGE_PREFIX}/share/aclocal"
RELEASE_LIBDIR="${SAFE_DIR}/target/release"
COMPAT_DIR="${SAFE_DIR}/tests/compat"
HARNESS_ROOT="${SAFE_DIR}/target/bootstrap/compat-smoke"
AUTOMAKE_LIBDIR="$(automake --print-libdir)"
SYSTEM_PKGCONFIG_PATHS="$(pkg-config --variable pc_path pkg-config)"

fail() {
  echo "run-compat-smoke: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

stage_install_tree() {
  mkdir -p "${STAGE_LIBDIR}" "${STAGE_INCLUDEDIR}" "${STAGE_PKGCONFIG}" "${STAGE_BINDIR}" "${STAGE_ACLOCAL}"
  cp "${SAFE_DIR}/target/release/libgcrypt.so" "${STAGE_LIBDIR}/libgcrypt.so.20"
  ln -sfn "libgcrypt.so.20" "${STAGE_LIBDIR}/libgcrypt.so"
  cp "${SAFE_DIR}/target/release/libgcrypt.a" "${STAGE_LIBDIR}/libgcrypt.a"
  cp "${GENERATED_DIR}/include/gcrypt.h" "${STAGE_INCLUDEDIR}/gcrypt.h"
  cp "${GENERATED_DIR}/pkgconfig/libgcrypt.pc" "${STAGE_PKGCONFIG}/libgcrypt.pc"
  cp "${GENERATED_DIR}/bin/libgcrypt-config" "${STAGE_BINDIR}/libgcrypt-config"
  cp "${SAFE_DIR}/abi/libgcrypt.m4" "${STAGE_ACLOCAL}/libgcrypt.m4"
  chmod +x "${STAGE_BINDIR}/libgcrypt-config"
}

compile_probe() {
  local output="$1"
  shift
  cc "$@" -o "${output}"
}

run_probe() {
  local binary="$1"
  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${binary}"
}

compile_generated_surface_probe() {
  local output="${HARNESS_ROOT}/public-api-generated"
  compile_probe \
    "${output}" \
    -I"${GENERATED_DIR}/include" \
    "${COMPAT_DIR}/public-api-smoke.c" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error
  run_probe "${output}"
}

compile_pkg_config_probe() {
  local output="${HARNESS_ROOT}/public-api-pkg-config"
  local cflags libs

  cflags="$(PKG_CONFIG_SYSROOT_DIR="${STAGE_ROOT}" PKG_CONFIG_LIBDIR="${STAGE_PKGCONFIG}:${SYSTEM_PKGCONFIG_PATHS}" PKG_CONFIG_PATH= pkg-config --cflags libgcrypt)"
  libs="$(PKG_CONFIG_SYSROOT_DIR="${STAGE_ROOT}" PKG_CONFIG_LIBDIR="${STAGE_PKGCONFIG}:${SYSTEM_PKGCONFIG_PATHS}" PKG_CONFIG_PATH= pkg-config --libs libgcrypt)"
  # shellcheck disable=SC2086
  compile_probe \
    "${output}" \
    ${cflags} \
    "${COMPAT_DIR}/public-api-smoke.c" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    ${libs}
  run_probe "${output}"
}

compile_config_probe() {
  local output="${HARNESS_ROOT}/public-api-config"
  local cflags libs

  cflags="$("${STAGE_BINDIR}/libgcrypt-config" --cflags)"
  libs="$("${STAGE_BINDIR}/libgcrypt-config" --libs)"
  # shellcheck disable=SC2086
  compile_probe \
    "${output}" \
    -I"${STAGE_INCLUDEDIR}" \
    ${cflags} \
    "${COMPAT_DIR}/public-api-smoke.c" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    ${libs} \
    -lgpg-error
  run_probe "${output}"
}

check_pk_register_version() {
  objdump -T "${STAGE_LIBDIR}/libgcrypt.so.20" | grep -Eq 'gcry_pk_register[[:space:]]*$' \
    || fail "gcry_pk_register is missing from the dynamic symbol table"
  objdump -T "${STAGE_LIBDIR}/libgcrypt.so.20" | grep -Eq 'gcry_pk_register[[:space:]].*GCRYPT_1\.6|GCRYPT_1\.6[[:space:]]+gcry_pk_register' \
    || fail "gcry_pk_register is not exported with GCRYPT_1.6"
}

compile_abi_only_probe() {
  local output="${HARNESS_ROOT}/abi-only-exports"

  compile_probe \
    "${output}" \
    -I"${STAGE_INCLUDEDIR}" \
    "${COMPAT_DIR}/abi-only-exports.c" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -ldl -lgcrypt -lgpg-error
  run_probe "${output}"
}

run_m4_smoke() {
  local tmpdir configure_ac makefile_in makefile
  tmpdir="$(mktemp -d "${HARNESS_ROOT}/libgcrypt-m4.XXXXXX")"
  configure_ac="${tmpdir}/configure.ac"
  makefile_in="${tmpdir}/Makefile.in"
  makefile="${tmpdir}/Makefile"

  cat >"${configure_ac}" <<EOF
m4_include([${STAGE_ACLOCAL}/libgcrypt.m4])
AC_INIT([libgcrypt-compat-smoke], [0.1])
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
    PATH="${STAGE_BINDIR}:${PATH}" LIBGCRYPT_CONFIG="${STAGE_BINDIR}/libgcrypt-config" autoconf
    PATH="${STAGE_BINDIR}:${PATH}" LIBGCRYPT_CONFIG="${STAGE_BINDIR}/libgcrypt-config" ./configure >/dev/null
  )

  grep -Fxq 'LIBGCRYPT_CFLAGS=' "${makefile}" || fail "libgcrypt.m4 configure smoke produced unexpected CFLAGS"
  grep -Fxq 'LIBGCRYPT_LIBS=-lgcrypt' "${makefile}" || fail "libgcrypt.m4 configure smoke produced unexpected LIBS"
  rm -rf "${tmpdir}"
}

usage() {
  cat <<'EOF'
Usage: run-compat-smoke.sh [--all]
EOF
}

main() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --all)
        ;;
      --help|-h)
        usage
        return 0
        ;;
      -*)
        fail "unknown option: $1"
        ;;
      *)
        fail "unexpected argument: $1"
        ;;
    esac
    shift
  done

  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --offline
  mkdir -p "${HARNESS_ROOT}"
  stage_install_tree

  require_file "${COMPAT_DIR}/public-api-smoke.c"
  require_file "${COMPAT_DIR}/abi-only-exports.c"
  require_file "${STAGE_PKGCONFIG}/libgcrypt.pc"
  require_file "${STAGE_BINDIR}/libgcrypt-config"
  require_file "${STAGE_ACLOCAL}/libgcrypt.m4"

  compile_generated_surface_probe
  compile_pkg_config_probe
  compile_config_probe
  check_pk_register_version
  compile_abi_only_probe
  run_m4_smoke

  echo "run-compat-smoke: ok"
}

main "$@"

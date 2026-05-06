#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gcry-eddsa-testkey-import-seed: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-eddsa-testkey.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

probe_c="${tmpdir}/probe.c"
probe_bin="${tmpdir}/probe"
probe_lib_dir="${tmpdir}/lib"
mkdir -p "${probe_lib_dir}"
ln -sf "${RELEASE_LIB}" "${probe_lib_dir}/libgcrypt.so.20"

cat >"${probe_c}" <<'EOF'
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
die_gcry(const char *where, gcry_error_t err)
{
  if (err)
    {
      fprintf(stderr, "%s: %s (%u)\n", where, gpg_strerror(err), gcry_err_code(err));
      exit(2);
    }
}

int
main(void)
{
  gcry_sexp_t key = NULL;

  gcry_check_version(NULL);
  die_gcry("gcry_sexp_sscan",
           gcry_sexp_sscan(
             &key, NULL,
             "(private-key(ecc(curve \"Ed25519\")"
             "(q #40133581914ee3b641ca0526624140b4e0b89a97216d472b7cd34a817e48c247de#)"
             "(d #f82c389a199ac49b8ba52505161f59ebf86aee18d4a9cfa90e9993bdf1f8316c#)))",
             0));
  die_gcry("gcry_pk_testkey", gcry_pk_testkey(key));
  gcry_sexp_release(key);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${probe_lib_dir}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${probe_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gcry-eddsa-testkey-import-seed: ok"

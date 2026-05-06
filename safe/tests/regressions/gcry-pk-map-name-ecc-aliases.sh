#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gcry-pk-map-name-ecc-aliases: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-pk-map-name.XXXXXX")"
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

static void
check_alias(const char *name)
{
  int algo = gcry_pk_map_name(name);

  if (algo != GCRY_PK_ECC)
    {
      fprintf(stderr, "%s mapped to %d, expected GCRY_PK_ECC (%d)\n",
              name, algo, GCRY_PK_ECC);
      exit(2);
    }
}

int
main(void)
{
  gcry_check_version(NULL);
  check_alias("ecc");
  check_alias("ecdsa");
  check_alias("ecdh");
  check_alias("eddsa");
  check_alias("EdDSA");
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${probe_lib_dir}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${probe_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gcry-pk-map-name-ecc-aliases: ok"

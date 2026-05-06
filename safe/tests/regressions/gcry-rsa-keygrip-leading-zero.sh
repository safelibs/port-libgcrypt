#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gcry-rsa-keygrip-leading-zero: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-rsa-keygrip.XXXXXX")"
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

static gcry_sexp_t
find_token(gcry_sexp_t sexp, const char *name)
{
  gcry_sexp_t token = gcry_sexp_find_token(sexp, name, 0);

  if (!token)
    {
      fprintf(stderr, "missing token: %s\n", name);
      exit(2);
    }
  return token;
}

static gcry_mpi_t
token_mpi(gcry_sexp_t sexp, const char *name)
{
  gcry_sexp_t token = find_token(sexp, name);
  gcry_mpi_t mpi = gcry_sexp_nth_mpi(token, 1, GCRYMPI_FMT_USG);

  gcry_sexp_release(token);
  if (!mpi)
    {
      fprintf(stderr, "missing MPI: %s\n", name);
      exit(2);
    }
  return mpi;
}

int
main(void)
{
  gcry_sexp_t spec = NULL;
  gcry_sexp_t key = NULL;
  gcry_sexp_t secret = NULL;
  gcry_sexp_t rebuilt_public = NULL;
  gcry_mpi_t n = NULL;
  gcry_mpi_t e = NULL;
  unsigned char secret_grip[20];
  unsigned char public_grip[20];

  gcry_check_version(NULL);

  die_gcry("build RSA genkey spec",
           gcry_sexp_build(&spec, NULL,
                           "(genkey(rsa(nbits 2:16)"
                           "(test-parms(p #00fb#)(q #00f1#))))"));
  die_gcry("gcry_pk_genkey", gcry_pk_genkey(&key, spec));

  secret = find_token(key, "private-key");
  n = token_mpi(secret, "n");
  e = token_mpi(secret, "e");

  die_gcry("rebuild public key with %m",
           gcry_sexp_build(&rebuilt_public, NULL,
                           "(public-key(rsa(n%m)(e%m)))", n, e));

  if (!gcry_pk_get_keygrip(secret, secret_grip))
    {
      fprintf(stderr, "gcry_pk_get_keygrip failed for generated private key\n");
      return 2;
    }
  if (!gcry_pk_get_keygrip(rebuilt_public, public_grip))
    {
      fprintf(stderr, "gcry_pk_get_keygrip failed for rebuilt public key\n");
      return 2;
    }

  if (memcmp(secret_grip, public_grip, sizeof(secret_grip)) != 0)
    {
      fprintf(stderr, "RSA keygrip mismatch between generated private key and %%m public key\n");
      return 2;
    }

  gcry_mpi_release(e);
  gcry_mpi_release(n);
  gcry_sexp_release(rebuilt_public);
  gcry_sexp_release(secret);
  gcry_sexp_release(key);
  gcry_sexp_release(spec);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${probe_lib_dir}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${probe_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gcry-rsa-keygrip-leading-zero: ok"

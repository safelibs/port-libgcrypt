#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gcry-x448-ecdh-raw-result: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-x448-ecdh.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

probe_c="${tmpdir}/probe.c"
probe_bin="${tmpdir}/probe"

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

static unsigned char
hex_nibble(char c)
{
  if (c >= '0' && c <= '9')
    return (unsigned char)(c - '0');
  if (c >= 'a' && c <= 'f')
    return (unsigned char)(10 + c - 'a');
  if (c >= 'A' && c <= 'F')
    return (unsigned char)(10 + c - 'A');
  fprintf(stderr, "invalid hex character: %c\n", c);
  exit(2);
}

static void
hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
  if (strlen(hex) != out_len * 2)
    {
      fprintf(stderr, "bad hex length\n");
      exit(2);
    }
  for (size_t i = 0; i < out_len; i++)
    out[i] = (unsigned char)((hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1]));
}

static void
require_bytes(const char *where, const unsigned char *got, size_t got_len,
              const unsigned char *expected, size_t expected_len)
{
  if (got_len != expected_len)
    {
      fprintf(stderr, "%s length mismatch: got %zu expected %zu\n",
              where, got_len, expected_len);
      if (got_len == expected_len + 1 && got[0] == 0x40)
        fprintf(stderr, "%s still has the libgcrypt-incompatible X448 0x40 prefix\n", where);
      exit(2);
    }
  if (memcmp(got, expected, expected_len) != 0)
    {
      fprintf(stderr, "%s bytes mismatch\n", where);
      exit(2);
    }
}

int
main(void)
{
  static const char *k_hex =
      "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
      "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3";
  static const char *u_hex =
      "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
      "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086";
  static const char *expected_hex =
      "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
      "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f";
  unsigned char k[56];
  unsigned char u[56];
  unsigned char expected[56];
  unsigned char low_level[56];
  gcry_mpi_t mpi_k = NULL;
  gcry_sexp_t data = NULL;
  gcry_sexp_t pkey = NULL;
  gcry_sexp_t enc = NULL;
  gcry_sexp_t s_atom = NULL;
  unsigned char *high_level = NULL;
  size_t high_level_len = 0;

  gcry_check_version(NULL);
  hex_to_bytes(k_hex, k, sizeof k);
  hex_to_bytes(u_hex, u, sizeof u);
  hex_to_bytes(expected_hex, expected, sizeof expected);

  die_gcry("gcry_ecc_mul_point",
           gcry_ecc_mul_point(GCRY_ECC_CURVE448, low_level, k, u));
  require_bytes("gcry_ecc_mul_point", low_level, sizeof low_level,
                expected, sizeof expected);

  mpi_k = gcry_mpi_set_opaque_copy(NULL, k, sizeof k * 8);
  die_gcry("build X448 scalar", gcry_sexp_build(&data, NULL, "%m", mpi_k));
  die_gcry("build X448 public key",
           gcry_sexp_build(&pkey, NULL,
                           "(public-key(ecc(curve \"X448\")(q%b)))",
                           (int)sizeof u, u));
  die_gcry("gcry_pk_encrypt", gcry_pk_encrypt(&enc, data, pkey));

  s_atom = gcry_sexp_find_token(enc, "s", 0);
  if (!s_atom)
    {
      fprintf(stderr, "missing X448 shared secret atom\n");
      return 2;
    }
  high_level = gcry_sexp_nth_buffer(s_atom, 1, &high_level_len);
  if (!high_level)
    {
      fprintf(stderr, "missing X448 shared secret bytes\n");
      return 2;
    }
  require_bytes("gcry_pk_encrypt", high_level, high_level_len,
                expected, sizeof expected);

  gcry_free(high_level);
  gcry_sexp_release(s_atom);
  gcry_sexp_release(enc);
  gcry_sexp_release(pkey);
  gcry_sexp_release(data);
  gcry_mpi_release(mpi_k);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${RELEASE_LIB_DIR}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${RELEASE_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gcry-x448-ecdh-raw-result: ok"

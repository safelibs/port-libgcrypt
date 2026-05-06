#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gcry-md-asnoid-sha-family: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-md-asnoid.XXXXXX")"
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

struct case_record
{
  int algo;
  const char *name;
  const unsigned char *asn;
  size_t asn_len;
};

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static const unsigned char md5_asn[] = {
  0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char sha1_asn[] = {
  0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
  0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static const unsigned char sha224_asn[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
  0x1c
};
static const unsigned char sha256_asn[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
  0x20
};
static const unsigned char sha384_asn[] = {
  0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
  0x30
};
static const unsigned char sha512_asn[] = {
  0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
  0x40
};
static const unsigned char sha512_256_asn[] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04,
  0x20
};
static const unsigned char sha512_224_asn[] = {
  0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
  0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04,
  0x1c
};

static void
die_gcry(const char *where, gcry_error_t err)
{
  if (err)
    {
      fprintf(stderr, "%s: %s (%u)\n", where, gpg_strerror(err), gcry_err_code(err));
      exit(2);
    }
}

static void
check_asnoid(const struct case_record *record)
{
  unsigned char buffer[128];
  size_t nbytes = 0;

  die_gcry(record->name, gcry_md_get_asnoid(record->algo, NULL, &nbytes));
  if (nbytes != record->asn_len)
    {
      fprintf(stderr, "%s length mismatch: got %zu expected %zu\n",
              record->name, nbytes, record->asn_len);
      exit(2);
    }

  memset(buffer, 0xa5, sizeof(buffer));
  nbytes = record->asn_len;
  die_gcry(record->name, gcry_md_get_asnoid(record->algo, buffer, &nbytes));
  if (nbytes != record->asn_len || memcmp(buffer, record->asn, record->asn_len) != 0)
    {
      fprintf(stderr, "%s ASN.1 OID mismatch\n", record->name);
      exit(2);
    }

  nbytes = record->asn_len - 1;
  if (gcry_md_get_asnoid(record->algo, buffer, &nbytes) == 0)
    {
      fprintf(stderr, "%s accepted an undersized ASN.1 OID buffer\n", record->name);
      exit(2);
    }
}

int
main(void)
{
  const struct case_record cases[] = {
    { GCRY_MD_MD5, "MD5", md5_asn, sizeof(md5_asn) },
    { GCRY_MD_SHA1, "SHA1", sha1_asn, sizeof(sha1_asn) },
    { GCRY_MD_SHA224, "SHA224", sha224_asn, sizeof(sha224_asn) },
    { GCRY_MD_SHA256, "SHA256", sha256_asn, sizeof(sha256_asn) },
    { GCRY_MD_SHA384, "SHA384", sha384_asn, sizeof(sha384_asn) },
    { GCRY_MD_SHA512, "SHA512", sha512_asn, sizeof(sha512_asn) },
    { GCRY_MD_SHA512_256, "SHA512_256", sha512_256_asn, sizeof(sha512_256_asn) },
    { GCRY_MD_SHA512_224, "SHA512_224", sha512_224_asn, sizeof(sha512_224_asn) },
  };

  gcry_check_version(NULL);
  for (size_t i = 0; i < ARRAY_LEN(cases); i++)
    check_asnoid(&cases[i]);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${probe_lib_dir}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${probe_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gcry-md-asnoid-sha-family: ok"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gpg-curve25519-ecdh-encrypt-ephemeral: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-curve25519-ecdh.XXXXXX")"
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

static unsigned char *
copy_prefixed_atom(gcry_sexp_t sexp, const char *token, size_t *out_len)
{
  gcry_sexp_t found = gcry_sexp_find_token(sexp, token, 0);
  size_t length = 0;
  const unsigned char *data;
  unsigned char *copy;

  if (!found)
    {
      fprintf(stderr, "missing atom: %s\n", token);
      exit(2);
    }

  data = (const unsigned char *)gcry_sexp_nth_data(found, 1, &length);
  if (!data || length != 33 || data[0] != 0x40)
    {
      fprintf(stderr, "unexpected %s atom: len=%zu first=%02x\n",
              token, length, data && length ? data[0] : 0);
      exit(2);
    }

  copy = malloc(length);
  if (!copy)
    {
      fprintf(stderr, "malloc failed\n");
      exit(2);
    }
  memcpy(copy, data, length);
  *out_len = length;
  gcry_sexp_release(found);
  return copy;
}

static void
require_flag(gcry_sexp_t sexp, const char *flag)
{
  gcry_sexp_t flags = gcry_sexp_find_token(sexp, "flags", 0);
  int length;

  if (!flags)
    {
      fprintf(stderr, "missing flags list\n");
      exit(2);
    }

  length = gcry_sexp_length(flags);
  for (int i = 1; i < length; i++)
    {
      size_t atom_len = 0;
      const char *atom = gcry_sexp_nth_data(flags, i, &atom_len);
      if (atom && atom_len == strlen(flag) && memcmp(atom, flag, atom_len) == 0)
        {
          gcry_sexp_release(flags);
          return;
        }
    }

  fprintf(stderr, "missing flag: %s\n", flag);
  exit(2);
}

int
main(void)
{
  unsigned char scalar[32] = {
      0x42, 0x11, 0x9a, 0x7c, 0x63, 0x21, 0x5e, 0x0d,
      0x15, 0xe9, 0x35, 0x51, 0x2a, 0xb0, 0x45, 0x87,
      0xc3, 0xdd, 0x91, 0x2a, 0x09, 0xf8, 0x7e, 0xbc,
      0x8f, 0x4a, 0x2c, 0x6e, 0x71, 0x04, 0xb8, 0x55
  };
  gcry_sexp_t parms = NULL;
  gcry_sexp_t key = NULL;
  gcry_sexp_t pkey = NULL;
  gcry_sexp_t skey = NULL;
  gcry_sexp_t data = NULL;
  gcry_sexp_t enc = NULL;
  gcry_sexp_t plain = NULL;
  unsigned char *shared = NULL;
  unsigned char *ephemeral = NULL;
  unsigned char *decrypted = NULL;
  size_t shared_len = 0;
  size_t ephemeral_len = 0;
  size_t decrypted_len = 0;

  gcry_check_version(NULL);

  die_gcry("build Curve25519 ECDH genkey parms",
           gcry_sexp_build(&parms, NULL,
                           "(genkey(ecc(curve \"Curve25519\")(flags djb-tweak comp)))"));
  die_gcry("gcry_pk_genkey", gcry_pk_genkey(&key, parms));
  pkey = gcry_sexp_find_token(key, "public-key", 0);
  skey = gcry_sexp_find_token(key, "private-key", 0);
  if (!pkey || !skey)
    {
      fprintf(stderr, "generated Curve25519 key is missing public or private half\n");
      return 2;
    }
  require_flag(pkey, "djb-tweak");
  require_flag(skey, "djb-tweak");

  die_gcry("build Curve25519 ECDH scalar",
           gcry_sexp_build(&data, NULL, "(data(flags raw)(value %b))",
                           (int)sizeof(scalar), scalar));
  die_gcry("gcry_pk_encrypt", gcry_pk_encrypt(&enc, data, pkey));

  shared = copy_prefixed_atom(enc, "s", &shared_len);
  ephemeral = copy_prefixed_atom(enc, "e", &ephemeral_len);
  die_gcry("gcry_pk_decrypt", gcry_pk_decrypt(&plain, enc, skey));
  decrypted = copy_prefixed_atom(plain, "value", &decrypted_len);
  if (shared_len != decrypted_len || memcmp(shared, decrypted, shared_len) != 0)
    {
      fprintf(stderr, "decrypted ECDH shared secret does not match encrypt output\n");
      return 2;
    }

  free(decrypted);
  free(ephemeral);
  free(shared);
  gcry_sexp_release(plain);
  gcry_sexp_release(enc);
  gcry_sexp_release(data);
  gcry_sexp_release(skey);
  gcry_sexp_release(pkey);
  gcry_sexp_release(key);
  gcry_sexp_release(parms);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${RELEASE_LIB_DIR}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${RELEASE_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gpg-curve25519-ecdh-encrypt-ephemeral: ok"

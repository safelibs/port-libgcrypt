#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
INCLUDE_DIR="${SAFE_DIR}/target/bootstrap/generated/include"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"

fail() {
  echo "gpg-ed25519-eddsa-genkey-sign: $*" >&2
  exit 1
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
[[ -f "${INCLUDE_DIR}/gcrypt.h" ]] || fail "missing generated gcrypt.h: ${INCLUDE_DIR}/gcrypt.h"

tmpdir="$(mktemp -d "${SAFE_DIR}/target/regression-ed25519-eddsa.XXXXXX")"
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

static void
require_token(gcry_sexp_t sexp, const char *token)
{
  gcry_sexp_t found = gcry_sexp_find_token(sexp, token, 0);
  if (!found)
    {
      fprintf(stderr, "missing token: %s\n", token);
      exit(2);
    }
  gcry_sexp_release(found);
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

static void
require_atom_len(gcry_sexp_t sexp, const char *token, size_t len, int first)
{
  gcry_sexp_t found = gcry_sexp_find_token(sexp, token, 0);
  size_t actual = 0;
  const unsigned char *data;

  if (!found)
    {
      fprintf(stderr, "missing atom token: %s\n", token);
      exit(2);
    }

  data = (const unsigned char *)gcry_sexp_nth_data(found, 1, &actual);
  if (!data || actual != len || (first >= 0 && len && data[0] != (unsigned char)first))
    {
      fprintf(stderr, "unexpected %s atom length/prefix: len=%zu first=%02x\n",
              token, actual, data && actual ? data[0] : 0);
      exit(2);
    }

  gcry_sexp_release(found);
}

int
main(void)
{
  gcry_sexp_t parms = NULL;
  gcry_sexp_t key = NULL;
  gcry_sexp_t pub = NULL;
  gcry_sexp_t sec = NULL;
  gcry_sexp_t data = NULL;
  gcry_sexp_t sig = NULL;
  unsigned char digest[64];

  gcry_check_version(NULL);

  die_gcry("build genkey parms",
           gcry_sexp_build(&parms, NULL,
                           "(genkey(ecc(curve \"Ed25519\")(flags eddsa comp)))"));
  die_gcry("gcry_pk_genkey", gcry_pk_genkey(&key, parms));

  pub = gcry_sexp_find_token(key, "public-key", 0);
  sec = gcry_sexp_find_token(key, "private-key", 0);
  if (!pub || !sec)
    {
      fprintf(stderr, "generated key is missing public or private half\n");
      return 2;
    }

  require_flag(pub, "eddsa");
  require_flag(sec, "eddsa");
  require_atom_len(pub, "q", 33, 0x40);
  require_atom_len(sec, "q", 33, 0x40);
  require_atom_len(sec, "d", 32, -1);

  for (size_t i = 0; i < sizeof(digest); i++)
    digest[i] = (unsigned char)i;

  die_gcry("build eddsa signing data",
           gcry_sexp_build(&data, NULL,
                           "(data(flags eddsa)(hash-algo sha512)(value %b))",
                           (int)sizeof(digest), digest));
  die_gcry("gcry_pk_sign", gcry_pk_sign(&sig, data, sec));
  require_token(sig, "eddsa");
  die_gcry("gcry_pk_verify", gcry_pk_verify(sig, data, pub));

  gcry_sexp_release(sig);
  gcry_sexp_release(data);
  gcry_sexp_release(sec);
  gcry_sexp_release(pub);
  gcry_sexp_release(key);
  gcry_sexp_release(parms);
  return 0;
}
EOF

cc -I"${INCLUDE_DIR}" "${probe_c}" \
  -L"${RELEASE_LIB_DIR}" -Wl,-rpath,"${RELEASE_LIB_DIR}" \
  -lgcrypt -lgpg-error -o "${probe_bin}"

LD_LIBRARY_PATH="${RELEASE_LIB_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"

echo "gpg-ed25519-eddsa-genkey-sign: ok"

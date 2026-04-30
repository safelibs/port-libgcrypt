#include <gcrypt.h>
#include <gpg-error.h>

#include <stdio.h>
#include <string.h>

/* Kept out of the installed header, but still exported for ABI compatibility. */
gcry_err_code_t gcry_md_get(gcry_md_hd_t hd, int algo,
                            unsigned char *buffer, int buflen);
gcry_err_code_t gcry_pk_register(void);

static int
die(const char *message, unsigned long value)
{
  fprintf(stderr, "abi-only-exports: %s (%lu)\n", message, value);
  return 1;
}

int
main(void)
{
  gcry_md_hd_t md = NULL;
  unsigned char digest[64];
  const unsigned char *expected;
  unsigned int digest_len;
  gcry_err_code_t rc;

  if (!gcry_check_version(GCRYPT_VERSION))
    return die("gcry_check_version rejected header version", 0);

  rc = gcry_md_open(&md, GCRY_MD_SHA256, 0);
  if (rc)
    return die("gcry_md_open failed", rc);

  gcry_md_write(md, "compat", 6);
  gcry_md_final(md);

  digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
  if (digest_len == 0 || digest_len > sizeof(digest))
    return die("unexpected SHA256 digest length", digest_len);

  memset(digest, 0, sizeof(digest));
  rc = gcry_md_get(md, GCRY_MD_SHA256, digest, (int)sizeof(digest));
  if (rc)
    return die("gcry_md_get failed", rc);

  expected = gcry_md_read(md, GCRY_MD_SHA256);
  if (!expected)
    return die("gcry_md_read returned NULL", 0);
  if (memcmp(digest, expected, digest_len))
    return die("gcry_md_get digest mismatch", 0);

  gcry_md_close(md);

  rc = gcry_pk_register();
  if (gpg_err_code(rc) != GPG_ERR_NOT_SUPPORTED)
    return die("gcry_pk_register returned unexpected code", rc);

  return 0;
}

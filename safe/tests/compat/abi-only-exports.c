#include <gcrypt.h>
#include <gpg-error.h>

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/* Kept out of the installed header, but still exported for ABI compatibility. */
gcry_err_code_t gcry_md_get(gcry_md_hd_t hd, int algo,
                            unsigned char *buffer, int buflen);

typedef unsigned int (*gcry_pk_register_fn_t)(void);

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
  void *handle;
  gcry_pk_register_fn_t pk_register;

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

  handle = dlopen("libgcrypt.so.20", RTLD_NOW | RTLD_LOCAL);
  if (!handle)
    {
      fprintf(stderr, "abi-only-exports: dlopen failed: %s\n", dlerror());
      return 1;
    }

  pk_register = (gcry_pk_register_fn_t)dlsym(handle, "gcry_pk_register");
  if (!pk_register)
    {
      fprintf(stderr, "abi-only-exports: dlsym failed: %s\n", dlerror());
      dlclose(handle);
      return 1;
    }

  rc = pk_register();
  if (gpg_err_code(rc) != GPG_ERR_NOT_SUPPORTED)
    {
      dlclose(handle);
      return die("gcry_pk_register returned unexpected code", rc);
    }

  dlclose(handle);
  return 0;
}

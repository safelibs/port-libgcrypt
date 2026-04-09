#include <gcrypt.h>
#include <gpg-error.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

GCRY_THREAD_OPTION_PTH_IMPL;
GCRY_THREAD_OPTION_PTHREAD_IMPL;

struct log_capture
{
  int level;
  char message[256];
};

static int
die(const char *message, unsigned long value)
{
  fprintf(stderr, "public-api-smoke: %s (%lu)\n", message, value);
  return 1;
}

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
  struct log_capture *capture = opaque;

  capture->level = level;
  vsnprintf(capture->message, sizeof(capture->message), fmt, ap);
}

int
main(void)
{
  struct log_capture log_capture = {0, {0}};
  gcry_md_hd_t md = NULL;
  gcry_sexp_t first = NULL;
  gcry_sexp_t second = NULL;
  gcry_sexp_t combined = NULL;
  gcry_sexp_t key = NULL;
  gcry_mpi_t mpi_n = NULL;
  gcry_mpi_t mpi_e = NULL;
  int rng_type = -1;
  unsigned int digest_len;
  size_t erroff = 0;
  unsigned char digest[64];
  const unsigned char *expected;
  gcry_error_t err;
  int fips_mode;

  if (gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("unexpected initialization before thread probe", 0);

  if (gcry_threads_pth.option
      != (GCRY_THREAD_OPTION_PTH | (GCRY_THREAD_OPTION_VERSION << 8)))
    return die("GCRY_THREAD_OPTION_PTH_IMPL mismatch", gcry_threads_pth.option);
  if (gcry_threads_pthread.option
      != (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)))
    return die("GCRY_THREAD_OPTION_PTHREAD_IMPL mismatch",
               gcry_threads_pthread.option);

  if (gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM))
    return die("SET_PREFERRED_RNG_TYPE failed", 0);

  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng_type))
    return die("GET_CURRENT_RNG_TYPE before SET_THREAD_CBS failed", 0);
  if (rng_type != GCRY_RNG_TYPE_SYSTEM)
    return die("preferred RNG type did not stick", rng_type);

  if (gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread))
    return die("SET_THREAD_CBS failed", 0);
  if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("SET_THREAD_CBS did not initialize libgcrypt", 0);

  rng_type = -1;
  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng_type))
    return die("GET_CURRENT_RNG_TYPE after SET_THREAD_CBS failed", 0);
  if (rng_type != GCRY_RNG_TYPE_STANDARD)
    return die("SET_THREAD_CBS did not restore standard RNG type", rng_type);

  if (!gcry_check_version(GCRYPT_VERSION))
    return die("gcry_check_version rejected header version", 0);

  if (gcry_control(GCRYCTL_SET_VERBOSITY, 0))
    return die("SET_VERBOSITY failed", 0);

  gcry_fast_random_poll();
  fips_mode = gcry_fips_mode_active();
  if (fips_mode != 0 && fips_mode != 1)
    return die("gcry_fips_mode_active returned non-boolean", fips_mode);

  gcry_set_log_handler(capture_log, &log_capture);
  gcry_log_debug("compat smoke %d", 42);
  if (log_capture.level != GCRY_LOG_DEBUG)
    return die("gcry_log_debug delivered wrong level", log_capture.level);
  if (!strstr(log_capture.message, "compat smoke 42"))
    return die("gcry_log_debug message mismatch", 0);

  err = gcry_md_open(&md, GCRY_MD_SHA256, 0);
  if (err)
    return die("gcry_md_open failed", err);

  gcry_md_putc(md, 'a');
  gcry_md_write(md, "bc", 2);
  gcry_md_final(md);

  digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
  if (digest_len == 0 || digest_len > sizeof(digest))
    return die("unexpected SHA256 digest length", digest_len);

  expected = gcry_md_read(md, GCRY_MD_SHA256);
  if (!expected)
    return die("gcry_md_read returned NULL", 0);
  memcpy(digest, expected, digest_len);
  if (!memcmp(digest, expected, digest_len))
    ;
  else
    return die("gcry_md_putc digest mismatch", 0);

  err = gcry_sexp_build(&first, &erroff, "(alpha %u)", 1U);
  if (err)
    return die("gcry_sexp_build(first) failed", err);
  err = gcry_sexp_build(&second, &erroff, "(beta %u)", 2U);
  if (err)
    return die("gcry_sexp_build(second) failed", err);

  combined = gcry_sexp_vlist(first, second, NULL);
  if (!combined)
    return die("gcry_sexp_vlist returned NULL", 0);

  err = gcry_sexp_sscan(&key, &erroff,
                        "(public-key(rsa(n #010001#)(e #03#)))",
                        strlen("(public-key(rsa(n #010001#)(e #03#)))"));
  if (err)
    return die("gcry_sexp_sscan failed", err);

  err = gcry_sexp_extract_param(key, NULL, "ne", &mpi_n, &mpi_e, NULL);
  if (err)
    return die("gcry_sexp_extract_param failed", err);
  if (!mpi_n || !mpi_e)
    return die("gcry_sexp_extract_param returned NULL values", 0);

  gcry_mpi_release(mpi_n);
  gcry_mpi_release(mpi_e);
  gcry_sexp_release(key);
  gcry_sexp_release(combined);
  gcry_sexp_release(second);
  gcry_sexp_release(first);
  gcry_md_close(md);

  return 0;
}

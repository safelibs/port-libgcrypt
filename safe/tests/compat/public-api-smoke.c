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

static int
prime_check_callback(void *opaque, int mode, gcry_mpi_t candidate)
{
  int *result = opaque;

  (void)candidate;
  if (mode != GCRY_PRIME_CHECK_AT_FINISH)
    return 1;
  return *result;
}

static int
check_phase3_regressions(void)
{
  static const unsigned char blob_bytes[] = {'a', 0, 'b'};
  static const unsigned char array_blob[] = {'x', 0, 'y'};
  static const unsigned char opaque_bytes[] = {0x00, 0xff, 0x42};
  const char *array_string = "array";
  const char *array_blob_ptr = (const char *)array_blob;
  const char *hinted_text = "([4:mime]3:raw)";
  const char *top_hinted_text = "[4:mime]3:raw";
  const char *escaped_text = "(\"a\\101b\" \"c\\\nd\")";
  const char *prefixed_text = "(3\"abc\"2#4142#4|QUJD|)";
  const char *literal_arg = "arg";
  const char *array_literal_arg = "array-arg";
  const char *protected_hex_sub = "4142";
  const char *protected_base64_sub = "QUJD";
  unsigned char hexbuf[6];
  unsigned char stdbuf[1];
  unsigned char *secure_import = NULL;
  unsigned char *secure_print = NULL;
  unsigned char *secure_bytes = NULL;
  unsigned char *plain_bytes = NULL;
  unsigned int array_uint = 7;
  const char *data;
  char *hex = NULL;
  char *empty_string = NULL;
  void *empty_buffer = NULL;
  void *opaque_ptr;
  void *array_args[4];
  void *protected_args[2];
  int array_blob_len = sizeof array_blob;
  gcry_sexp_t hinted = NULL;
  gcry_sexp_t top_hinted = NULL;
  gcry_sexp_t escaped = NULL;
  gcry_sexp_t prefixed = NULL;
  gcry_sexp_t array_built = NULL;
  gcry_sexp_t built = NULL;
  gcry_sexp_t bad_build = NULL;
  gcry_sexp_t node = NULL;
  gcry_mpi_t opaque = NULL;
  gcry_mpi_t neg = NULL;
  gcry_mpi_t bad_mpi = NULL;
  gcry_mpi_t group_prime = NULL;
  gcry_mpi_t group_factor_two = NULL;
  gcry_mpi_t group_factor_three = NULL;
  gcry_mpi_t group_generator = NULL;
  gcry_mpi_t callback_prime = NULL;
  gcry_mpi_t secure_scan = NULL;
  gcry_mpi_t secure_mpi = NULL;
  gcry_mpi_t secure_opaque = NULL;
  gcry_mpi_t group_factors[3] = {NULL, NULL, NULL};
  gcry_mpi_t short_group_factors[2] = {NULL, NULL};
  int callback_result = 0;
  unsigned int nbits = 0;
  size_t datalen = 0;
  size_t erroff = 99;
  size_t hex_len = 0;
  size_t nscanned = 0;
  size_t nwritten = 0;
  size_t secure_print_len = 0;
  gcry_error_t errcode = 0;
  gcry_error_t err;
  size_t canon_len;

  canon_len = gcry_sexp_canon_len ((const unsigned char *)"(9:abcdefghi) ",
                                   14, &erroff, &errcode);
  if (canon_len != 13 || erroff != 0 || gcry_err_code (errcode))
    return die ("canonical S-expression length regression", canon_len);

  canon_len = gcry_sexp_canon_len ((const unsigned char *)"(010:abcdefghi)",
                                   15, &erroff, &errcode);
  if (canon_len != 0 || erroff != 1
      || gcry_err_code (errcode) != GPG_ERR_SEXP_ZERO_PREFIX)
    return die ("canonical S-expression error regression",
                gcry_err_code (errcode));

  err = gcry_sexp_sscan (&hinted, &erroff, hinted_text, strlen (hinted_text));
  if (err)
    return die ("display-hinted S-expression scan failed", err);
  data = gcry_sexp_nth_data (hinted, 0, &datalen);
  if (!data || datalen != 4 || memcmp (data, "mime", 4))
    return die ("display hint did not preserve hinted atom data", datalen);
  data = gcry_sexp_nth_data (hinted, 1, &datalen);
  if (!data || datalen != 3 || memcmp (data, "raw", 3))
    return die ("display hint changed following atom data", datalen);

  err = gcry_sexp_sscan (&top_hinted, &erroff, top_hinted_text,
                         strlen (top_hinted_text));
  if (err)
    return die ("top-level display-hinted S-expression scan failed", err);
  data = gcry_sexp_nth_data (top_hinted, 0, &datalen);
  if (!data || datalen != 4 || memcmp (data, "mime", 4))
    return die ("top-level display hint lost hinted atom data", datalen);
  data = gcry_sexp_nth_data (top_hinted, 1, &datalen);
  if (!data || datalen != 3 || memcmp (data, "raw", 3))
    return die ("top-level display hint changed following atom data", datalen);

  err = gcry_sexp_sscan (&escaped, &erroff, escaped_text,
                         strlen (escaped_text));
  if (err)
    return die ("quoted atom escape scan failed", err);
  data = gcry_sexp_nth_data (escaped, 0, &datalen);
  if (!data || datalen != 3 || memcmp (data, "aAb", 3))
    return die ("quoted octal escape mismatch", datalen);
  data = gcry_sexp_nth_data (escaped, 1, &datalen);
  if (!data || datalen != 2 || memcmp (data, "cd", 2))
    return die ("quoted line continuation mismatch", datalen);

  err = gcry_sexp_sscan (&prefixed, &erroff, prefixed_text,
                         strlen (prefixed_text));
  if (err)
    return die ("length-prefixed advanced atom scan failed", err);
  data = gcry_sexp_nth_data (prefixed, 0, &datalen);
  if (!data || datalen != 3 || memcmp (data, "abc", 3))
    return die ("length-prefixed quoted atom mismatch", datalen);
  data = gcry_sexp_nth_data (prefixed, 1, &datalen);
  if (!data || datalen != 2 || memcmp (data, "AB", 2))
    return die ("length-prefixed hex atom mismatch", datalen);
  data = gcry_sexp_nth_data (prefixed, 2, &datalen);
  if (!data || datalen != 3 || memcmp (data, "ABC", 3))
    return die ("length-prefixed base64 atom mismatch", datalen);

  erroff = 99;
  err = gcry_sexp_sscan (&bad_build, &erroff, "(bad {)", strlen ("(bad {)"));
  if (gcry_err_code (err) != GPG_ERR_SEXP_UNEXPECTED_PUNC || erroff != 5
      || bad_build)
    return die ("reserved brace punctuation accepted as token", erroff);
  erroff = 99;
  err = gcry_sexp_sscan (&bad_build, &erroff, "(bad \\)",
                         strlen ("(bad \\)"));
  if (gcry_err_code (err) != GPG_ERR_SEXP_UNEXPECTED_PUNC || erroff != 5
      || bad_build)
    return die ("reserved backslash punctuation accepted as token", erroff);

  erroff = 99;
  err = gcry_sexp_build (&bad_build, &erroff, "(bad %q)", "ignored");
  if (gcry_err_code (err) != GPG_ERR_SEXP_INV_LEN_SPEC || erroff != 6
      || bad_build)
    return die ("S-expression build error offset mismatch", erroff);

  err = gcry_sexp_build (&bad_build, &erroff, "(bad-hex #%s# %s)",
                         protected_hex_sub, literal_arg);
  if (!err || bad_build)
    return die ("hex atom percent marker was consumed as vararg", err);
  err = gcry_sexp_build (&bad_build, &erroff, "(bad-base64 |%s| %s)",
                         protected_base64_sub, literal_arg);
  if (!err || bad_build)
    return die ("base64 atom percent marker was consumed as vararg", err);
  protected_args[0] = &protected_hex_sub;
  protected_args[1] = &array_literal_arg;
  err = gcry_sexp_build_array (&bad_build, &erroff,
                               "(bad-array-hex #%s# %s)", protected_args);
  if (!err || bad_build)
    return die ("array hex atom percent marker was consumed", err);
  protected_args[0] = &protected_base64_sub;
  protected_args[1] = &array_literal_arg;
  err = gcry_sexp_build_array (&bad_build, &erroff,
                               "(bad-array-base64 |%s| %s)",
                               protected_args);
  if (!err || bad_build)
    return die ("array base64 atom percent marker was consumed", err);

  array_args[0] = &array_string;
  array_args[1] = &array_blob_len;
  array_args[2] = &array_blob_ptr;
  array_args[3] = &array_uint;
  err = gcry_sexp_build_array (&array_built, &erroff, "(arr %s %b %u)",
                               array_args);
  if (err)
    return die ("gcry_sexp_build_array failed", err);
  node = gcry_sexp_find_token (array_built, "arr", 0);
  if (!node)
    return die ("array-built token lookup failed", 0);
  data = gcry_sexp_nth_data (node, 1, &datalen);
  if (!data || datalen != strlen (array_string)
      || memcmp (data, array_string, strlen (array_string)))
    return die ("array-built string mismatch", datalen);
  data = gcry_sexp_nth_data (node, 2, &datalen);
  if (!data || datalen != sizeof array_blob
      || memcmp (data, array_blob, sizeof array_blob))
    return die ("array-built binary mismatch", datalen);
  data = gcry_sexp_nth_data (node, 3, &datalen);
  if (!data || datalen != 1 || memcmp (data, "7", 1))
    return die ("array-built unsigned mismatch", datalen);
  gcry_sexp_release (node);
  node = NULL;
  gcry_sexp_release (array_built);
  array_built = NULL;

  err = gcry_sexp_build (&built, &erroff,
                         "(literal \"%s\" #2573# |JXM=| %s)",
                         literal_arg);
  if (err)
    return die ("literal percent build failed", err);
  node = gcry_sexp_find_token (built, "literal", 0);
  if (!node)
    return die ("literal percent token lookup failed", 0);
  data = gcry_sexp_nth_data (node, 1, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("quoted literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 2, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("hex literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 3, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("base64 literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 4, &datalen);
  if (!data || datalen != strlen (literal_arg)
      || memcmp (data, literal_arg, strlen (literal_arg)))
    return die ("real percent substitution mismatch", datalen);
  gcry_sexp_release (node);
  node = NULL;
  gcry_sexp_release (built);
  built = NULL;

  array_args[0] = &array_literal_arg;
  err = gcry_sexp_build_array (&array_built, &erroff,
                               "(literal-array \"%s\" #2573# |JXM=| %s)",
                               array_args);
  if (err)
    return die ("literal percent build_array failed", err);
  node = gcry_sexp_find_token (array_built, "literal-array", 0);
  if (!node)
    return die ("literal percent array token lookup failed", 0);
  data = gcry_sexp_nth_data (node, 1, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("array quoted literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 2, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("array hex literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 3, &datalen);
  if (!data || datalen != 2 || memcmp (data, "%s", 2))
    return die ("array base64 literal percent was substituted", datalen);
  data = gcry_sexp_nth_data (node, 4, &datalen);
  if (!data || datalen != strlen (array_literal_arg)
      || memcmp (data, array_literal_arg, strlen (array_literal_arg)))
    return die ("array real percent substitution mismatch", datalen);
  gcry_sexp_release (node);
  node = NULL;

  err = gcry_sexp_build (&built, &erroff, "(blob %b)", 3, blob_bytes);
  if (err)
    return die ("binary atom varargs build failed", err);
  node = gcry_sexp_find_token (built, "blob", 0);
  if (!node)
    return die ("binary atom token lookup failed", 0);
  data = gcry_sexp_nth_data (node, 1, &datalen);
  if (!data || datalen != sizeof blob_bytes
      || memcmp (data, blob_bytes, sizeof blob_bytes))
    return die ("binary atom varargs data mismatch", datalen);
  gcry_sexp_release (node);
  node = NULL;
  gcry_sexp_release (built);
  built = NULL;

  err = gcry_sexp_build (&built, &erroff, "(empty %b)", 0, "");
  if (err)
    return die ("zero-length atom varargs build failed", err);
  node = gcry_sexp_find_token (built, "empty", 0);
  if (!node)
    return die ("zero-length atom token lookup failed", 0);
  (void)gcry_sexp_nth_data (node, 1, &datalen);
  if (datalen != 0)
    return die ("zero-length atom data mismatch", datalen);
  empty_string = gcry_sexp_nth_string (node, 1);
  if (empty_string)
    {
      gcry_free (empty_string);
      return die ("zero-length atom returned nth_string", 0);
    }
  datalen = 77;
  empty_buffer = gcry_sexp_nth_buffer (node, 1, &datalen);
  if (empty_buffer || datalen != 0)
    {
      gcry_free (empty_buffer);
      return die ("zero-length atom returned nth_buffer", datalen);
    }

  opaque = gcry_mpi_set_opaque_copy (NULL, opaque_bytes, 20);
  if (!opaque || !gcry_mpi_get_flag (opaque, GCRYMPI_FLAG_OPAQUE))
    return die ("opaque MPI allocation failed", 0);
  opaque_ptr = gcry_mpi_get_opaque (opaque, &nbits);
  if (!opaque_ptr || nbits != 20 || memcmp (opaque_ptr, opaque_bytes, 3))
    return die ("opaque MPI payload mismatch", nbits);

  group_prime = gcry_mpi_set_ui (NULL, 7);
  group_factor_two = gcry_mpi_set_ui (NULL, 2);
  group_factor_three = gcry_mpi_set_ui (NULL, 3);
  group_factors[0] = group_factor_two;
  group_factors[1] = group_factor_three;
  short_group_factors[0] = group_factor_two;
  err = gcry_prime_group_generator (NULL, group_prime, group_factors, NULL);
  if (gcry_err_code (err) != GPG_ERR_INV_ARG)
    return die ("prime group generator accepted NULL output", err);
  err = gcry_prime_group_generator (&group_generator, group_prime, NULL, NULL);
  if (gcry_err_code (err) != GPG_ERR_INV_ARG || group_generator)
    return die ("prime group generator accepted NULL factors", err);
  err = gcry_prime_group_generator (&group_generator, group_prime,
                                    short_group_factors, NULL);
  if (gcry_err_code (err) != GPG_ERR_INV_ARG || group_generator)
    return die ("prime group generator accepted short factors", err);
  err = gcry_prime_group_generator (&group_generator, group_prime,
                                    group_factors, NULL);
  if (err || !group_generator || gcry_mpi_cmp_ui (group_generator, 3))
    return die ("prime group generator default mismatch", err);
  gcry_mpi_release (group_generator);
  group_generator = NULL;

  callback_result = 0;
  err = gcry_prime_generate (&callback_prime, 48, 0, NULL,
                             prime_check_callback, &callback_result,
                             GCRY_WEAK_RANDOM, 0);
  if (gcry_err_code (err) != GPG_ERR_GENERAL || callback_prime)
    return die ("prime callback rejection accepted candidate", err);
  callback_result = 1;
  err = gcry_prime_generate (&callback_prime, 48, 0, NULL,
                             prime_check_callback, &callback_result,
                             GCRY_WEAK_RANDOM, 0);
  if (err || !callback_prime)
    return die ("prime callback acceptance rejected candidate", err);
  gcry_mpi_release (callback_prime);
  callback_prime = NULL;

  err = gcry_mpi_scan (&neg, GCRYMPI_FMT_HEX, "-0080", 0, NULL);
  if (err)
    return die ("negative MPI scan failed", err);
  nscanned = 77;
  err = gcry_mpi_scan (NULL, GCRYMPI_FMT_HEX, "2A", 0, &nscanned);
  if (err || nscanned != 2)
    return die ("MPI scan with null output slot failed", err);
  nscanned = 77;
  err = gcry_mpi_scan (&bad_mpi, GCRYMPI_FMT_HEX, "2A", 2, &nscanned);
  if (gcry_err_code (err) != GPG_ERR_INV_ARG || bad_mpi || nscanned != 0)
    return die ("HEX MPI scan accepted nonzero length", err);
  err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, (unsigned char **)&hex, &hex_len,
                         neg);
  if (err)
    return die ("negative MPI hex print failed", err);
  if (hex_len != 6 || strcmp (hex, "-0080"))
    return die ("negative MPI hex formatting mismatch", 0);
  gcry_free (hex);
  hex = NULL;
  err = gcry_mpi_print (GCRYMPI_FMT_HEX, NULL, 0, &hex_len, neg);
  if (err || hex_len != 6)
    return die ("negative MPI HEX length query mismatch", err);
  err = gcry_mpi_print (GCRYMPI_FMT_HEX, hexbuf, sizeof hexbuf, &hex_len,
                        neg);
  if (err || hex_len != 6 || memcmp (hexbuf, "-0080", 6))
    return die ("negative MPI HEX print length mismatch", err);
  hex_len = 77;
  err = gcry_mpi_print (GCRYMPI_FMT_HEX, hexbuf, sizeof hexbuf - 1,
                        &hex_len, neg);
  if (gcry_err_code (err) != GPG_ERR_TOO_SHORT || hex_len != 0)
    return die ("MPI HEX short-buffer print mismatch", err);
  err = gcry_mpi_print (GCRYMPI_FMT_STD, stdbuf, sizeof stdbuf,
                        &nwritten, neg);
  if (err || nwritten != 1 || stdbuf[0] != 0x80)
    return die ("negative MPI STD formatting mismatch", err);

  secure_import = gcry_xmalloc_secure (1);
  secure_import[0] = 0x2a;
  err = gcry_mpi_scan (&secure_scan, GCRYMPI_FMT_USG, secure_import, 1, NULL);
  gcry_free (secure_import);
  secure_import = NULL;
  if (err || !secure_scan
      || !gcry_mpi_get_flag (secure_scan, GCRYMPI_FLAG_SECURE))
    return die ("secure MPI scan did not preserve secure input", err);
  err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &secure_print, &secure_print_len,
                         secure_scan);
  if (err || !secure_print || secure_print_len != 1 || secure_print[0] != 0x2a)
    return die ("secure MPI aprint payload mismatch", err);
  if (!gcry_is_secure (secure_print))
    return die ("secure MPI aprint used plain memory", 0);
  gcry_free (secure_print);
  secure_print = NULL;

  secure_bytes = gcry_xmalloc_secure (sizeof opaque_bytes);
  memcpy (secure_bytes, opaque_bytes, sizeof opaque_bytes);
  secure_opaque = gcry_mpi_set_opaque_copy (NULL, secure_bytes,
                                            sizeof opaque_bytes * 8);
  gcry_free (secure_bytes);
  secure_bytes = NULL;
  if (!secure_opaque
      || !gcry_mpi_get_flag (secure_opaque, GCRYMPI_FLAG_SECURE))
    return die ("secure opaque MPI copy lost secure flag", 0);
  opaque_ptr = gcry_mpi_get_opaque (secure_opaque, &nbits);
  if (!opaque_ptr || !gcry_is_secure (opaque_ptr))
    return die ("secure opaque MPI copy used plain memory", 0);

  secure_mpi = gcry_mpi_snew (0);
  if (!secure_mpi || !gcry_mpi_get_flag (secure_mpi, GCRYMPI_FLAG_SECURE))
    return die ("secure MPI allocation failed", 0);
  plain_bytes = gcry_malloc (2);
  if (!plain_bytes)
    return die ("plain opaque payload allocation failed", 0);
  plain_bytes[0] = 0x12;
  plain_bytes[1] = 0x34;
  secure_mpi = gcry_mpi_set_opaque (secure_mpi, plain_bytes, 16);
  plain_bytes = NULL;
  if (!secure_mpi || gcry_mpi_get_flag (secure_mpi, GCRYMPI_FLAG_SECURE))
    return die ("plain opaque MPI retained stale secure flag", 0);

  gcry_mpi_release (secure_mpi);
  gcry_mpi_release (secure_opaque);
  gcry_mpi_release (secure_scan);
  gcry_mpi_release (callback_prime);
  gcry_mpi_release (group_generator);
  gcry_mpi_release (group_factor_three);
  gcry_mpi_release (group_factor_two);
  gcry_mpi_release (group_prime);
  gcry_mpi_release (neg);
  gcry_mpi_release (opaque);
  gcry_sexp_release (node);
  gcry_sexp_release (built);
  gcry_sexp_release (array_built);
  gcry_sexp_release (prefixed);
  gcry_sexp_release (escaped);
  gcry_sexp_release (top_hinted);
  gcry_sexp_release (hinted);
  return 0;
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

  if (check_phase3_regressions ())
    return 1;

  gcry_mpi_release(mpi_n);
  gcry_mpi_release(mpi_e);
  gcry_sexp_release(key);
  gcry_sexp_release(combined);
  gcry_sexp_release(second);
  gcry_sexp_release(first);
  gcry_md_close(md);

  return 0;
}

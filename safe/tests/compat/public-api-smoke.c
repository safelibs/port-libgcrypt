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
  gcry_md_hd_t keyed_md = NULL;
  gcry_mac_hd_t mac = NULL;
  gcry_sexp_t first = NULL;
  gcry_sexp_t second = NULL;
  gcry_sexp_t combined = NULL;
  gcry_sexp_t key = NULL;
  gcry_kdf_hd_t kdf = NULL;
  gcry_mpi_t mpi_n = NULL;
  gcry_mpi_t mpi_e = NULL;
  gcry_buffer_t hash_iov[1];
  int rng_type = -1;
  unsigned int digest_len;
  size_t erroff = 0;
  size_t info_len = 0;
  size_t mac_len = 0;
  unsigned char digest[64];
  unsigned char mac_digest[32];
  unsigned char argon2_digest[16];
  unsigned char balloon_digest[32];
  unsigned char kdf_digest[20];
  unsigned char pbkdf2_digest[32];
  const unsigned char *expected;
  static const unsigned char expected_hmac_sha256[] = {
    0x9c, 0x19, 0x6e, 0x32, 0xdc, 0x01, 0x75, 0xf8,
    0x6f, 0x4b, 0x1c, 0xb8, 0x92, 0x89, 0xd6, 0x61,
    0x9d, 0xe6, 0xbe, 0xe6, 0x99, 0xe4, 0xc3, 0x78,
    0xe6, 0x83, 0x09, 0xed, 0x97, 0xa1, 0xa6, 0xab
  };
  static const unsigned char cmac_aes_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  };
  static const unsigned char cmac_aes_data[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  static const unsigned char expected_cmac_aes[] = {
    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
  };
  static const unsigned char poly1305_key[] = {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
  };
  static const unsigned char expected_poly1305[] = {
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
    0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
  };
  static const unsigned char gost28147_imit_data[] = {
    0xb5, 0xa1, 0xf0, 0xe3, 0xce, 0x2f, 0x02, 0x1d,
    0x67, 0x61, 0x94, 0x34, 0x5c, 0x41, 0xe3, 0x6e
  };
  static const unsigned char gost28147_imit_key[] = {
    0x9d, 0x05, 0xb7, 0x9e, 0x90, 0xca, 0xd0, 0x0a,
    0x2c, 0xda, 0xd2, 0x2e, 0xf4, 0xe8, 0x6f, 0x5c,
    0xf5, 0xdc, 0x37, 0x68, 0x19, 0x85, 0xb3, 0xbf,
    0xaa, 0x18, 0xc1, 0xc3, 0x05, 0x0a, 0x91, 0xa2
  };
  static const unsigned char expected_gost28147_imit[] = {
    0xf8, 0x1f, 0x08, 0xa3
  };
  static const int cmac_probe_algos[] = {
    GCRY_MAC_CMAC_3DES,
    GCRY_MAC_CMAC_CAMELLIA,
    GCRY_MAC_CMAC_CAST5,
    GCRY_MAC_CMAC_BLOWFISH,
    GCRY_MAC_CMAC_TWOFISH,
    GCRY_MAC_CMAC_SERPENT,
    GCRY_MAC_CMAC_SEED,
    GCRY_MAC_CMAC_RFC2268,
    GCRY_MAC_CMAC_IDEA,
    GCRY_MAC_CMAC_GOST28147,
    GCRY_MAC_CMAC_SM4
  };
  static const int poly1305_cipher_probe_algos[] = {
    GCRY_MAC_POLY1305_AES,
    GCRY_MAC_POLY1305_CAMELLIA,
    GCRY_MAC_POLY1305_TWOFISH,
    GCRY_MAC_POLY1305_SERPENT,
    GCRY_MAC_POLY1305_SEED
  };
  static const int gmac_probe_algos[] = {
    GCRY_MAC_GMAC_AES,
    GCRY_MAC_GMAC_CAMELLIA,
    GCRY_MAC_GMAC_TWOFISH,
    GCRY_MAC_GMAC_SERPENT,
    GCRY_MAC_GMAC_SEED
  };
  static const unsigned char mac_probe_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };
  static const unsigned char mac_probe_iv[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
  };
  static const size_t expected_cmac_probe_lens[] = {
    8, 16, 8, 8, 16, 16, 16, 8, 8, 8, 16
  };
  static const unsigned char expected_cmac_probe_tags[][16] = {
    {0x1f, 0x94, 0x8f, 0x0a, 0xb5, 0x5a, 0xa5, 0x36},
    {0x31, 0xc3, 0x0f, 0xca, 0xab, 0x07, 0x49, 0xe1,
     0x07, 0xb6, 0xc5, 0x44, 0x62, 0x23, 0xf3, 0x2e},
    {0x19, 0xe1, 0xe1, 0x5b, 0xbc, 0x79, 0xa9, 0x1c},
    {0x9f, 0x9b, 0xe2, 0x71, 0x4a, 0x33, 0x19, 0x00},
    {0x1b, 0x6d, 0x09, 0xc9, 0x6b, 0x83, 0xbd, 0x7f,
     0x02, 0x6f, 0x00, 0xab, 0xff, 0x4e, 0xd0, 0x00},
    {0x40, 0x8a, 0x92, 0xfd, 0x26, 0x0a, 0x7a, 0x85,
     0x25, 0xc9, 0xf3, 0xc7, 0x07, 0x4c, 0x3a, 0x85},
    {0x8e, 0x5a, 0xa3, 0x4e, 0xbe, 0x87, 0xe9, 0x76,
     0x90, 0x3e, 0xef, 0x02, 0x22, 0x84, 0xcc, 0x2b},
    {0x56, 0x7c, 0x25, 0x73, 0x6a, 0xd3, 0xa2, 0x7f},
    {0x56, 0x38, 0x7a, 0xc7, 0x30, 0x21, 0x5c, 0x7d},
    {0x5c, 0x56, 0x4f, 0x15, 0x25, 0x16, 0x59, 0xba},
    {0x12, 0x19, 0x1f, 0x51, 0xdc, 0x5c, 0x89, 0xaf,
     0x84, 0x44, 0x6d, 0xf2, 0x43, 0x55, 0xd3, 0xf7}
  };
  static const unsigned char expected_poly1305_cipher_probe_tags[][16] = {
    {0x1f, 0xbb, 0x29, 0xec, 0x2a, 0x2c, 0xac, 0xf2,
     0xbb, 0xa9, 0x99, 0xae, 0x88, 0x7f, 0x31, 0x78},
    {0xec, 0x56, 0x90, 0x1b, 0x52, 0x51, 0x6a, 0x69,
     0xc3, 0xbf, 0xe3, 0xcc, 0x26, 0xb2, 0x78, 0x86},
    {0xe6, 0x81, 0x30, 0x75, 0x95, 0xda, 0x69, 0x9e,
     0xca, 0x40, 0x44, 0x16, 0x1d, 0x3a, 0x35, 0xda},
    {0xa1, 0x63, 0x5a, 0x18, 0x71, 0x52, 0xb2, 0x53,
     0x61, 0x39, 0x34, 0x39, 0x40, 0xdb, 0x63, 0xdc},
    {0x6a, 0x6f, 0x4e, 0x57, 0x22, 0xa0, 0x6e, 0x50,
     0xf3, 0xec, 0x48, 0xeb, 0xd1, 0x42, 0xe5, 0x37}
  };
  static const unsigned char expected_gmac_probe_tags[][16] = {
    {0x25, 0x16, 0x53, 0x38, 0xa4, 0x0c, 0xac, 0x65,
     0x34, 0x96, 0xc5, 0x9f, 0xf6, 0x4b, 0x15, 0x2b},
    {0x1f, 0x41, 0xee, 0x22, 0x9f, 0x2e, 0xd2, 0x9e,
     0x19, 0xd8, 0x38, 0xfb, 0xd4, 0x9e, 0x73, 0x9f},
    {0x7a, 0x1c, 0x48, 0x3d, 0x26, 0x6d, 0x29, 0x9a,
     0x78, 0xa2, 0x31, 0xa6, 0x7d, 0x10, 0x5b, 0x03},
    {0x2f, 0x8b, 0x97, 0xba, 0xef, 0xf3, 0x43, 0x9e,
     0x77, 0x18, 0xdd, 0xe2, 0x91, 0x1b, 0x35, 0xca},
    {0x1c, 0x32, 0xe3, 0xce, 0xb4, 0x42, 0x23, 0xb9,
     0xb5, 0x9a, 0xe5, 0x3d, 0x01, 0x7f, 0x57, 0xac}
  };
  unsigned long argon2_params3[] = {16, 2, 8};
  unsigned long balloon_params[] = {4, 2};
  static const unsigned char expected_pbkdf2_sha1[] = {
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
    0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
    0x2f, 0xe0, 0x37, 0xa6
  };
  static const int pbkdf2_hmac_probe_algos[] = {
    GCRY_MD_SHA3_224,
    GCRY_MD_SHA3_256,
    GCRY_MD_SHA3_384,
    GCRY_MD_SHA3_512,
    GCRY_MD_SM3,
    GCRY_MD_STRIBOG256,
    GCRY_MD_STRIBOG512
  };
  static const unsigned char expected_pbkdf2_hmac_probe[][32] = {
    {0xd3, 0x6c, 0xad, 0x0f, 0xee, 0xa8, 0xcf, 0x94,
     0x28, 0x60, 0x13, 0x04, 0x63, 0x09, 0x3a, 0x62,
     0x3b, 0xea, 0xd2, 0x1f, 0x82, 0x36, 0x6f, 0x18,
     0x4f, 0x31, 0x8b, 0x4f, 0xd6, 0xb3, 0xc6, 0x54},
    {0x94, 0x61, 0x3f, 0x3e, 0xe2, 0xea, 0x73, 0x0e,
     0x0b, 0x06, 0x75, 0x4f, 0x3f, 0xc8, 0x16, 0xd4,
     0xf8, 0x7c, 0x9b, 0xe9, 0xcb, 0xd8, 0x55, 0x6b,
     0x5d, 0x59, 0xb5, 0x23, 0x30, 0xe3, 0x33, 0xa8},
    {0x7d, 0x7a, 0xba, 0x34, 0x1e, 0x6a, 0xc8, 0x4e,
     0x99, 0x38, 0xf0, 0xf5, 0xa2, 0xf6, 0x3c, 0x07,
     0xda, 0xa3, 0xe0, 0x58, 0x4c, 0xc6, 0xdb, 0x99,
     0x65, 0x0a, 0x75, 0xeb, 0x29, 0x48, 0xf2, 0xb9},
    {0xf7, 0xa2, 0x68, 0x46, 0x30, 0xec, 0x0f, 0x81,
     0xf2, 0x3a, 0xbb, 0xf6, 0x06, 0x27, 0x8d, 0xee,
     0xaa, 0xd1, 0xa3, 0x50, 0x53, 0xdb, 0x3c, 0x06,
     0x69, 0x03, 0xd9, 0x11, 0x4e, 0xd3, 0xfd, 0x6e},
    {0x46, 0x12, 0xf9, 0x22, 0xa1, 0xfd, 0xce, 0xfa,
     0xf4, 0x31, 0x2f, 0xc6, 0xf8, 0xf3, 0x32, 0x2b,
     0x48, 0x9c, 0xbf, 0x24, 0xf2, 0xea, 0x36, 0x1b,
     0x44, 0xc2, 0xbd, 0x8f, 0xa2, 0xc6, 0xdc, 0xb0},
    {0xd7, 0x89, 0x45, 0x8d, 0x14, 0x3b, 0x9a, 0xbe,
     0xbc, 0x4e, 0xf6, 0x3c, 0xa8, 0xe5, 0x76, 0xc7,
     0x2b, 0x13, 0xc7, 0xd4, 0x28, 0x9d, 0xb2, 0x3f,
     0xc1, 0xe9, 0x46, 0xf8, 0x4c, 0xd6, 0x05, 0xbc},
    {0x64, 0x77, 0x0a, 0xf7, 0xf7, 0x48, 0xc3, 0xb1,
     0xc9, 0xac, 0x83, 0x1d, 0xbc, 0xfd, 0x85, 0xc2,
     0x61, 0x11, 0xb3, 0x0a, 0x8a, 0x65, 0x7d, 0xdc,
     0x30, 0x56, 0xb8, 0x0c, 0xa7, 0x3e, 0x04, 0x0d}
  };
  static const unsigned char expected_md4_abc[] = {
    0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
    0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d
  };
  static const unsigned char expected_crc32[] = {
    0xcb, 0xf4, 0x39, 0x26
  };
  static const unsigned char expected_crc32_rfc1510[] = {
    0x2d, 0xfd, 0x2d, 0x88
  };
  static const unsigned char expected_crc24_rfc2440[] = {
    0x21, 0xcf, 0x02
  };
  static const unsigned char expected_tiger_abc[] = {
    0xf2, 0x58, 0xc1, 0xe8, 0x84, 0x14, 0xab, 0x2a,
    0x52, 0x7a, 0xb5, 0x41, 0xff, 0xc5, 0xb8, 0xbf,
    0x93, 0x5f, 0x7b, 0x95, 0x1c, 0x13, 0x29, 0x51
  };
  static const unsigned char expected_tiger1_abc[] = {
    0x2a, 0xab, 0x14, 0x84, 0xe8, 0xc1, 0x58, 0xf2,
    0xbf, 0xb8, 0xc5, 0xff, 0x41, 0xb5, 0x7a, 0x52,
    0x51, 0x29, 0x13, 0x1c, 0x95, 0x7b, 0x5f, 0x93
  };
  static const unsigned char expected_whirlpool_bugemu[] = {
    0x35, 0x28, 0xd6, 0x4c, 0x56, 0x2c, 0x55, 0x2e,
    0x3b, 0x91, 0x93, 0x95, 0x7b, 0xdd, 0xcc, 0x6e,
    0x6f, 0xb7, 0xbf, 0x76, 0x22, 0x9c, 0xc6, 0x23,
    0xda, 0x3e, 0x09, 0x9b, 0x36, 0xe8, 0x6d, 0x76,
    0x2f, 0x94, 0x3b, 0x0c, 0x63, 0xa0, 0xba, 0xa3,
    0x4d, 0x66, 0x71, 0xe6, 0x5d, 0x26, 0x67, 0x28,
    0x36, 0x1f, 0x0e, 0x1a, 0x40, 0xf0, 0xce, 0x83,
    0x50, 0x90, 0x1f, 0xfa, 0x3f, 0xed, 0x6f, 0xfd
  };
  static const unsigned char expected_blake2b_256_keyed[] = {
    0x03, 0x30, 0x53, 0x1d, 0x09, 0x73, 0x55, 0xa3,
    0xf7, 0x2e, 0x80, 0xd5, 0x5c, 0x12, 0x45, 0xcc,
    0xf7, 0x9f, 0x17, 0x04, 0x43, 0x1c, 0x6e, 0x38,
    0x87, 0x93, 0x83, 0x20, 0x44, 0x2c, 0x23, 0xc0
  };
  static const unsigned char expected_blake2s_128_keyed[] = {
    0x94, 0xfd, 0xf6, 0xf3, 0x5b, 0x99, 0x99, 0x92,
    0x0d, 0xcd, 0xca, 0xee, 0x36, 0x1a, 0xd4, 0x35
  };
  gcry_error_t err;
  int fips_mode;
  int mac_algo;
  size_t expected_mac_len;
  size_t i;
  size_t key_len;

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

  if (gcry_md_map_name("RMD160") != GCRY_MD_RMD160
      || gcry_md_map_name("RIPEMD160") != GCRY_MD_RMD160)
    return die("legacy RIPEMD160 map_name mismatch", 0);
  if (gcry_md_map_name("MD4") != GCRY_MD_MD4)
    return die("legacy MD4 map_name mismatch", 0);
  if (gcry_md_map_name("TIGER192") != GCRY_MD_TIGER
      || gcry_md_map_name("TIGER") != GCRY_MD_TIGER1
      || gcry_md_map_name("TIGER2") != GCRY_MD_TIGER2)
    return die("legacy TIGER map_name mismatch", 0);
  if (gcry_md_map_name("CRC32") != GCRY_MD_CRC32
      || gcry_md_map_name("CRC32RFC1510") != GCRY_MD_CRC32_RFC1510
      || gcry_md_map_name("CRC24RFC2440") != GCRY_MD_CRC24_RFC2440)
    return die("legacy CRC map_name mismatch", 0);
  if (gcry_md_map_name("WHIRLPOOL") != GCRY_MD_WHIRLPOOL)
    return die("legacy WHIRLPOOL map_name mismatch", 0);
  if (gcry_md_get_algo_dlen(GCRY_MD_RMD160) != 20
      || gcry_md_get_algo_dlen(GCRY_MD_MD4) != 16
      || gcry_md_get_algo_dlen(GCRY_MD_CRC32) != 4
      || gcry_md_get_algo_dlen(GCRY_MD_CRC32_RFC1510) != 4
      || gcry_md_get_algo_dlen(GCRY_MD_CRC24_RFC2440) != 3
      || gcry_md_get_algo_dlen(GCRY_MD_WHIRLPOOL) != 64
      || gcry_md_get_algo_dlen(GCRY_MD_TIGER) != 24
      || gcry_md_get_algo_dlen(GCRY_MD_TIGER1) != 24
      || gcry_md_get_algo_dlen(GCRY_MD_TIGER2) != 24)
    return die("legacy digest length mismatch", 0);
  if (strcmp(gcry_md_algo_name(GCRY_MD_SHA512_256), "SHA512_256")
      || strcmp(gcry_md_algo_name(GCRY_MD_SHA512_224), "SHA512_224"))
    return die("SHA512 truncated digest name mismatch", 0);

  err = gcry_md_open(&keyed_md, GCRY_MD_SHAKE128, GCRY_MD_FLAG_HMAC);
  if (gcry_err_code(err) != GPG_ERR_DIGEST_ALGO)
    return die("gcry_md_open accepted HMAC SHAKE128", gcry_err_code(err));
  if (keyed_md)
    {
      gcry_md_close(keyed_md);
      keyed_md = NULL;
    }
  err = gcry_md_open(&keyed_md, 0, GCRY_MD_FLAG_HMAC);
  if (err)
    return die("gcry_md_open empty HMAC failed", err);
  err = gcry_md_enable(keyed_md, GCRY_MD_SHAKE256);
  if (gcry_err_code(err) != GPG_ERR_DIGEST_ALGO)
    return die("gcry_md_enable accepted HMAC SHAKE256", gcry_err_code(err));
  gcry_md_close(keyed_md);
  keyed_md = NULL;

  memset(hash_iov, 0, sizeof hash_iov);
  hash_iov[0].size = 3;
  hash_iov[0].off = 0;
  hash_iov[0].len = 3;
  hash_iov[0].data = (void *)"abc";
  err = gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE,
                             digest, hash_iov, 1);
  if (gcry_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_md_hash_buffers accepted invalid flag",
               gcry_err_code(err));
  err = gcry_md_hash_buffers(GCRY_MD_SHA256, 0, digest, NULL, 0);
  if (gcry_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_md_hash_buffers accepted NULL iov",
               gcry_err_code(err));
  err = gcry_md_hash_buffers(GCRY_MD_SHAKE128, 0, digest, hash_iov, 1);
  if (gcry_err_code(err) != GPG_ERR_DIGEST_ALGO)
    return die("gcry_md_hash_buffers accepted SHAKE128",
               gcry_err_code(err));

  err = gcry_md_open(&keyed_md, GCRY_MD_WHIRLPOOL, GCRY_MD_FLAG_BUGEMU1);
  if (err)
    return die("gcry_md_open WHIRLPOOL bugemu failed", err);
  gcry_md_write(keyed_md, "1234567890", 10);
  gcry_md_write(keyed_md,
                "1234567890123456789012345678901234567890123456789012",
                52);
  expected = gcry_md_read(keyed_md, GCRY_MD_WHIRLPOOL);
  if (!expected
      || memcmp(expected, expected_whirlpool_bugemu,
                sizeof expected_whirlpool_bugemu))
    return die("WHIRLPOOL bugemu digest mismatch", 0);
  gcry_md_close(keyed_md);
  keyed_md = NULL;

  gcry_md_hash_buffer(GCRY_MD_MD4, digest, "abc", 3);
  if (memcmp(digest, expected_md4_abc, sizeof expected_md4_abc))
    return die("legacy MD4 digest mismatch", 0);
  gcry_md_hash_buffer(GCRY_MD_CRC32, digest, "123456789", 9);
  if (memcmp(digest, expected_crc32, sizeof expected_crc32))
    return die("legacy CRC32 digest mismatch", 0);
  gcry_md_hash_buffer(GCRY_MD_CRC32_RFC1510, digest, "123456789", 9);
  if (memcmp(digest, expected_crc32_rfc1510,
             sizeof expected_crc32_rfc1510))
    return die("legacy CRC32RFC1510 digest mismatch", 0);
  gcry_md_hash_buffer(GCRY_MD_CRC24_RFC2440, digest, "123456789", 9);
  if (memcmp(digest, expected_crc24_rfc2440, sizeof expected_crc24_rfc2440))
    return die("legacy CRC24RFC2440 digest mismatch", 0);
  gcry_md_hash_buffer(GCRY_MD_TIGER, digest, "abc", 3);
  if (memcmp(digest, expected_tiger_abc, sizeof expected_tiger_abc))
    return die("legacy TIGER192 digest mismatch", 0);
  gcry_md_hash_buffer(GCRY_MD_TIGER1, digest, "abc", 3);
  if (memcmp(digest, expected_tiger1_abc, sizeof expected_tiger1_abc))
    return die("legacy TIGER1 digest mismatch", 0);
  err = gcry_md_open(&keyed_md, GCRY_MD_BLAKE2B_256, 0);
  if (err)
    return die("gcry_md_open BLAKE2B keyed failed", err);
  err = gcry_md_setkey(keyed_md, "key", 3);
  if (err)
    return die("gcry_md_setkey BLAKE2B keyed failed", err);
  gcry_md_write(keyed_md, "abc", 3);
  expected = gcry_md_read(keyed_md, GCRY_MD_BLAKE2B_256);
  if (!expected
      || memcmp(expected, expected_blake2b_256_keyed,
                sizeof expected_blake2b_256_keyed))
    return die("gcry_md_read BLAKE2B keyed mismatch", 0);
  gcry_md_close(keyed_md);
  keyed_md = NULL;
  err = gcry_md_open(&keyed_md, GCRY_MD_BLAKE2S_128, 0);
  if (err)
    return die("gcry_md_open BLAKE2S keyed failed", err);
  err = gcry_md_setkey(keyed_md, "key", 3);
  if (err)
    return die("gcry_md_setkey BLAKE2S keyed failed", err);
  gcry_md_write(keyed_md, "abc", 3);
  expected = gcry_md_read(keyed_md, GCRY_MD_BLAKE2S_128);
  if (!expected
      || memcmp(expected, expected_blake2s_128_keyed,
                sizeof expected_blake2s_128_keyed))
    return die("gcry_md_read BLAKE2S keyed mismatch", 0);
  gcry_md_close(keyed_md);
  keyed_md = NULL;

  err = gcry_mac_open(&mac, GCRY_MAC_HMAC_SHA256, 0, NULL);
  if (err)
    return die("gcry_mac_open failed", err);
  err = gcry_mac_setkey(mac, "key", 3);
  if (err)
    return die("gcry_mac_setkey failed", err);
  err = gcry_mac_write(mac, "abc", 3);
  if (err)
    return die("gcry_mac_write failed", err);
  mac_len = sizeof mac_digest;
  err = gcry_mac_read(mac, mac_digest, &mac_len);
  if (err)
    return die("gcry_mac_read failed", err);
  if (mac_len != sizeof expected_hmac_sha256
      || memcmp(mac_digest, expected_hmac_sha256, sizeof expected_hmac_sha256))
    return die("gcry_mac_read digest mismatch", mac_len);
  err = gcry_mac_verify(mac, mac_digest, 0);
  if (gpg_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_mac_verify accepted zero-length tag", gpg_err_code(err));
  err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
  if (gpg_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_mac_setiv accepted HMAC IV", gpg_err_code(err));
  gcry_mac_close(mac);
  mac = NULL;

  if (gcry_mac_map_name("HMAC-SHA512-256") != GCRY_MAC_HMAC_SHA512_256)
    return die("gcry_mac_map_name HMAC-SHA512-256 mismatch", 0);
  if (gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512_224) != 28)
    return die("gcry_mac_get_algo_maclen HMAC-SHA512-224 mismatch",
               gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512_224));
  if (gcry_mac_map_name("HMAC-MD4") != GCRY_MAC_HMAC_MD4
      || gcry_mac_map_name("HMAC-RMD160") != GCRY_MAC_HMAC_RMD160
      || gcry_mac_map_name("HMAC-TIGER1") != GCRY_MAC_HMAC_TIGER1
      || gcry_mac_map_name("HMAC-WHIRLPOOL") != GCRY_MAC_HMAC_WHIRLPOOL)
    return die("legacy HMAC map_name mismatch", 0);
  if (gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_MD4) != 16
      || gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_RMD160) != 20
      || gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_TIGER1) != 24
      || gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_WHIRLPOOL) != 64)
    return die("legacy HMAC maclen mismatch", 0);
  info_len = 0;
  err = gcry_mac_algo_info(GCRY_MAC_HMAC_SHA256, GCRYCTL_GET_KEYLEN,
                           NULL, &info_len);
  if (err || info_len != 64)
    return die("gcry_mac_algo_info HMAC keylen mismatch", info_len);
  info_len = 0;
  err = gcry_mac_algo_info(GCRY_MAC_CMAC_AES, GCRYCTL_GET_KEYLEN,
                           NULL, &info_len);
  if (err || info_len != 16)
    return die("gcry_mac_algo_info CMAC keylen mismatch", info_len);
  info_len = 0;
  err = gcry_mac_algo_info(GCRY_MAC_GOST28147_IMIT, GCRYCTL_GET_KEYLEN,
                           NULL, &info_len);
  if (err || info_len != 32)
    return die("gcry_mac_algo_info GOST28147-IMIT keylen mismatch",
               info_len);
  info_len = 0;
  err = gcry_mac_algo_info(GCRY_MAC_HMAC_SHA256, GCRYCTL_GET_KEYLEN,
                           digest, &info_len);
  if (!err)
    return die("gcry_mac_algo_info accepted output buffer", 0);

  if (gcry_mac_algo_info(GCRY_MAC_GOST28147_IMIT, GCRYCTL_TEST_ALGO,
                         NULL, NULL))
    return die("gcry_mac_algo_info GOST28147-IMIT rejected", 0);
  if (gcry_mac_map_name("GOST28147_IMIT") != GCRY_MAC_GOST28147_IMIT)
    return die("gcry_mac_map_name GOST28147-IMIT mismatch", 0);
  if (gcry_mac_get_algo_maclen(GCRY_MAC_GOST28147_IMIT) != 4
      || gcry_mac_get_algo_keylen(GCRY_MAC_GOST28147_IMIT) != 32)
    return die("gcry_mac_get_algo_* GOST28147-IMIT mismatch", 0);
  err = gcry_mac_open(&mac, GCRY_MAC_GOST28147_IMIT, 0, NULL);
  if (err)
    return die("gcry_mac_open GOST28147-IMIT failed", err);
  err = gcry_mac_setkey(mac, gost28147_imit_key,
                        sizeof gost28147_imit_key);
  if (err)
    return die("gcry_mac_setkey GOST28147-IMIT failed", err);
  err = gcry_mac_ctl(mac, GCRYCTL_SET_SBOX, "1.2.643.2.2.31.1", 0);
  if (err)
    return die("gcry_mac_ctl GOST28147-IMIT set-sbox failed", err);
  err = gcry_mac_ctl(mac, GCRYCTL_SET_SBOX, "bad", 0);
  if (gpg_err_code(err) != GPG_ERR_VALUE_NOT_FOUND)
    return die("gcry_mac_ctl GOST28147-IMIT invalid sbox mismatch",
               gpg_err_code(err));
  err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
  if (gpg_err_code(err) != GPG_ERR_INV_LENGTH)
    return die("gcry_mac_setiv GOST28147-IMIT length mismatch",
               gpg_err_code(err));
  err = gcry_mac_write(mac, gost28147_imit_data,
                       sizeof gost28147_imit_data);
  if (err)
    return die("gcry_mac_write GOST28147-IMIT failed", err);
  mac_len = sizeof expected_gost28147_imit;
  err = gcry_mac_read(mac, mac_digest, &mac_len);
  if (err)
    return die("gcry_mac_read GOST28147-IMIT failed", err);
  if (mac_len != sizeof expected_gost28147_imit
      || memcmp(mac_digest, expected_gost28147_imit,
                sizeof expected_gost28147_imit))
    return die("gcry_mac_read GOST28147-IMIT mismatch", mac_len);
  err = gcry_mac_verify(mac, expected_gost28147_imit,
                        sizeof expected_gost28147_imit);
  if (err)
    return die("gcry_mac_verify GOST28147-IMIT failed", err);
  gcry_mac_close(mac);
  mac = NULL;

  err = gcry_mac_open(&mac, GCRY_MAC_CMAC_AES, 0, NULL);
  if (err)
    return die("gcry_mac_open CMAC-AES failed", err);
  err = gcry_mac_setkey(mac, cmac_aes_key, sizeof cmac_aes_key);
  if (err)
    return die("gcry_mac_setkey CMAC-AES failed", err);
  err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
  if (gpg_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_mac_setiv accepted CMAC IV", gpg_err_code(err));
  err = gcry_mac_write(mac, cmac_aes_data, sizeof cmac_aes_data);
  if (err)
    return die("gcry_mac_write CMAC-AES failed", err);
  mac_len = sizeof mac_digest;
  err = gcry_mac_read(mac, mac_digest, &mac_len);
  if (err)
    return die("gcry_mac_read CMAC-AES failed", err);
  if (mac_len != sizeof expected_cmac_aes
      || memcmp(mac_digest, expected_cmac_aes, sizeof expected_cmac_aes))
    return die("gcry_mac_read CMAC-AES mismatch", mac_len);
  gcry_mac_close(mac);
  mac = NULL;

  err = gcry_mac_open(&mac, GCRY_MAC_POLY1305, 0, NULL);
  if (err)
    return die("gcry_mac_open Poly1305 failed", err);
  err = gcry_mac_setkey(mac, poly1305_key, sizeof poly1305_key);
  if (err)
    return die("gcry_mac_setkey Poly1305 failed", err);
  err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
  if (gpg_err_code(err) != GPG_ERR_INV_ARG)
    return die("gcry_mac_setiv accepted plain Poly1305 IV",
               gpg_err_code(err));
  err = gcry_mac_write(mac, "Cryptographic Forum Research Group", 34);
  if (err)
    return die("gcry_mac_write Poly1305 failed", err);
  mac_len = sizeof mac_digest;
  err = gcry_mac_read(mac, mac_digest, &mac_len);
  if (err)
    return die("gcry_mac_read Poly1305 failed", err);
  if (mac_len != sizeof expected_poly1305
      || memcmp(mac_digest, expected_poly1305, sizeof expected_poly1305))
    return die("gcry_mac_read Poly1305 mismatch", mac_len);
  gcry_mac_close(mac);
  mac = NULL;

  for (i = 0; i < sizeof cmac_probe_algos / sizeof cmac_probe_algos[0]; i++)
    {
      mac_algo = cmac_probe_algos[i];
      key_len = gcry_mac_get_algo_keylen(mac_algo);
      expected_mac_len = gcry_mac_get_algo_maclen(mac_algo);
      if (key_len == 0 || key_len > sizeof mac_probe_key)
        return die("gcry_mac_get_algo_keylen CMAC probe invalid", mac_algo);
      if (expected_mac_len == 0 || expected_mac_len > sizeof mac_digest)
        return die("gcry_mac_get_algo_maclen CMAC probe invalid", mac_algo);
      err = gcry_mac_algo_info(mac_algo, GCRYCTL_TEST_ALGO, NULL, NULL);
      if (err)
        return die("gcry_mac_algo_info CMAC probe rejected", mac_algo);
      info_len = 0;
      err = gcry_mac_algo_info(mac_algo, GCRYCTL_GET_KEYLEN, NULL,
                               &info_len);
      if (err || info_len != key_len)
        return die("gcry_mac_algo_info CMAC probe keylen mismatch",
                   mac_algo);
      err = gcry_mac_open(&mac, mac_algo, 0, NULL);
      if (err)
        return die("gcry_mac_open CMAC probe failed", mac_algo);
      err = gcry_mac_setkey(mac, mac_probe_key, key_len);
      if (err)
        return die("gcry_mac_setkey CMAC probe failed", mac_algo);
      err = gcry_mac_write(mac, "abc", 3);
      if (err)
        return die("gcry_mac_write CMAC probe failed", mac_algo);
      mac_len = sizeof mac_digest;
      err = gcry_mac_read(mac, mac_digest, &mac_len);
      if (err)
        return die("gcry_mac_read CMAC probe failed", mac_algo);
      if (expected_mac_len != expected_cmac_probe_lens[i])
        return die("gcry_mac_get_algo_maclen CMAC probe vector mismatch",
                   mac_algo);
      if (mac_len != expected_mac_len
          || memcmp(mac_digest, expected_cmac_probe_tags[i], mac_len))
        return die("gcry_mac_read CMAC probe tag mismatch", mac_algo);
      gcry_mac_close(mac);
      mac = NULL;
    }

  for (i = 0; i < sizeof gmac_probe_algos / sizeof gmac_probe_algos[0]; i++)
    {
      mac_algo = gmac_probe_algos[i];
      key_len = gcry_mac_get_algo_keylen(mac_algo);
      expected_mac_len = gcry_mac_get_algo_maclen(mac_algo);
      if (key_len == 0 || key_len > sizeof mac_probe_key)
        return die("gcry_mac_get_algo_keylen GMAC probe invalid", mac_algo);
      if (expected_mac_len != 16)
        return die("gcry_mac_get_algo_maclen GMAC probe invalid",
                   mac_algo);
      err = gcry_mac_algo_info(mac_algo, GCRYCTL_TEST_ALGO, NULL, NULL);
      if (err)
        return die("gcry_mac_algo_info GMAC probe rejected", mac_algo);
      info_len = 0;
      err = gcry_mac_algo_info(mac_algo, GCRYCTL_GET_KEYLEN, NULL,
                               &info_len);
      if (err || info_len != key_len)
        return die("gcry_mac_algo_info GMAC probe keylen mismatch",
                   mac_algo);
      err = gcry_mac_open(&mac, mac_algo, 0, NULL);
      if (err)
        return die("gcry_mac_open GMAC probe failed", mac_algo);
      err = gcry_mac_setkey(mac, mac_probe_key, key_len);
      if (err)
        return die("gcry_mac_setkey GMAC probe failed", mac_algo);
      err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
      if (err)
        return die("gcry_mac_setiv GMAC probe failed", mac_algo);
      err = gcry_mac_write(mac, "abc", 3);
      if (err)
        return die("gcry_mac_write GMAC probe failed", mac_algo);
      mac_len = sizeof mac_digest;
      err = gcry_mac_read(mac, mac_digest, &mac_len);
      if (err)
        return die("gcry_mac_read GMAC probe failed", mac_algo);
      if (mac_len != 16
          || memcmp(mac_digest, expected_gmac_probe_tags[i], 16))
        return die("gcry_mac_read GMAC probe tag mismatch", mac_algo);
      gcry_mac_close(mac);
      mac = NULL;
    }

  for (i = 0;
       i < sizeof poly1305_cipher_probe_algos
           / sizeof poly1305_cipher_probe_algos[0];
       i++)
    {
      mac_algo = poly1305_cipher_probe_algos[i];
      key_len = gcry_mac_get_algo_keylen(mac_algo);
      if (key_len != 32)
        return die("gcry_mac_get_algo_keylen Poly1305 probe invalid",
                   mac_algo);
      err = gcry_mac_algo_info(mac_algo, GCRYCTL_TEST_ALGO, NULL, NULL);
      if (err)
        return die("gcry_mac_algo_info Poly1305 probe rejected", mac_algo);
      err = gcry_mac_open(&mac, mac_algo, 0, NULL);
      if (err)
        return die("gcry_mac_open Poly1305 probe failed", mac_algo);
      err = gcry_mac_setkey(mac, mac_probe_key, key_len);
      if (err)
        return die("gcry_mac_setkey Poly1305 probe failed", mac_algo);
      err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
      if (err)
        return die("gcry_mac_setiv Poly1305 probe failed", mac_algo);
      err = gcry_mac_write(mac, "abc", 3);
      if (err)
        return die("gcry_mac_write Poly1305 probe failed", mac_algo);
      mac_len = sizeof mac_digest;
      err = gcry_mac_read(mac, mac_digest, &mac_len);
      if (err)
        return die("gcry_mac_read Poly1305 probe failed", mac_algo);
      if (mac_len != 16
          || memcmp(mac_digest, expected_poly1305_cipher_probe_tags[i], 16))
        return die("gcry_mac_read Poly1305 probe tag mismatch", mac_algo);
      gcry_mac_close(mac);
      mac = NULL;
    }

  err = gcry_mac_open(&mac, GCRY_MAC_POLY1305_AES, 0, NULL);
  if (err)
    return die("gcry_mac_open Poly1305 setiv order probe failed", err);
  err = gcry_mac_setiv(mac, mac_probe_iv, sizeof mac_probe_iv);
  if (err)
    return die("gcry_mac_setiv before key failed", err);
  err = gcry_mac_setkey(mac, mac_probe_key, 32);
  if (err)
    return die("gcry_mac_setkey Poly1305 setiv order probe failed", err);
  err = gcry_mac_write(mac, "abc", 3);
  if (gpg_err_code(err) != GPG_ERR_INV_STATE)
    return die("gcry_mac_setiv before key preserved nonce",
               gpg_err_code(err));
  gcry_mac_close(mac);
  mac = NULL;

  err = gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                        "salt", 4, 1, sizeof kdf_digest, kdf_digest);
  if (err)
    return die("gcry_kdf_derive PBKDF2 failed", err);
  if (memcmp(kdf_digest, expected_pbkdf2_sha1, sizeof expected_pbkdf2_sha1))
    return die("gcry_kdf_derive PBKDF2 mismatch", 0);
  for (i = 0;
       i < sizeof pbkdf2_hmac_probe_algos / sizeof pbkdf2_hmac_probe_algos[0];
       i++)
    {
      err = gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2,
                            pbkdf2_hmac_probe_algos[i], "salt", 4, 1,
                            sizeof pbkdf2_digest, pbkdf2_digest);
      if (err)
        return die("gcry_kdf_derive PBKDF2 HMAC probe failed",
                   pbkdf2_hmac_probe_algos[i]);
      if (memcmp(pbkdf2_digest, expected_pbkdf2_hmac_probe[i],
                 sizeof pbkdf2_digest))
        return die("gcry_kdf_derive PBKDF2 HMAC probe mismatch",
                   pbkdf2_hmac_probe_algos[i]);
    }
  err = gcry_kdf_derive("password", 8, GCRY_KDF_SALTED_S2K, GCRY_MD_SHA1,
                        "salt", 4, 0, sizeof kdf_digest, kdf_digest);
  if (gpg_err_code(err) != GPG_ERR_INV_VALUE)
    return die("gcry_kdf_derive accepted short S2K salt", gpg_err_code(err));
  err = gcry_kdf_derive("password", 8, GCRY_KDF_ITERSALTED_S2K,
                        GCRY_MD_SHA1, "123456789", 9, 1024,
                        sizeof kdf_digest, kdf_digest);
  if (gpg_err_code(err) != GPG_ERR_INV_VALUE)
    return die("gcry_kdf_derive accepted long S2K salt", gpg_err_code(err));

  err = gcry_kdf_open(&kdf, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
                      argon2_params3, 3, "password", 8,
                      "1234567890123456", 16, NULL, 0, NULL, 0);
  if (err)
    return die("gcry_kdf_open Argon2 3-param failed", err);
  err = gcry_kdf_compute(kdf, NULL);
  if (err)
    return die("gcry_kdf_compute Argon2 failed", err);
  err = gcry_kdf_final(kdf, sizeof argon2_digest, argon2_digest);
  if (err)
    return die("gcry_kdf_final Argon2 failed", err);
  gcry_kdf_close(kdf);
  kdf = NULL;

  err = gcry_kdf_open(&kdf, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
                      argon2_params3, 3, "password", 8,
                      "1234567890123456", 16, NULL, 0, NULL, 0);
  if (err)
    return die("gcry_kdf_open Argon2 taglen probe failed", err);
  err = gcry_kdf_compute(kdf, NULL);
  if (err)
    return die("gcry_kdf_compute Argon2 taglen probe failed", err);
  err = gcry_kdf_final(kdf, sizeof balloon_digest, balloon_digest);
  if (!err)
    return die("gcry_kdf_final Argon2 ignored tag length", 0);
  gcry_kdf_close(kdf);
  kdf = NULL;

  err = gcry_kdf_open(&kdf, GCRY_KDF_BALLOON, GCRY_MD_SHA256,
                      balloon_params, 2, "password", 8, "salt", 4,
                      NULL, 0, NULL, 0);
  if (err)
    return die("gcry_kdf_open Balloon failed", err);
  err = gcry_kdf_compute(kdf, NULL);
  if (err)
    return die("gcry_kdf_compute Balloon failed", err);
  err = gcry_kdf_final(kdf, sizeof balloon_digest, balloon_digest);
  if (err)
    return die("gcry_kdf_final Balloon failed", err);
  gcry_kdf_close(kdf);
  kdf = NULL;

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
  if (mac)
    gcry_mac_close(mac);
  if (kdf)
    gcry_kdf_close(kdf);
  if (keyed_md)
    gcry_md_close(keyed_md);
  gcry_md_close(md);

  return 0;
}

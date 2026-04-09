#ifndef SAFE_CABI_EXPORTS_H
#define SAFE_CABI_EXPORTS_H

#include "gcrypt.h"

#include <stdint.h>

gcry_error_t safe_gcry_control_dispatch(enum gcry_ctl_cmds cmd,
                                        uintptr_t arg0,
                                        uintptr_t arg1,
                                        uintptr_t arg2);
const char *safe_gcry_check_version(const char *req_version);
gcry_err_code_t safe_gcry_err_code_from_errno(int err);
int safe_gcry_err_code_to_errno(gcry_err_code_t code);
gcry_error_t safe_gcry_err_make_from_errno(gcry_err_source_t source, int err);
gcry_error_t safe_gcry_error_from_errno(int err);
const char *safe_gcry_strerror(gcry_error_t err);
const char *safe_gcry_strsource(gcry_error_t err);
void *safe_gcry_malloc(size_t n);
void *safe_gcry_malloc_secure(size_t n);
void *safe_gcry_calloc(size_t n, size_t m);
void *safe_gcry_calloc_secure(size_t n, size_t m);
void *safe_gcry_realloc(void *a, size_t n);
char *safe_gcry_strdup(const char *string);
int safe_gcry_is_secure(const void *a);
void *safe_gcry_xcalloc(size_t n, size_t m);
void *safe_gcry_xcalloc_secure(size_t n, size_t m);
void *safe_gcry_xmalloc(size_t n);
void *safe_gcry_xmalloc_secure(size_t n);
void *safe_gcry_xrealloc(void *a, size_t n);
char *safe_gcry_xstrdup(const char *a);
void safe_gcry_free(void *a);
void safe_gcry_set_outofcore_handler(gcry_handler_no_mem_t handler, void *opaque);
gcry_error_t safe_gcry_random_add_bytes(const void *buffer, size_t length, int quality);
void *safe_gcry_random_bytes(size_t nbytes, enum gcry_random_level level);
void *safe_gcry_random_bytes_secure(size_t nbytes, enum gcry_random_level level);
void safe_gcry_randomize(void *buffer, size_t length, enum gcry_random_level level);
void safe_gcry_create_nonce(void *buffer, size_t length);
char *safe_gcry_get_config(int mode, const char *what);
gcry_error_t safe_gcry_md_get(gcry_md_hd_t hd, int algo, unsigned char *buffer, int buflen);
gcry_error_t safe_gcry_sexp_build_dispatch(gcry_sexp_t *retsexp,
                                           size_t *erroff,
                                           const char *format);
gcry_sexp_t safe_gcry_sexp_vlist_dispatch(const gcry_sexp_t a);
gpg_error_t safe_gcry_sexp_extract_param_dispatch(gcry_sexp_t sexp,
                                                  const char *path,
                                                  const char *list);
void safe_gcry_log_debug_dispatch(const char *message);
uintptr_t safe_gcry_stub_zero(void);

#endif /* SAFE_CABI_EXPORTS_H */

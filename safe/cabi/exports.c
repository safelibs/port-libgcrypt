#include "exports.h"

#include <stdarg.h>
#include <stdio.h>

#define FORWARD0(ret, name) \
  ret name(void) { return safe_##name(); }
#define FORWARD1(ret, name, t1, a1) \
  ret name(t1 a1) { return safe_##name(a1); }
#define FORWARD2(ret, name, t1, a1, t2, a2) \
  ret name(t1 a1, t2 a2) { return safe_##name(a1, a2); }
#define FORWARD3(ret, name, t1, a1, t2, a2, t3, a3) \
  ret name(t1 a1, t2 a2, t3 a3) { return safe_##name(a1, a2, a3); }
#define FORWARD4(ret, name, t1, a1, t2, a2, t3, a3, t4, a4) \
  ret name(t1 a1, t2 a2, t3 a3, t4 a4) { return safe_##name(a1, a2, a3, a4); }
#define FORWARDV(name, t1, a1, t2, a2) \
  void name(t1 a1, t2 a2) { safe_##name(a1, a2); }
#define FORWARDV1(name, t1, a1) \
  void name(t1 a1) { safe_##name(a1); }
#define FORWARDV3(name, t1, a1, t2, a2, t3, a3) \
  void name(t1 a1, t2 a2, t3 a3) { safe_##name(a1, a2, a3); }

FORWARD1(const char *, gcry_check_version, const char *, req_version)
FORWARD1(gcry_err_code_t, gcry_err_code_from_errno, int, err)
FORWARD1(int, gcry_err_code_to_errno, gcry_err_code_t, code)
FORWARD2(gcry_error_t, gcry_err_make_from_errno, gcry_err_source_t, source, int, err)
FORWARD1(gcry_error_t, gcry_error_from_errno, int, err)
FORWARD1(const char *, gcry_strerror, gcry_error_t, err)
FORWARD1(const char *, gcry_strsource, gcry_error_t, err)
FORWARD1(void *, gcry_malloc, size_t, n)
FORWARD1(void *, gcry_malloc_secure, size_t, n)
FORWARD2(void *, gcry_calloc, size_t, n, size_t, m)
FORWARD2(void *, gcry_calloc_secure, size_t, n, size_t, m)
FORWARD2(void *, gcry_realloc, void *, a, size_t, n)
FORWARD1(char *, gcry_strdup, const char *, string)
FORWARD1(int, gcry_is_secure, const void *, a)
FORWARD2(void *, gcry_xcalloc, size_t, n, size_t, m)
FORWARD2(void *, gcry_xcalloc_secure, size_t, n, size_t, m)
FORWARD1(void *, gcry_xmalloc, size_t, n)
FORWARD1(void *, gcry_xmalloc_secure, size_t, n)
FORWARD2(void *, gcry_xrealloc, void *, a, size_t, n)
FORWARD1(char *, gcry_xstrdup, const char *, a)
FORWARDV(gcry_set_outofcore_handler, gcry_handler_no_mem_t, handler, void *, opaque)
FORWARD3(gcry_error_t, gcry_random_add_bytes, const void *, buffer, size_t, length, int, quality)
FORWARD2(void *, gcry_random_bytes, size_t, nbytes, enum gcry_random_level, level)
FORWARD2(void *, gcry_random_bytes_secure, size_t, nbytes, enum gcry_random_level, level)
FORWARDV3(gcry_randomize, void *, buffer, size_t, length, enum gcry_random_level, level)
FORWARDV(gcry_create_nonce, void *, buffer, size_t, length)
FORWARD2(char *, gcry_get_config, int, mode, const char *, what)
FORWARDV1(gcry_free, void *, a)
FORWARD4(gcry_error_t,
         gcry_md_get,
         gcry_md_hd_t, hd,
         int, algo,
         unsigned char *, buffer,
         int, buflen)

gcry_error_t
gcry_control(enum gcry_ctl_cmds cmd, ...)
{
  uintptr_t arg0 = 0;
  uintptr_t arg1 = 0;
  uintptr_t arg2 = 0;
  va_list ap;

  va_start(ap, cmd);
  switch (cmd)
    {
    case GCRYCTL_SET_VERBOSITY:
    case GCRYCTL_SET_DEBUG_FLAGS:
    case GCRYCTL_DISABLE_SECMEM:
    case GCRYCTL_INITIALIZATION_FINISHED:
    case GCRYCTL_ENABLE_QUICK_RANDOM:
    case GCRYCTL_FIPS_MODE_P:
      arg0 = (uintptr_t)va_arg(ap, int);
      break;
    case GCRYCTL_INIT_SECMEM:
      arg0 = (uintptr_t)va_arg(ap, size_t);
      arg1 = (uintptr_t)va_arg(ap, int);
      break;
    case GCRYCTL_DISABLE_HWF:
      arg0 = (uintptr_t)va_arg(ap, const char *);
      arg1 = (uintptr_t)va_arg(ap, void *);
      break;
    case GCRYCTL_PRINT_CONFIG:
      arg0 = (uintptr_t)va_arg(ap, FILE *);
      break;
    default:
      break;
    }
  va_end(ap);

  return safe_gcry_control_dispatch(cmd, arg0, arg1, arg2);
}

gcry_error_t
gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  va_end(ap);
  return safe_gcry_sexp_build_dispatch(retsexp, erroff, format);
}

gcry_sexp_t
gcry_sexp_vlist(const gcry_sexp_t a, ...)
{
  va_list ap;

  va_start(ap, a);
  va_end(ap);
  return safe_gcry_sexp_vlist_dispatch(a);
}

gpg_error_t
gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path, const char *list, ...)
{
  va_list ap;

  va_start(ap, list);
  va_end(ap);
  return safe_gcry_sexp_extract_param_dispatch(sexp, path, list);
}

void
gcry_log_debug(const char *fmt, ...)
{
  char buffer[1024];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buffer, sizeof buffer, fmt, ap);
  va_end(ap);
  safe_gcry_log_debug_dispatch(buffer);
}

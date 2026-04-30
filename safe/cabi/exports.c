#include "exports.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#define FORWARD5(ret, name, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
  ret name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5) { return safe_##name(a1, a2, a3, a4, a5); }
#define FORWARDV(name, t1, a1, t2, a2) \
  void name(t1 a1, t2 a2) { safe_##name(a1, a2); }
#define FORWARDV1(name, t1, a1) \
  void name(t1 a1) { safe_##name(a1); }
#define FORWARDV3(name, t1, a1, t2, a2, t3, a3) \
  void name(t1 a1, t2 a2, t3 a3) { safe_##name(a1, a2, a3); }

static gcry_handler_log_t registered_log_handler;
static void *registered_log_opaque;

static void
invoke_registered_log_handler(gcry_handler_log_t handler,
                              void *opaque,
                              int level,
                              const char *fmt,
                              ...)
{
  va_list ap;

  va_start(ap, fmt);
  handler(opaque, level, fmt, ap);
  va_end(ap);
}

void
safe_cabi_set_log_handler(gcry_handler_log_t handler, void *opaque)
{
  registered_log_handler = handler;
  registered_log_opaque = opaque;
}

void
safe_cabi_dispatch_log_message(int level, const char *message)
{
  const char *prefix = "";

  if (!message)
    message = "";

  if (registered_log_handler)
    {
      invoke_registered_log_handler(registered_log_handler,
                                    registered_log_opaque,
                                    level,
                                    "%s",
                                    message);
      return;
    }

  switch (level)
    {
    case GCRY_LOG_CONT:
      break;
    case GCRY_LOG_FATAL:
      prefix = "Fatal: ";
      break;
    case GCRY_LOG_DEBUG:
      prefix = "DBG: ";
      break;
    default:
      break;
    }

  if (*prefix)
    fputs(prefix, stderr);
  fputs(message, stderr);
}

FORWARD1(const char *, gcry_check_version, const char *, req_version)
FORWARDV(gcry_set_progress_handler, gcry_handler_progress_t, cb, void *, cb_data)
FORWARD5(void,
         gcry_set_allocation_handler,
         gcry_handler_alloc_t, func_alloc,
         gcry_handler_alloc_t, func_alloc_secure,
         gcry_handler_secure_check_t, func_secure_check,
         gcry_handler_realloc_t, func_realloc,
         gcry_handler_free_t, func_free)
FORWARDV(gcry_set_fatalerror_handler, gcry_handler_error_t, fnc, void *, opaque)
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
FORWARD0(gcry_error_t, gcry_pk_register)
FORWARDV3(gcry_log_debughex,
          const char *, text,
          const void *, buffer,
          size_t, length)

gcry_error_t
gcry_control(enum gcry_ctl_cmds cmd, ...)
{
  uintptr_t arg0 = 0;
  uintptr_t arg1 = 0;
  uintptr_t arg2 = 0;
  uintptr_t arg3 = 0;
  va_list ap;

  va_start(ap, cmd);
  switch (cmd)
    {
    case GCRYCTL_SET_PREFERRED_RNG_TYPE:
    case GCRYCTL_SET_VERBOSITY:
    case GCRYCTL_FIPS_SERVICE_INDICATOR_KDF:
    case 61: /* PRIV_CTL_EXTERNAL_LOCK_TEST */
      arg0 = (uintptr_t)va_arg(ap, int);
      break;
    case GCRYCTL_SET_DEBUG_FLAGS:
    case GCRYCTL_CLEAR_DEBUG_FLAGS:
    case GCRYCTL_AUTO_EXPAND_SECMEM:
      arg0 = (uintptr_t)va_arg(ap, unsigned int);
      break;
    case GCRYCTL_INIT_SECMEM:
      arg0 = (uintptr_t)va_arg(ap, size_t);
      arg1 = (uintptr_t)va_arg(ap, int);
      break;
    case GCRYCTL_SET_RANDOM_SEED_FILE:
    case GCRYCTL_SET_RNDEGD_SOCKET:
    case GCRYCTL_SET_RANDOM_DAEMON_SOCKET:
    case GCRYCTL_SET_THREAD_CBS:
      arg0 = (uintptr_t)va_arg(ap, void *);
      break;
    case GCRYCTL_DISABLE_HWF:
      arg0 = (uintptr_t)va_arg(ap, const char *);
      arg1 = (uintptr_t)va_arg(ap, void *);
      break;
    case GCRYCTL_GET_CURRENT_RNG_TYPE:
      arg0 = (uintptr_t)va_arg(ap, int *);
      break;
    case GCRYCTL_PRINT_CONFIG:
      arg0 = (uintptr_t)va_arg(ap, FILE *);
      break;
    case GCRYCTL_DRBG_REINIT:
      arg0 = (uintptr_t)va_arg(ap, const char *);
      arg1 = (uintptr_t)va_arg(ap, void *);
      arg2 = (uintptr_t)va_arg(ap, int);
      arg3 = (uintptr_t)va_arg(ap, void *);
      break;
    case 59: /* PRIV_CTL_RUN_EXTRNG_TEST */
      arg0 = (uintptr_t)va_arg(ap, void *);
      arg1 = (uintptr_t)va_arg(ap, void *);
      break;
    default:
      break;
    }
  va_end(ap);

  return safe_gcry_control_dispatch(cmd, arg0, arg1, arg2, arg3);
}

void
gcry_set_log_handler(gcry_handler_log_t f, void *opaque)
{
  safe_cabi_set_log_handler(f, opaque);
}

void
gcry_set_gettext_handler(const char *(*f)(const char *))
{
  safe_gcry_set_gettext_handler(f);
}

static int
sexp_format_next_spec(const char *format, size_t *offset)
{
  enum
    {
      SEXP_FORMAT_NORMAL,
      SEXP_FORMAT_LENGTH,
      SEXP_FORMAT_QUOTED,
      SEXP_FORMAT_HEX,
      SEXP_FORMAT_BASE64
    } state = SEXP_FORMAT_NORMAL;
  size_t idx = *offset;
  size_t length = 0;
  int escaped = 0;

  if (!format)
    return 0;

  while (format[idx])
    {
      unsigned char byte = (unsigned char)format[idx];

      switch (state)
        {
        case SEXP_FORMAT_NORMAL:
          if (byte == '%')
            {
              if (!format[idx + 1])
                {
                  *offset = idx;
                  return 0;
                }
              *offset = idx + 1;
              return (unsigned char)format[idx + 1];
            }
          else if (byte == '"')
            {
              state = SEXP_FORMAT_QUOTED;
              escaped = 0;
              idx++;
            }
          else if (byte == '#')
            {
              state = SEXP_FORMAT_HEX;
              idx++;
            }
          else if (byte == '|')
            {
              state = SEXP_FORMAT_BASE64;
              idx++;
            }
          else if (byte >= '0' && byte <= '9')
            {
              state = SEXP_FORMAT_LENGTH;
              length = byte - '0';
              idx++;
            }
          else
            idx++;
          break;

        case SEXP_FORMAT_LENGTH:
          if (byte >= '0' && byte <= '9')
            {
              length = length * 10 + (byte - '0');
              idx++;
            }
          else if (byte == ':')
            {
              idx++;
              while (length && format[idx])
                {
                  idx++;
                  length--;
                }
              state = SEXP_FORMAT_NORMAL;
            }
          else if (byte == '"')
            {
              state = SEXP_FORMAT_QUOTED;
              escaped = 0;
              idx++;
            }
          else if (byte == '#')
            {
              state = SEXP_FORMAT_HEX;
              idx++;
            }
          else if (byte == '|')
            {
              state = SEXP_FORMAT_BASE64;
              idx++;
            }
          else
            {
              state = SEXP_FORMAT_NORMAL;
              idx++;
            }
          break;

        case SEXP_FORMAT_QUOTED:
          if (escaped)
            {
              escaped = 0;
              idx++;
            }
          else if (byte == '\\')
            {
              escaped = 1;
              idx++;
            }
          else if (byte == '"')
            {
              state = SEXP_FORMAT_NORMAL;
              idx++;
            }
          else
            idx++;
          break;

        case SEXP_FORMAT_HEX:
          if (byte == '#')
            state = SEXP_FORMAT_NORMAL;
          idx++;
          break;

        case SEXP_FORMAT_BASE64:
          if (byte == '|')
            state = SEXP_FORMAT_NORMAL;
          idx++;
          break;
        }
    }

  *offset = idx;
  return 0;
}

static size_t
sexp_format_arg_count(const char *format)
{
  size_t argc = 0;
  size_t offset = 0;
  int spec;

  while ((spec = sexp_format_next_spec(format, &offset)))
    {
      switch (spec)
        {
        case 'm':
        case 'M':
        case 's':
        case 'S':
        case 'd':
        case 'u':
          argc += 1;
          break;
        case 'b':
          argc += 2;
          break;
        default:
          break;
        }
      offset++;
    }

  return argc;
}

gcry_error_t
gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff, const char *format, ...)
{
  va_list ap;
  uintptr_t *args = NULL;
  size_t argc = 0;
  size_t offset = 0;
  int spec;
  gcry_error_t rc;

  va_start(ap, format);
  argc = sexp_format_arg_count(format);
  if (argc)
    {
      args = malloc (argc * sizeof *args);
      if (!args)
        {
          va_end (ap);
          errno = ENOMEM;
          return safe_gcry_error_from_errno (errno);
        }
    }
  argc = 0;
  while ((spec = sexp_format_next_spec(format, &offset)))
    {
      switch (spec)
        {
        case 'm':
        case 'M':
        case 's':
        case 'S':
          args[argc++] = (uintptr_t)va_arg (ap, void *);
          break;
        case 'b':
          args[argc++] = (uintptr_t)(intptr_t)va_arg (ap, int);
          args[argc++] = (uintptr_t)va_arg (ap, void *);
          break;
        case 'd':
          args[argc++] = (uintptr_t)(intptr_t)va_arg (ap, int);
          break;
        case 'u':
          args[argc++] = (uintptr_t)va_arg (ap, unsigned int);
          break;
        default:
          break;
        }
      offset++;
    }
  va_end(ap);
  rc = safe_gcry_sexp_build_dispatch(retsexp, erroff, format, args, argc);
  free (args);
  return rc;
}

gcry_sexp_t
gcry_sexp_vlist(const gcry_sexp_t a, ...)
{
  va_list ap;
  gcry_sexp_t *items = NULL;
  size_t count = 0;
  size_t idx;
  gcry_sexp_t item;
  gcry_sexp_t result;

  va_start(ap, a);
  while ((item = va_arg (ap, gcry_sexp_t)))
    count++;
  va_end(ap);

  if (count)
    {
      items = malloc (count * sizeof *items);
      if (!items)
        {
          errno = ENOMEM;
          return NULL;
        }
    }

  va_start (ap, a);
  for (idx = 0; idx < count; idx++)
    items[idx] = va_arg (ap, gcry_sexp_t);
  (void)va_arg (ap, gcry_sexp_t);
  va_end (ap);

  result = safe_gcry_sexp_vlist_dispatch(a, items, count);
  free (items);
  return result;
}

gpg_error_t
gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path, const char *list, ...)
{
  va_list ap;
  void **args = NULL;
  size_t argc = 0;
  const char *p;
  gpg_error_t rc;
  void *term;

  va_start(ap, list);
  for (p = list; p && *p; p++)
    {
      if (*p == '&' || *p == '+' || *p == '-' || *p == '/' || *p == '?')
        continue;
      if (*p == '%')
        {
          p++;
          if (!*p)
            break;
          if (*p == 'l' && (p[1] == 'u' || p[1] == 'd'))
            p++;
          else if ((*p == 'z' && p[1] == 'u')
                   || (*p == '#' && p[1] == 's'))
            p++;
          continue;
        }
      if (*p == '\'' )
        {
          const char *end = strchr (p + 1, '\'');
          if (!end || end == p + 1)
            {
              va_end (ap);
              return GPG_ERR_SYNTAX;
            }
          p = end;
        }
      else if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == '\f' || *p == '\v')
        continue;
      argc++;
    }
  if (argc)
    {
      args = malloc (argc * sizeof *args);
      if (!args)
        {
          va_end (ap);
          errno = ENOMEM;
          return safe_gcry_error_from_errno (errno);
        }
    }
  for (size_t i = 0; i < argc; i++)
    {
      args[i] = va_arg (ap, void *);
      if (!args[i])
        {
          free (args);
          va_end (ap);
          return GPG_ERR_MISSING_VALUE;
        }
    }
  term = va_arg (ap, void *);
  va_end(ap);

  if (term)
    {
      free (args);
      return GPG_ERR_INV_ARG;
    }

  rc = safe_gcry_sexp_extract_param_dispatch(sexp, path, list, args, argc);
  free (args);
  return rc;
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

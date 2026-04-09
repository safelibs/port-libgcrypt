/* Derived from original/libgcrypt20-1.10.3/config.h.in for the phase-1
   Ubuntu 24.04/Linux upstream-test harness inputs.  */

#ifndef _GCRYPT_CONFIG_H_INCLUDED
#define _GCRYPT_CONFIG_H_INCLUDED

/* Enable gpg-error's strerror macro for W32CE.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

/* Fixed build metadata used by compat/compat.c.  */
#define PACKAGE_VERSION "1.10.3"
#define BUILD_REVISION "aa161086"
#define BUILD_TIMESTAMP "<none>"

/* Harness-visible feature toggles for the Linux test path.  */
#define HAVE_CONFIG_H 1
#define HAVE_CLOCK 1
#define HAVE_FLOCKFILE 1
#define HAVE_GETPID 1
#define HAVE_MMAP 1
#define HAVE_STDINT_H 1
#define HAVE_SYSCONF 1

#define SIZEOF_UNSIGNED_SHORT 2
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 8
#define SIZEOF_UNSIGNED_LONG_LONG 8
#define SIZEOF_UINT64_T 8

/* Keep the Windows paths disabled for Linux test compilation.  */
#undef HAVE_W32_SYSTEM
#undef HAVE_W32CE_SYSTEM

#define _GCRYPT_IN_LIBGCRYPT 1
#define CAMELLIA_EXT_SYM_PREFIX _gcry_

#ifndef _REENTRANT
#define _REENTRANT 1
#endif

#endif /* _GCRYPT_CONFIG_H_INCLUDED */

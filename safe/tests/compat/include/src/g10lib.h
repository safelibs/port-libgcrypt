/* Minimal compat-build subset derived from
   original/libgcrypt20-1.10.3/src/g10lib.h and kept aligned with the
   committed original-build contract.

   The imported Linux test harness only needs compat/compat.c to include
   this header so the upstream relative include layout still works.  */

#ifndef G10LIB_H
#define G10LIB_H 1

#ifndef _GCRYPT_IN_LIBGCRYPT
#error something is wrong with config.h
#endif

#endif /* G10LIB_H */

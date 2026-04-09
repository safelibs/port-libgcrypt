/* t-lock.c - Check the lock functions
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#if HAVE_PTHREAD
# include <pthread.h>
#endif

#ifdef _GCRYPT_IN_LIBGCRYPT
# undef _GCRYPT_IN_LIBGCRYPT
# include "gcrypt.h"
#else
# include <gcrypt.h>
#endif

#define PGM "t-lock"

#include "t-common.h"

/* Mingw requires us to include windows.h after winsock2.h which is
   included by gcrypt.h.  */
#ifdef _WIN32
# include <windows.h>
#endif

#ifdef _WIN32
# define THREAD_RET_TYPE  DWORD WINAPI
# define THREAD_RET_VALUE 0
#else
# define THREAD_RET_TYPE  void *
# define THREAD_RET_VALUE NULL
#endif


/* Number of threads to run.  */
#define N_NONCE_THREADS 8
/* Number of interations.  */
#define N_NONCE_ITERATIONS 1000
/* Requested nonce size.  */
#define NONCE_SIZE  11

/* Number of threads for the public crypto stress test.  */
#define N_CRYPTO_THREADS 4
/* Number of iterations for the public crypto stress test.  */
#define N_CRYPTO_ITERATIONS 1000


struct thread_arg_s
{
  int no;
};

static const unsigned char aes_test_key[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char aes_test_plaintext[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const unsigned char aes_test_ciphertext[16] = {
  0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

static const unsigned char sha256_input[] = "abc";

static const unsigned char sha256_result[32] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
  0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
  0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};




#if defined(HAVE_PTHREAD) || defined(_WIN32)
/* The nonce thread.  We simply request a couple of nonces and
   return.  */
static THREAD_RET_TYPE
nonce_thread (void *argarg)
{
  struct thread_arg_s *arg = argarg;
  int i;
  char nonce[NONCE_SIZE];

  for (i = 0; i < N_NONCE_ITERATIONS; i++)
    {
      gcry_create_nonce (nonce, sizeof nonce);
      if (i && !(i%100))
        info ("thread %d created %d nonces so far", arg->no, i);
    }

  gcry_free (arg);
  return THREAD_RET_VALUE;
}
#endif


/* To check Libgcrypt's public locking behavior we run several threads
   all accessing nonce generation.  If this function returns we know
   that there are no obvious deadlocks in this code path.  */
static void
check_nonce_lock (void)
{
  struct thread_arg_s *arg;
#ifdef _WIN32
  HANDLE threads[N_NONCE_THREADS];
  int i;
  int rc;

  for (i=0; i < N_NONCE_THREADS; i++)
    {
      arg = gcry_xmalloc (sizeof *arg);
      arg->no = i;
      threads[i] = CreateThread (NULL, 0, nonce_thread, arg, 0, NULL);
      if (!threads[i])
        die ("error creating nonce thread %d: rc=%d",
             i, (int)GetLastError ());
    }

  for (i=0; i < N_NONCE_THREADS; i++)
    {
      rc = WaitForSingleObject (threads[i], INFINITE);
      if (rc == WAIT_OBJECT_0)
        info ("nonce thread %d has terminated", i);
      else
        fail ("waiting for nonce thread %d failed: %d",
              i, (int)GetLastError ());
      CloseHandle (threads[i]);
    }

#elif HAVE_PTHREAD
  pthread_t threads[N_NONCE_THREADS];
  int rc, i;

  for (i=0; i < N_NONCE_THREADS; i++)
    {
      arg = gcry_xmalloc (sizeof *arg);
      arg->no = i;
      pthread_create (&threads[i], NULL, nonce_thread, arg);
    }

  for (i=0; i < N_NONCE_THREADS; i++)
    {
      rc = pthread_join (threads[i], NULL);
      if (rc)
        fail ("pthread_join failed for nonce thread %d: %s",
              i, strerror (errno));
      else
        info ("nonce thread %d has terminated", i);
    }
#else
  (void)arg;
#endif /*!_WIN32*/
}


#if defined(HAVE_PTHREAD) || defined(_WIN32)
/* The crypto thread repeatedly creates, uses, verifies, and destroys
   independent public API contexts from multiple threads.  */
static THREAD_RET_TYPE
crypto_thread (void *argarg)
{
  struct thread_arg_s *arg = argarg;
  int i;

  for (i = 0; i < N_CRYPTO_ITERATIONS; i++)
    {
      gcry_cipher_hd_t chd;
      gcry_md_hd_t mhd;
      gpg_error_t err;
      unsigned char out[sizeof aes_test_ciphertext];
      unsigned char digest[sizeof sha256_result];
      const unsigned char *p;

      err = gcry_cipher_open (&chd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
      if (err)
        die ("thread %d: gcry_cipher_open failed: %s",
             arg->no, gpg_strerror (err));
      err = gcry_cipher_setkey (chd, aes_test_key, sizeof aes_test_key);
      if (err)
        die ("thread %d: gcry_cipher_setkey failed: %s",
             arg->no, gpg_strerror (err));
      err = gcry_cipher_encrypt (chd, out, sizeof out,
                                 aes_test_plaintext,
                                 sizeof aes_test_plaintext);
      if (err)
        die ("thread %d: gcry_cipher_encrypt failed: %s",
             arg->no, gpg_strerror (err));
      if (memcmp (out, aes_test_ciphertext, sizeof out))
        die ("thread %d: AES test vector mismatch", arg->no);
      gcry_cipher_close (chd);

      err = gcry_md_open (&mhd, GCRY_MD_SHA256, 0);
      if (err)
        die ("thread %d: gcry_md_open failed: %s",
             arg->no, gpg_strerror (err));
      gcry_md_write (mhd, sha256_input, sizeof sha256_input - 1);
      p = gcry_md_read (mhd, GCRY_MD_SHA256);
      if (!p)
        die ("thread %d: gcry_md_read failed", arg->no);
      memcpy (digest, p, sizeof digest);
      gcry_md_close (mhd);
      if (memcmp (digest, sha256_result, sizeof digest))
        die ("thread %d: SHA-256 test vector mismatch", arg->no);

      if (i && !(i%100))
        info ("thread %d completed %d crypto iterations so far", arg->no, i);
    }

  gcry_free (arg);
  return THREAD_RET_VALUE;
}
#endif

/* To check Libgcrypt's public locking behavior we also run several
   threads all creating and destroying cipher and digest contexts.  */
static void
check_crypto_lock (void)
{
#ifdef _WIN32
  HANDLE threads[N_CRYPTO_THREADS];
  struct thread_arg_s *arg;
  int i;
  int rc;

  for (i=0; i < N_CRYPTO_THREADS; i++)
    {
      arg = gcry_xmalloc (sizeof *arg);
      arg->no = i;
      threads[i] = CreateThread (NULL, 0, crypto_thread, arg, 0, NULL);
      if (!threads[i])
        die ("error creating crypto thread %d: rc=%d",
             i, (int)GetLastError ());
    }

  for (i=0; i < N_CRYPTO_THREADS; i++)
    {
      rc = WaitForSingleObject (threads[i], INFINITE);
      if (rc == WAIT_OBJECT_0)
        info ("crypto thread %d has terminated", i);
      else
        fail ("waiting for crypto thread %d failed: %d",
              i, (int)GetLastError ());
      CloseHandle (threads[i]);
    }

#elif HAVE_PTHREAD
  pthread_t threads[N_CRYPTO_THREADS];
  struct thread_arg_s *arg;
  int rc, i;

  for (i=0; i < N_CRYPTO_THREADS; i++)
    {
      arg = gcry_xmalloc (sizeof *arg);
      arg->no = i;
      pthread_create (&threads[i], NULL, crypto_thread, arg);
    }

  for (i=0; i < N_CRYPTO_THREADS; i++)
    {
      rc = pthread_join (threads[i], NULL);
      if (rc)
        fail ("pthread_join failed for crypto thread %d: %s",
              i, strerror (errno));
      else
        info ("crypto thread %d has terminated", i);
    }
#endif /*!_WIN32*/
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts (
"usage: ./t-lock [options]\n"
"\n"
"Options:\n"
"  --verbose      Show what is going on\n"
"  --debug        Flyswatter\n"
);
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
    }

  if (debug)
    xgcry_control ((GCRYCTL_SET_DEBUG_FLAGS, 1u, 0));
  xgcry_control ((GCRYCTL_DISABLE_SECMEM, 0));
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch");
  xgcry_control ((GCRYCTL_ENABLE_QUICK_RANDOM, 0));
  xgcry_control ((GCRYCTL_INITIALIZATION_FINISHED, 0));

  check_nonce_lock ();
  check_crypto_lock ();

  /* Run a second time to exercise repeated threaded context setup.  */
  check_crypto_lock ();

  return error_count ? 1 : 0;
}

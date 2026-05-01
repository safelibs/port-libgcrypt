#include <string.h>
#include <strings.h>

#define GCRY_MD_MD5 1
#define GCRY_MD_SHA1 2
#define GCRY_MD_RMD160 3
#define GCRY_MD_TIGER 6
#define GCRY_MD_SHA256 8
#define GCRY_MD_SHA384 9
#define GCRY_MD_SHA512 10
#define GCRY_MD_SHA224 11
#define GCRY_MD_MD4 301
#define GCRY_MD_TIGER1 306
#define GCRY_MD_TIGER2 307
#define GCRY_MD_SHA512_256 327
#define GCRY_MD_SHA512_224 328

static int name_is(const char *name, const char *expected) {
  return name != NULL && strcasecmp(name, expected) == 0;
}

static int oid_is(const char *name, const char *expected) {
  return name != NULL &&
         (strcmp(name, expected) == 0 ||
          (strncmp(name, "oid.", 4) == 0 && strcmp(name + 4, expected) == 0));
}

int gcry_md_map_name(const char *name) {
  if (name_is(name, "md5") || oid_is(name, "1.2.840.113549.2.5") ||
      oid_is(name, "1.2.840.113549.1.1.4")) {
    return GCRY_MD_MD5;
  }
  if (name_is(name, "sha1") || oid_is(name, "1.3.14.3.2.26") ||
      oid_is(name, "1.2.840.113549.1.1.5") ||
      oid_is(name, "1.2.840.10045.4.1")) {
    return GCRY_MD_SHA1;
  }
  if (name_is(name, "rmd160") || name_is(name, "ripemd160") ||
      oid_is(name, "1.3.36.3.2.1")) {
    return GCRY_MD_RMD160;
  }
  if (name_is(name, "tiger192")) {
    return GCRY_MD_TIGER;
  }
  if (name_is(name, "tiger") || name_is(name, "tiger1")) {
    return GCRY_MD_TIGER1;
  }
  if (name_is(name, "tiger2")) {
    return GCRY_MD_TIGER2;
  }
  if (name_is(name, "sha224") || oid_is(name, "2.16.840.1.101.3.4.2.4") ||
      oid_is(name, "1.2.840.113549.1.1.14")) {
    return GCRY_MD_SHA224;
  }
  if (name_is(name, "sha256") || oid_is(name, "2.16.840.1.101.3.4.2.1") ||
      oid_is(name, "1.2.840.113549.1.1.11") ||
      oid_is(name, "1.2.840.10045.4.3.2")) {
    return GCRY_MD_SHA256;
  }
  if (name_is(name, "sha384") || oid_is(name, "2.16.840.1.101.3.4.2.2") ||
      oid_is(name, "1.2.840.113549.1.1.12") ||
      oid_is(name, "1.2.840.10045.4.3.3")) {
    return GCRY_MD_SHA384;
  }
  if (name_is(name, "sha512") || oid_is(name, "2.16.840.1.101.3.4.2.3") ||
      oid_is(name, "1.2.840.113549.1.1.13") ||
      oid_is(name, "1.2.840.10045.4.3.4")) {
    return GCRY_MD_SHA512;
  }
  if (name_is(name, "sha512256")) {
    return GCRY_MD_SHA512_256;
  }
  if (name_is(name, "sha512224")) {
    return GCRY_MD_SHA512_224;
  }
  if (name_is(name, "md4") || oid_is(name, "1.2.840.113549.2.4")) {
    return GCRY_MD_MD4;
  }

  return 0;
}

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
ORIGINAL_DIR="${REPO_DIR}/original/libgcrypt20-1.10.3"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
GENERATED_DIR="${SAFE_DIR}/target/bootstrap/generated"
STAGE_ROOT="${SAFE_DIR}/target/bootstrap/staging"
STAGE_PREFIX="${STAGE_ROOT}/usr"
STAGE_LIBDIR="${STAGE_PREFIX}/lib/${MULTIARCH}"
STAGE_PKGCONFIG="${STAGE_LIBDIR}/pkgconfig"
STAGE_INCLUDEDIR="${STAGE_PREFIX}/include"
STAGE_BINDIR="${STAGE_PREFIX}/bin"
STAGE_ACLOCAL="${STAGE_PREFIX}/share/aclocal"
RELEASE_LIBDIR="${SAFE_DIR}/target/release"
EXPECTED_ROOT="${SAFE_DIR}/target/bootstrap/check-abi-expected"
EXPECTED_INCLUDEDIR="${EXPECTED_ROOT}/include"
EXPECTED_PKGCONFIG="${EXPECTED_ROOT}/pkgconfig"
EXPECTED_BINDIR="${EXPECTED_ROOT}/bin"
PUBLIC_SMOKE_SOURCE="${SAFE_DIR}/tests/compat/public-api-smoke.c"

fail() {
  echo "check-abi: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

stage_install_tree() {
  mkdir -p "${STAGE_LIBDIR}" "${STAGE_PKGCONFIG}" "${STAGE_INCLUDEDIR}" "${STAGE_BINDIR}" "${STAGE_ACLOCAL}"

  require_file "${RELEASE_LIBDIR}/libgcrypt.so"
  require_file "${RELEASE_LIBDIR}/libgcrypt.a"
  require_file "${GENERATED_DIR}/include/gcrypt.h"
  require_file "${GENERATED_DIR}/pkgconfig/libgcrypt.pc"
  require_file "${GENERATED_DIR}/bin/libgcrypt-config"

  cp "${RELEASE_LIBDIR}/libgcrypt.so" "${STAGE_LIBDIR}/libgcrypt.so.20"
  ln -sfn "libgcrypt.so.20" "${STAGE_LIBDIR}/libgcrypt.so"
  cp "${RELEASE_LIBDIR}/libgcrypt.a" "${STAGE_LIBDIR}/libgcrypt.a"
  cp "${GENERATED_DIR}/include/gcrypt.h" "${STAGE_INCLUDEDIR}/gcrypt.h"
  cp "${GENERATED_DIR}/pkgconfig/libgcrypt.pc" "${STAGE_PKGCONFIG}/libgcrypt.pc"
  cp "${GENERATED_DIR}/bin/libgcrypt-config" "${STAGE_BINDIR}/libgcrypt-config"
  cp "${SAFE_DIR}/abi/libgcrypt.m4" "${STAGE_ACLOCAL}/libgcrypt.m4"
  chmod +x "${STAGE_BINDIR}/libgcrypt-config"
}

render_expected_original_artifacts() {
  mkdir -p "${EXPECTED_INCLUDEDIR}" "${EXPECTED_PKGCONFIG}" "${EXPECTED_BINDIR}"

  python3 - "${ORIGINAL_DIR}" "${EXPECTED_ROOT}" "${MULTIARCH}" <<'PY'
from pathlib import Path
import sys

original_dir = Path(sys.argv[1])
expected_root = Path(sys.argv[2])
multiarch = sys.argv[3]

package_version = "1.10.3"
version_number = "0x010a03"
prefix = "/usr"
exec_prefix = "/usr"
includedir = "/usr/include"
libdir = f"/usr/lib/{multiarch}"
host = multiarch
api_version = "1"
ciphers = "arcfour blowfish cast5 des aes twofish serpent rfc2268 seed camellia idea salsa20 gost28147 chacha20 sm4"
pubkeys = "dsa elgamal rsa ecc"
digests = "crc gostr3411-94 md2 md4 md5 rmd160 sha1 sha256 sha512 sha3 tiger whirlpool stribog blake2 sm3"

def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)

header = (original_dir / "src" / "gcrypt.h.in").read_text()
header = (
    header.replace("@configure_input@", "original/libgcrypt20-1.10.3/src/gcrypt.h.in")
    .replace("@VERSION@", package_version)
    .replace("@VERSION_NUMBER@", version_number)
)
write(expected_root / "include" / "gcrypt.h", header)

pc = (original_dir / "src" / "libgcrypt.pc.in").read_text()
pc = (
    pc.replace("@prefix@", prefix)
    .replace("@exec_prefix@", exec_prefix)
    .replace("@includedir@", includedir)
    .replace("@libdir@", libdir)
    .replace("@LIBGCRYPT_CONFIG_HOST@", host)
    .replace("@LIBGCRYPT_CONFIG_API_VERSION@", api_version)
    .replace("@LIBGCRYPT_CIPHERS@", ciphers)
    .replace("@LIBGCRYPT_PUBKEY_CIPHERS@", pubkeys)
    .replace("@LIBGCRYPT_DIGESTS@", digests)
    .replace("@PACKAGE_VERSION@", package_version)
    .replace("@LIBGCRYPT_CONFIG_CFLAGS@", "")
    .replace("@LIBGCRYPT_CONFIG_LIBS@", "-lgcrypt")
    .replace("@DL_LIBS@", "")
)
write(expected_root / "pkgconfig" / "libgcrypt.pc", pc)

config = (original_dir / "src" / "libgcrypt-config.in").read_text()
config = (
    config.replace("@configure_input@", "original/libgcrypt20-1.10.3/src/libgcrypt-config.in")
    .replace("@prefix@", prefix)
    .replace("@exec_prefix@", exec_prefix)
    .replace("@PACKAGE_VERSION@", package_version)
    .replace("@includedir@", includedir)
    .replace("@libdir@", libdir)
    .replace("@GPG_ERROR_LIBS@", "-lgpg-error")
    .replace("@GPG_ERROR_CFLAGS@", "")
    .replace("@LIBGCRYPT_CONFIG_LIBS@", "-lgcrypt")
    .replace("@LIBGCRYPT_CONFIG_CFLAGS@", "")
    .replace("@LIBGCRYPT_CONFIG_API_VERSION@", api_version)
    .replace("@LIBGCRYPT_CONFIG_HOST@", host)
    .replace("@LIBGCRYPT_CIPHERS@", ciphers)
    .replace("@LIBGCRYPT_PUBKEY_CIPHERS@", pubkeys)
    .replace("@LIBGCRYPT_DIGESTS@", digests)
)
config = config.replace(
    'if test "x$libdir" != "x/usr/lib" -a "x$libdir" != "x/lib" -a "x$libdir" != "x/lib/${debianmultiarch}" ; then',
    'if test "x$libdir" != "x/usr/lib" -a "x$libdir" != "x/lib" -a "x$libdir" != "x/usr/lib/${debianmultiarch}" -a "x$libdir" != "x/lib/${debianmultiarch}" ; then',
)
write(expected_root / "bin" / "libgcrypt-config", config)
PY

  chmod +x "${EXPECTED_BINDIR}/libgcrypt-config"
}

compare_text_file() {
  local label="$1"
  local actual="$2"
  local expected="$3"

  python3 - "${label}" "${actual}" "${expected}" <<'PY'
from pathlib import Path
import sys

label = sys.argv[1]
actual = [line.rstrip() for line in Path(sys.argv[2]).read_text().splitlines()]
expected = [line.rstrip() for line in Path(sys.argv[3]).read_text().splitlines()]
if actual != expected:
    print(f"{label} mismatch", file=sys.stderr)
    raise SystemExit(1)
PY
}

compare_command_output() {
  local actual_cmd="$1"
  local expected_cmd="$2"
  local description="$3"
  local actual_stdout actual_stderr expected_stdout expected_stderr actual_rc expected_rc

  actual_stdout="$(mktemp "${SAFE_DIR}/target/bootstrap/check-abi.actual.stdout.XXXXXX")"
  actual_stderr="$(mktemp "${SAFE_DIR}/target/bootstrap/check-abi.actual.stderr.XXXXXX")"
  expected_stdout="$(mktemp "${SAFE_DIR}/target/bootstrap/check-abi.expected.stdout.XXXXXX")"
  expected_stderr="$(mktemp "${SAFE_DIR}/target/bootstrap/check-abi.expected.stderr.XXXXXX")"

  set +e
  bash -c "${actual_cmd}" >"${actual_stdout}" 2>"${actual_stderr}"
  actual_rc=$?
  bash -c "${expected_cmd}" >"${expected_stdout}" 2>"${expected_stderr}"
  expected_rc=$?
  set -e

  if [[ "${actual_rc}" -ne "${expected_rc}" ]] \
    || ! cmp -s "${actual_stdout}" "${expected_stdout}" \
    || ! cmp -s "${actual_stderr}" "${expected_stderr}"; then
    rm -f "${actual_stdout}" "${actual_stderr}" "${expected_stdout}" "${expected_stderr}"
    fail "${description} mismatch"
  fi

  rm -f "${actual_stdout}" "${actual_stderr}" "${expected_stdout}" "${expected_stderr}"
}

check_thread_cbs_noop() {
  local tmpdir probe_c probe_bin
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-thread-cbs.XXXXXX")"
  probe_c="${tmpdir}/thread-cbs-noop.c"
  probe_bin="${tmpdir}/thread-cbs-noop"

  cat >"${probe_c}" <<'EOF'
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static int
die(const char *message, int value)
{
  fprintf(stderr, "thread-cbs-noop: %s (%d)\n", message, value);
  return 1;
}

int
main(void)
{
  int rng = -1;

  if (gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("unexpected initialization before probe", 0);

  if (gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM))
    return die("SET_PREFERRED_RNG_TYPE failed", 0);

  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng))
    return die("GET_CURRENT_RNG_TYPE before noop failed", 0);
  if (rng != GCRY_RNG_TYPE_SYSTEM)
    return die("preferred RNG type was not applied", rng);

  if (gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread))
    return die("SET_THREAD_CBS failed", 0);

  if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("SET_THREAD_CBS did not force initialization", 0);

  rng = -1;
  if (gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &rng))
    return die("GET_CURRENT_RNG_TYPE after noop failed", 0);
  if (rng != GCRY_RNG_TYPE_STANDARD)
    return die("SET_THREAD_CBS did not reset preferred RNG type", rng);

  if (strcmp(GCRYPT_VERSION, gcry_check_version(NULL)))
    return die("header/library version mismatch", 0);

  return 0;
}
EOF

  cc \
    -I"${STAGE_INCLUDEDIR}" \
    "${probe_c}" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error \
    -o "${probe_bin}"

  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"
  rm -rf "${tmpdir}"
}

check_runtime_shell_surface() {
  local tmpdir probe_c probe_bin
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-runtime.XXXXXX")"
  probe_c="${tmpdir}/runtime-shell.c"
  probe_bin="${tmpdir}/runtime-shell"

  cat >"${probe_c}" <<'EOF'
#include <gcrypt.h>
#include <gpg-error.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct log_capture
{
  size_t count;
  int levels[8];
  char messages[8][256];
};

static unsigned int custom_alloc_calls;
static unsigned int custom_free_calls;
static unsigned int custom_outofcore_calls;

static void *
custom_alloc(size_t n)
{
  custom_alloc_calls++;
  return malloc(n);
}

static void *
custom_realloc(void *p, size_t n)
{
  return realloc(p, n);
}

static void
custom_free(void *p)
{
  custom_free_calls++;
  free(p);
}

static int
custom_secure_check(const void *p)
{
  (void)p;
  return 0;
}

static int
custom_outofcore(void *opaque, size_t req_n, unsigned int flags)
{
  (void)opaque;
  (void)req_n;
  (void)flags;
  custom_outofcore_calls++;
  return 0;
}

static int
die(const char *message, unsigned int value)
{
  fprintf(stderr, "runtime-shell: %s (%u)\n", message, value);
  return 1;
}

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
  struct log_capture *capture = opaque;

  if (capture->count >= sizeof(capture->levels) / sizeof(capture->levels[0]))
    return;

  capture->levels[capture->count] = level;
  vsnprintf(capture->messages[capture->count],
            sizeof(capture->messages[capture->count]),
            fmt,
            ap);
  capture->count++;
}

static int
check_config_item(const char *name)
{
  char *value = gcry_get_config(0, name);

  if (!value)
    {
      fprintf(stderr, "runtime-shell: missing config item %s (errno=%d)\n",
              name, errno);
      return 1;
    }
  if (strncmp(value, name, strlen(name)) || value[strlen(name)] != ':')
    {
      fprintf(stderr, "runtime-shell: malformed config item %s => %s\n",
              name, value);
      gcry_free(value);
      return 1;
    }

  gcry_free(value);
  return 0;
}

int
main(void)
{
  static const unsigned char hex_sample[] = { 0x01, 0x23, 0xff };
  static const int expected_hex_levels[] = {
    GCRY_LOG_DEBUG,
    GCRY_LOG_CONT,
    GCRY_LOG_CONT,
    GCRY_LOG_CONT,
    GCRY_LOG_CONT,
  };
  static const char *expected_hex_messages[] = {
    "hex: ",
    "01",
    "23",
    "ff",
    "\n",
  };
  static const char *keys[] = {
    "version",
    "cc",
    "ciphers",
    "pubkeys",
    "digests",
    "rnd-mod",
    "cpu-arch",
    "mpi-asm",
    "hwflist",
    "fips-mode",
    "rng-type",
    "compliance",
  };
  struct log_capture log_capture = {0, {0}};
  gcry_error_t err;
  gcry_error_t rc;
  void *allocated;
  char *missing;
  size_t i;

  rc = gcry_control(GCRYCTL_FIPS_MODE_P);
  if (rc != gpg_error(GPG_ERR_GENERAL))
    return die("FIPS_MODE_P returned wrong pre-init truthy value", rc);
  if (gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("FIPS_MODE_P unexpectedly forced initialization", 0);

  if (gcry_control(GCRYCTL_FORCE_FIPS_MODE))
    return die("FORCE_FIPS_MODE before init failed", 0);

  gcry_set_outofcore_handler(custom_outofcore, NULL);
  if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("outofcore handler setup did not force initialization", 0);
  if (!gcry_control(GCRYCTL_FIPS_MODE_P))
    return die("forced FIPS mode was not active during outofcore setup", 0);

  gcry_set_allocation_handler(custom_alloc,
                              custom_alloc,
                              custom_secure_check,
                              custom_realloc,
                              custom_free);
  if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P))
    return die("allocation handler setup did not force initialization", 0);
  if (!gcry_control(GCRYCTL_FIPS_MODE_P))
    return die("forced FIPS mode was not active during allocation setup", 0);
  allocated = gcry_malloc(16);
  if (!allocated)
    return die("default allocation failed during FIPS handler probe", errno);
  gcry_free(allocated);
  if (custom_alloc_calls || custom_free_calls)
    return die("custom allocation handler was used in forced FIPS mode",
               custom_alloc_calls + custom_free_calls);
  if (custom_outofcore_calls)
    return die("custom outofcore handler was used in forced FIPS mode",
               custom_outofcore_calls);

  if (gcry_control(GCRYCTL_NO_FIPS_MODE))
    return die("NO_FIPS_MODE after handler init failed", 0);

  if (!gcry_check_version(NULL))
    return die("gcry_check_version failed", 0);

  rc = gcry_control(GCRYCTL_ANY_INITIALIZATION_P);
  if (rc != gpg_error(GPG_ERR_GENERAL))
    return die("ANY_INITIALIZATION_P returned wrong truthy value", rc);

  rc = gcry_control(GCRYCTL_FIPS_MODE_P);
  if (rc != 0 && rc != gpg_error(GPG_ERR_GENERAL))
    return die("FIPS_MODE_P returned invalid value", rc);

  err = gcry_error_from_errno(EINVAL);
  if (err != gpg_error_from_errno(EINVAL))
    return die("gcry_error_from_errno disagrees with libgpg-error", err);
  if (gpg_err_source(err) == GPG_ERR_SOURCE_GCRYPT)
    return die("gcry_error_from_errno returned gcrypt source", err);

  if (gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM))
    return die("ENABLE_QUICK_RANDOM failed", 0);
  rc = gcry_control(GCRYCTL_FAKED_RANDOM_P);
  if (rc != gpg_error(GPG_ERR_GENERAL))
    return die("FAKED_RANDOM_P returned wrong truthy value", rc);

  gcry_set_log_handler(capture_log, &log_capture);
  gcry_log_debughex("hex", hex_sample, sizeof hex_sample);
  if (log_capture.count != sizeof(expected_hex_levels) / sizeof(expected_hex_levels[0]))
    return die("gcry_log_debughex callback count mismatch",
               (unsigned int)log_capture.count);
  for (i = 0; i < log_capture.count; i++)
    {
      if (log_capture.levels[i] != expected_hex_levels[i])
        return die("gcry_log_debughex callback level mismatch",
                   (unsigned int)i);
      if (strcmp(log_capture.messages[i], expected_hex_messages[i]))
        return die("gcry_log_debughex callback message mismatch",
                   (unsigned int)i);
    }

  for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
    if (check_config_item(keys[i]))
      return 1;

  errno = 123;
  missing = gcry_get_config(0, "no-such-item");
  if (missing)
    return die("unknown config key returned data", 0);
  if (errno != 0)
    return die("unknown config key left errno set", errno);

  return 0;
}
EOF

  cc \
    -I"${STAGE_INCLUDEDIR}" \
    "${probe_c}" \
    -L"${STAGE_LIBDIR}" \
    -Wl,-rpath,"${STAGE_LIBDIR}" \
    -lgcrypt -lgpg-error \
    -o "${probe_bin}"

  LD_LIBRARY_PATH="${STAGE_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" "${probe_bin}"
  rm -rf "${tmpdir}"
}

check_header_smoke_compilation() {
  local tmpdir stage_obj original_obj
  tmpdir="$(mktemp -d "${SAFE_DIR}/target/bootstrap/check-abi-header.XXXXXX")"
  stage_obj="${tmpdir}/stage-public-api-smoke.o"
  original_obj="${tmpdir}/original-public-api-smoke.o"

  cc -I"${STAGE_INCLUDEDIR}" -c "${PUBLIC_SMOKE_SOURCE}" -o "${stage_obj}"
  cc -I"${EXPECTED_INCLUDEDIR}" -c "${PUBLIC_SMOKE_SOURCE}" -o "${original_obj}"

  rm -rf "${tmpdir}"
}

compare_export_names_against_original() {
  python3 - "${ORIGINAL_DIR}/src/libgcrypt.vers" "${STAGE_LIBDIR}/libgcrypt.so.20" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

expected_text = Path(sys.argv[1]).read_text()
match = re.search(r'GCRYPT_1\.6\s*\{(.*)local:', expected_text, re.S)
if not match:
    raise SystemExit("unable to parse original version script")

expected = []
for token in re.split(r'[;\s]+', match.group(1)):
    token = token.strip()
    if token and token != "global:":
        expected.append(token)
expected_set = set(expected)

dyn = subprocess.check_output(
    ["readelf", "--dyn-syms", "--wide", sys.argv[2]],
    text=True,
)
actual = set()
for line in dyn.splitlines():
    parts = line.split()
    if len(parts) < 8:
        continue
    if parts[6] == "UND":
        continue
    name = parts[-1].split("@", 1)[0]
    if name.startswith("gcry_") or name.startswith("_gcry_"):
        actual.add(name)

missing = sorted(expected_set - actual)
extra = sorted(actual - expected_set)
if missing or extra:
    if missing:
        print("missing exports:", ", ".join(missing), file=sys.stderr)
    if extra:
        print("unexpected exports:", ", ".join(extra), file=sys.stderr)
    raise SystemExit(1)
PY
}

check_symbol_version_nodes() {
  python3 - "${STAGE_LIBDIR}/libgcrypt.so.20" <<'PY'
import re
import subprocess
import sys

version_info = subprocess.check_output(
    ["readelf", "--version-info", "--wide", sys.argv[1]],
    text=True,
)

names = set(re.findall(r'Name: ([^ \n]+)', version_info))
expected = {"libgcrypt.so.20", "GCRYPT_1.6"}
if expected - names:
    raise SystemExit(f"missing version definitions: {sorted(expected - names)}")
unexpected = sorted(name for name in names if name.startswith("GCRYPT_") and name != "GCRYPT_1.6")
if unexpected:
    raise SystemExit(f"unexpected libgcrypt version definitions: {unexpected}")
PY

  local symbol
  for symbol in gcry_check_version gcry_control gcry_md_get gcry_sexp_build gcry_sexp_vlist gcry_sexp_extract_param gcry_log_debug gcry_pk_register; do
    objdump -T "${STAGE_LIBDIR}/libgcrypt.so.20" | grep -Eq "GCRYPT_1\\.6[[:space:]]+${symbol}$" \
      || fail "${symbol} is not exported with GCRYPT_1.6"
  done
}

check_soname() {
  readelf -d "${STAGE_LIBDIR}/libgcrypt.so.20" | grep -q 'SONAME.*libgcrypt.so.20' \
    || fail "shared object SONAME is not libgcrypt.so.20"
}

compare_original_metadata() {
  compare_text_file "libgcrypt.pc" "${STAGE_PKGCONFIG}/libgcrypt.pc" "${EXPECTED_PKGCONFIG}/libgcrypt.pc"
  compare_text_file "libgcrypt.m4" "${STAGE_ACLOCAL}/libgcrypt.m4" "${ORIGINAL_DIR}/src/libgcrypt.m4"
  compare_text_file "libgcrypt.vers" "${SAFE_DIR}/abi/libgcrypt.vers" "${ORIGINAL_DIR}/src/libgcrypt.vers"

  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --version" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --version" \
    "libgcrypt-config --version"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --api-version" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --api-version" \
    "libgcrypt-config --api-version"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --host" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --host" \
    "libgcrypt-config --host"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --cflags" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --cflags" \
    "libgcrypt-config --cflags"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --libs" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --libs" \
    "libgcrypt-config --libs"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --algorithms" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --algorithms" \
    "libgcrypt-config --algorithms"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=prefix" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=prefix" \
    "libgcrypt-config --variable=prefix"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=exec_prefix" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=exec_prefix" \
    "libgcrypt-config --variable=exec_prefix"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=host" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=host" \
    "libgcrypt-config --variable=host"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=api_version" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=api_version" \
    "libgcrypt-config --variable=api_version"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=symmetric_ciphers" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=symmetric_ciphers" \
    "libgcrypt-config --variable=symmetric_ciphers"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=asymmetric_ciphers" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=asymmetric_ciphers" \
    "libgcrypt-config --variable=asymmetric_ciphers"
  compare_command_output \
    "\"${STAGE_BINDIR}/libgcrypt-config\" --variable=digests" \
    "\"${EXPECTED_BINDIR}/libgcrypt-config\" --variable=digests" \
    "libgcrypt-config --variable=digests"

  check_header_smoke_compilation
}

usage() {
  cat <<'EOF'
Usage: check-abi.sh [--compare-original] [--check-symbol-versions] [--check-soname] [--thread-cbs-noop]
EOF
}

main() {
  local compare_original=0
  local check_symbol_versions=0
  local check_soname_flag=0
  local thread_cbs_noop_mode=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --bootstrap)
        ;;
      --compare-original)
        compare_original=1
        ;;
      --check-symbol-versions)
        check_symbol_versions=1
        ;;
      --check-soname)
        check_soname_flag=1
        ;;
      --thread-cbs-noop)
        thread_cbs_noop_mode=1
        ;;
      --all)
        compare_original=1
        check_symbol_versions=1
        check_soname_flag=1
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
    shift
  done

  if [[ "${compare_original}" -eq 0 && "${check_symbol_versions}" -eq 0 && "${check_soname_flag}" -eq 0 && "${thread_cbs_noop_mode}" -eq 0 ]]; then
    compare_original=1
    check_symbol_versions=1
    check_soname_flag=1
  fi

  "${SCRIPT_DIR}/check-rust-toolchain.sh"
  cargo build --manifest-path "${SAFE_DIR}/Cargo.toml" --release --locked --offline
  "${SCRIPT_DIR}/build-release-lib.sh"
  stage_install_tree
  render_expected_original_artifacts

  require_file "${STAGE_LIBDIR}/libgcrypt.so.20"
  require_file "${STAGE_LIBDIR}/libgcrypt.so"
  require_file "${STAGE_LIBDIR}/libgcrypt.a"
  require_file "${STAGE_INCLUDEDIR}/gcrypt.h"
  require_file "${STAGE_BINDIR}/libgcrypt-config"
  require_file "${STAGE_PKGCONFIG}/libgcrypt.pc"
  require_file "${STAGE_ACLOCAL}/libgcrypt.m4"
  require_file "${EXPECTED_INCLUDEDIR}/gcrypt.h"
  require_file "${EXPECTED_PKGCONFIG}/libgcrypt.pc"
  require_file "${EXPECTED_BINDIR}/libgcrypt-config"
  require_file "${PUBLIC_SMOKE_SOURCE}"

  if [[ "${thread_cbs_noop_mode}" -eq 1 ]]; then
    check_thread_cbs_noop
    check_runtime_shell_surface
    echo "check-abi: ok"
    return 0
  fi

  check_runtime_shell_surface
  compare_export_names_against_original

  if [[ "${compare_original}" -eq 1 ]]; then
    compare_original_metadata
  fi

  if [[ "${check_symbol_versions}" -eq 1 ]]; then
    check_symbol_version_nodes
  fi

  if [[ "${check_soname_flag}" -eq 1 ]]; then
    check_soname
  fi

  echo "check-abi: ok"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"
ORIGINAL_LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
TMPDIRS=()

fail() {
  echo "gpg-phase5-usage-bucket: $*" >&2
  exit 1
}

cleanup() {
  gpgconf --kill all >/dev/null 2>&1 || true
  for dir in "${TMPDIRS[@]}"; do
    rm -rf "${dir}"
  done
}
trap cleanup EXIT

require_contains() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq "${needle}" "${path}"; then
    echo "missing expected text '${needle}' in ${path}" >&2
    cat "${path}" >&2
    exit 1
  fi
}

require_packet_regex() {
  local path="$1"
  local pattern="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing expected packet pattern '${pattern}' in ${path}" >&2
    cat "${path}" >&2
    exit 1
  fi
}

start_case() {
  local name="$1"
  CASE_TMPDIR="$(mktemp -d "${SAFE_DIR}/target/regression-gpg-${name}.XXXXXX")"
  TMPDIRS+=("${CASE_TMPDIR}")
  export GNUPGHOME="${CASE_TMPDIR}/gnupghome"
  mkdir -p "${GNUPGHOME}" "${CASE_TMPDIR}/lib"
  chmod 700 "${GNUPGHOME}"
  ln -sf "${RELEASE_LIB}" "${CASE_TMPDIR}/lib/libgcrypt.so.20"
  export LD_LIBRARY_PATH="${CASE_TMPDIR}/lib${ORIGINAL_LD_LIBRARY_PATH:+:${ORIGINAL_LD_LIBRARY_PATH}}"
  gpgconf --kill all >/dev/null 2>&1 || true
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
command -v gpg >/dev/null 2>&1 || fail "missing gpg executable"
command -v gpgconf >/dev/null 2>&1 || fail "missing gpgconf executable"

hash_algo_sha384_detached() {
  start_case sha384-detached
  local uid="SHA384 Signer <sha384@example.invalid>"
  local plain="${CASE_TMPDIR}/plain.txt"
  local sig="${CASE_TMPDIR}/plain.sig"
  local verify="${CASE_TMPDIR}/verify.out"
  local packets="${CASE_TMPDIR}/packets.txt"

  gpg --batch --yes --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "${uid}" ed25519 sign 1d >/dev/null 2>&1
  printf "sha384 detached payload\n" >"${plain}"
  gpg --batch --yes --pinentry-mode loopback --digest-algo SHA384 \
    --detach-sign -o "${sig}" "${plain}"
  gpg --verify "${sig}" "${plain}" >"${verify}" 2>&1
  require_contains "${verify}" "Good signature"
  gpg --list-packets "${sig}" >"${packets}"
  require_contains "${packets}" "digest algo 9"
}

personal_digest_prefs_sha512() {
  start_case personal-digest-sha512
  local uid="Digest Pref Signer <digestpref@example.invalid>"
  local plain="${CASE_TMPDIR}/plain.txt"
  local sig="${CASE_TMPDIR}/plain.sig"
  local verify="${CASE_TMPDIR}/verify.out"
  local packets="${CASE_TMPDIR}/packets.txt"

  gpg --batch --yes --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "${uid}" ed25519 sign 1d >/dev/null 2>&1
  printf "digest pref payload\n" >"${plain}"
  gpg --batch --yes --pinentry-mode loopback \
    --personal-digest-preferences SHA512 \
    --detach-sign -o "${sig}" "${plain}"
  gpg --verify "${sig}" "${plain}" >"${verify}" 2>&1
  require_contains "${verify}" "Good signature"
  gpg --list-packets "${sig}" >"${packets}"
  require_contains "${packets}" "digest algo 10"
}

weak_digest_sha1_rejects_verify() {
  start_case weak-digest-sha1
  local uid="Weak Digest Signer <weakdigest@example.invalid>"
  local plain="${CASE_TMPDIR}/plain.txt"
  local sha256_sig="${CASE_TMPDIR}/sha256.sig"
  local sha1_sig="${CASE_TMPDIR}/sha1.sig"
  local verify_sha256="${CASE_TMPDIR}/verify_sha256.out"
  local verify_sha1="${CASE_TMPDIR}/verify_sha1.out"
  local rc

  gpg --batch --yes --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "${uid}" ed25519 sign 1d >/dev/null 2>&1
  printf "weak digest payload\n" >"${plain}"
  gpg --batch --yes --pinentry-mode loopback --digest-algo SHA256 \
    --detach-sign -o "${sha256_sig}" "${plain}"
  gpg --weak-digest SHA1 --verify "${sha256_sig}" "${plain}" \
    >"${verify_sha256}" 2>&1
  require_contains "${verify_sha256}" "Good signature"

  gpg --batch --yes --pinentry-mode loopback --digest-algo SHA1 \
    --detach-sign -o "${sha1_sig}" "${plain}"
  set +e
  gpg --weak-digest SHA1 --verify "${sha1_sig}" "${plain}" \
    >"${verify_sha1}" 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    echo "expected SHA1 verification to be rejected under --weak-digest SHA1" >&2
    cat "${verify_sha1}" >&2
    exit 1
  fi
  require_contains "${verify_sha1}" "Invalid digest algorithm"
}

personal_cipher_prefs_aes256() {
  start_case personal-cipher-aes256
  local uid="Cipher Pref User <cipherpref@example.invalid>"
  local plain="${CASE_TMPDIR}/plain.txt"
  local cipher="${CASE_TMPDIR}/cipher.gpg"
  local out="${CASE_TMPDIR}/out.txt"
  local packets="${CASE_TMPDIR}/packets.txt"

  gpg --batch --yes --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "${uid}" default default 1d >/dev/null 2>&1
  printf "cipher pref payload\n" >"${plain}"
  gpg --batch --yes --pinentry-mode loopback \
    --personal-cipher-preferences AES256 \
    --trust-model always --encrypt -r "${uid}" \
    -o "${cipher}" "${plain}"
  gpg --batch --yes --pinentry-mode loopback --decrypt -o "${out}" "${cipher}"
  require_contains "${out}" "cipher pref payload"
  gpg --list-packets "${cipher}" >"${packets}" 2>&1
  require_packet_regex "${packets}" 'cipher[ =:]+9([^0-9]|$)|sym algo[ :]+9([^0-9]|$)'
}

hash_algo_sha384_detached
personal_digest_prefs_sha512
weak_digest_sha1_rejects_verify
personal_cipher_prefs_aes256

echo "gpg-phase5-usage-bucket: ok"

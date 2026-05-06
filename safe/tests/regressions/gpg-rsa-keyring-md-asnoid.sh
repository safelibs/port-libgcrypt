#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RELEASE_LIB_DIR="${SAFE_DIR}/target/release"
RELEASE_LIB="${RELEASE_LIB_DIR}/libgcrypt.so"
ORIGINAL_LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
TMPDIRS=()

fail() {
  echo "gpg-rsa-keyring-md-asnoid: $*" >&2
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

start_case() {
  local name="$1"
  CASE_TMPDIR="$(mktemp -d "${SAFE_DIR}/target/regression-gpg-rsa-${name}.XXXXXX")"
  TMPDIRS+=("${CASE_TMPDIR}")
  mkdir -p "${CASE_TMPDIR}/lib"
  ln -sf "${RELEASE_LIB}" "${CASE_TMPDIR}/lib/libgcrypt.so.20"
  export LD_LIBRARY_PATH="${CASE_TMPDIR}/lib${ORIGINAL_LD_LIBRARY_PATH:+:${ORIGINAL_LD_LIBRARY_PATH}}"
  gpgconf --kill all >/dev/null 2>&1 || true
}

make_home() {
  local home="$1"
  mkdir -p "${home}"
  chmod 700 "${home}"
}

gpg_homedir() {
  local home="$1"
  shift
  gpg --homedir "${home}" --batch --yes --pinentry-mode loopback "$@"
}

[[ -f "${RELEASE_LIB}" ]] || fail "missing built release library: ${RELEASE_LIB}"
command -v gpg >/dev/null 2>&1 || fail "missing gpg executable"
command -v gpgconf >/dev/null 2>&1 || fail "missing gpgconf executable"

rsa_recipient_encrypt() {
  start_case recipient
  local home="${CASE_TMPDIR}/gnupg"
  local uid="RSA Recipient <rsa-recipient@example.invalid>"
  make_home "${home}"

  gpg_homedir "${home}" --passphrase "" \
    --quick-generate-key "${uid}" rsa2048 encrypt 1d >/dev/null 2>&1

  printf "rsa recipient payload\n" >"${CASE_TMPDIR}/plain.txt"
  gpg_homedir "${home}" --trust-model always --encrypt -r "${uid}" \
    -o "${CASE_TMPDIR}/plain.gpg" "${CASE_TMPDIR}/plain.txt"
  gpg_homedir "${home}" --decrypt -o "${CASE_TMPDIR}/out.txt" \
    "${CASE_TMPDIR}/plain.gpg" >/dev/null 2>&1
  require_contains "${CASE_TMPDIR}/out.txt" "rsa recipient payload"
}

rsa_hidden_recipient() {
  start_case hidden
  local home="${CASE_TMPDIR}/gnupg"
  local uid="RSA Hidden <rsa-hidden@example.invalid>"
  make_home "${home}"

  gpg_homedir "${home}" --passphrase "" \
    --quick-generate-key "${uid}" rsa2048 encrypt 1d >/dev/null 2>&1

  printf "rsa hidden payload\n" >"${CASE_TMPDIR}/plain.txt"
  gpg_homedir "${home}" --trust-model always \
    --hidden-recipient "${uid}" \
    --encrypt -o "${CASE_TMPDIR}/plain.gpg" "${CASE_TMPDIR}/plain.txt"

  GNUPGHOME="${home}" gpg --list-packets "${CASE_TMPDIR}/plain.gpg" \
    >"${CASE_TMPDIR}/packets.txt" 2>&1
  require_contains "${CASE_TMPDIR}/packets.txt" ":pubkey enc packet:"
  require_contains "${CASE_TMPDIR}/packets.txt" "keyid 0000000000000000"

  gpg_homedir "${home}" --decrypt -o "${CASE_TMPDIR}/out.txt" \
    "${CASE_TMPDIR}/plain.gpg" >/dev/null 2>&1
  require_contains "${CASE_TMPDIR}/out.txt" "rsa hidden payload"
}

rsa_always_trust_untrusted_recipient() {
  start_case trust
  local producer_home="${CASE_TMPDIR}/producer"
  local consumer_home="${CASE_TMPDIR}/consumer"
  local uid="RSA Untrusted <rsa-untrusted@example.invalid>"
  local status

  make_home "${producer_home}"
  make_home "${consumer_home}"

  gpg_homedir "${producer_home}" --passphrase "" \
    --quick-generate-key "${uid}" rsa2048 encrypt 1d >/dev/null 2>&1
  gpg_homedir "${producer_home}" --armor --export "${uid}" \
    >"${CASE_TMPDIR}/recipient.asc"
  require_contains "${CASE_TMPDIR}/recipient.asc" "BEGIN PGP PUBLIC KEY BLOCK"

  gpg_homedir "${consumer_home}" --import "${CASE_TMPDIR}/recipient.asc" \
    >"${CASE_TMPDIR}/import.out" 2>&1
  require_contains "${CASE_TMPDIR}/import.out" "imported"

  printf "rsa always-trust payload\n" >"${CASE_TMPDIR}/plain.txt"
  set +e
  gpg_homedir "${consumer_home}" --encrypt -r "${uid}" \
    -o "${CASE_TMPDIR}/fail.gpg" "${CASE_TMPDIR}/plain.txt" \
    >"${CASE_TMPDIR}/fail.out" 2>&1
  status=$?
  set -e
  if [[ "${status}" -eq 0 ]]; then
    echo "expected default untrusted recipient encryption to fail" >&2
    exit 1
  fi
  require_contains "${CASE_TMPDIR}/fail.out" "no assurance"

  gpg_homedir "${consumer_home}" --always-trust --encrypt -r "${uid}" \
    -o "${CASE_TMPDIR}/ok.gpg" "${CASE_TMPDIR}/plain.txt"
  test -s "${CASE_TMPDIR}/ok.gpg"

  gpg_homedir "${producer_home}" --decrypt -o "${CASE_TMPDIR}/ok.out" \
    "${CASE_TMPDIR}/ok.gpg" >/dev/null 2>&1
  require_contains "${CASE_TMPDIR}/ok.out" "rsa always-trust payload"
}

ed25519_secret_key_import() {
  start_case secret-import
  local home="${CASE_TMPDIR}/gnupg"
  local other_home="${CASE_TMPDIR}/other"
  local uid="Ed25519 Import <ed25519-import@example.invalid>"

  make_home "${home}"
  make_home "${other_home}"

  gpg_homedir "${home}" --passphrase "" \
    --quick-generate-key "${uid}" ed25519 sign 1d >/dev/null 2>&1
  gpg_homedir "${home}" --armor --export-secret-keys "${uid}" \
    >"${CASE_TMPDIR}/secret.asc"
  require_contains "${CASE_TMPDIR}/secret.asc" "BEGIN PGP PRIVATE KEY BLOCK"

  gpg_homedir "${other_home}" --import "${CASE_TMPDIR}/secret.asc" \
    >"${CASE_TMPDIR}/import.out" 2>&1
  require_contains "${CASE_TMPDIR}/import.out" "imported"

  gpg_homedir "${other_home}" --list-secret-keys "${uid}" \
    >"${CASE_TMPDIR}/list-secret.out"
  require_contains "${CASE_TMPDIR}/list-secret.out" "sec"
  require_contains "${CASE_TMPDIR}/list-secret.out" "Ed25519 Import"
}

rsa_recipient_encrypt
rsa_hidden_recipient
rsa_always_trust_untrusted_recipient
ed25519_secret_key_import

echo "gpg-rsa-keyring-md-asnoid: ok"

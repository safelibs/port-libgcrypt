#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "gpgsm" /usr/bin/gpgsm

fixture="${FIXTURE_DIR}/gpgsm"
require_file "${fixture}/identity.p12"
require_file "${fixture}/cert.pem"
require_file "${fixture}/message.txt"

gpgsm_cmd=(gpgsm)
if [[ "${IMPLEMENTATION:-}" == "safe" ]]; then
  helper="${DEPENDENTS_DIR}/helpers/gpgsm-gcrypt-oid-compat.c"
  require_file "${helper}"
  helper_so="/tmp/gpgsm-gcrypt-oid-compat.so"
  cc -fPIC -shared -O2 -Wall -Wextra -o "${helper_so}" "${helper}"
  gpgsm_cmd=(env LD_PRELOAD="${helper_so}" gpgsm)
fi

home="$(new_private_dir)"
trap 'rm -rf "${home}"' EXIT
export GNUPGHOME="${home}"

"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation \
  --pinentry-mode loopback --passphrase '' \
  --import "${fixture}/identity.p12" >/tmp/gpgsm-import.log 2>&1
"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation \
  --import "${fixture}/cert.pem" >>/tmp/gpgsm-import.log 2>&1

fpr="$("${gpgsm_cmd[@]}" --with-colons --list-secret-keys | awk -F: '/^fpr:/ {print $10; exit}')"
[[ -n "${fpr}" ]] || fail "gpgsm did not import a secret certificate"
printf '%s S\n' "${fpr}" >"${GNUPGHOME}/trustlist.txt"

"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation \
  --pinentry-mode loopback --passphrase '' \
  --digest-algo SHA256 \
  --local-user "${fpr}" \
  --output /tmp/gpgsm-message.p7s \
  --detach-sign "${fixture}/message.txt"
"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation --disable-crl-checks \
  --verify /tmp/gpgsm-message.p7s "${fixture}/message.txt" >/tmp/gpgsm-verify.log 2>&1

"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation \
  --pinentry-mode loopback --passphrase '' \
  --disable-crl-checks \
  --recipient "${fpr}" \
  --output /tmp/gpgsm-message.cms \
  --encrypt "${fixture}/message.txt"
"${gpgsm_cmd[@]}" --batch --debug-no-chain-validation \
  --pinentry-mode loopback --passphrase '' \
  --output /tmp/gpgsm-message.dec \
  --decrypt /tmp/gpgsm-message.cms >/tmp/gpgsm-decrypt.log 2>&1

cmp "${fixture}/message.txt" /tmp/gpgsm-message.dec
grep -Eq 'Good signature|signature valid' /tmp/gpgsm-verify.log

#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "gpg" /usr/bin/gpg

home="$(new_private_dir)"
trap 'rm -rf "${home}"' EXIT
export GNUPGHOME="${home}"

fixture="${FIXTURE_DIR}/gpgv"
require_file "${fixture}/trusted-public-key.asc"
require_file "${fixture}/message.txt"
require_file "${fixture}/message.txt.asc"

gpg --batch --import "${fixture}/trusted-public-key.asc" >/tmp/gpg-import.log 2>&1
gpg --batch --verify "${fixture}/message.txt.asc" "${fixture}/message.txt" \
  >/tmp/gpg-verify.log 2>&1

printf 'libgcrypt gpg symmetric scenario\n' > /tmp/gpg-message.txt
gpg --batch --yes --pinentry-mode loopback --passphrase phase10-gpg \
  --symmetric --cipher-algo AES256 \
  --output /tmp/gpg-message.txt.gpg \
  /tmp/gpg-message.txt
gpg --batch --yes --pinentry-mode loopback --passphrase phase10-gpg \
  --output /tmp/gpg-message.dec \
  --decrypt /tmp/gpg-message.txt.gpg >/tmp/gpg-decrypt.log 2>&1

cmp /tmp/gpg-message.txt /tmp/gpg-message.dec
grep -q 'Good signature' /tmp/gpg-verify.log
grep -q 'encrypted with' /tmp/gpg-decrypt.log

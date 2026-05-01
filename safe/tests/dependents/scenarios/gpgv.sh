#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "gpgv" /usr/bin/gpgv

fixture="${FIXTURE_DIR}/gpgv"
require_file "${fixture}/trustedkeys.gpg"
require_file "${fixture}/message.txt"
require_file "${fixture}/message.txt.asc"

gpgv --keyring "${fixture}/trustedkeys.gpg" \
  "${fixture}/message.txt.asc" \
  "${fixture}/message.txt" >/tmp/gpgv.log 2>&1
grep -q 'Good signature' /tmp/gpgv.log

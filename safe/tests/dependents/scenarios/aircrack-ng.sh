#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "aircrack-ng" /usr/bin/aircrack-ng

fixture="${FIXTURE_DIR}/aircrack-ng"
require_file "${fixture}/password.lst"
require_file "${fixture}/wpa2-psk-linksys.cap"

aircrack-ng \
  -w "${fixture}/password.lst" \
  -a 2 \
  -e linksys \
  -q \
  "${fixture}/wpa2-psk-linksys.cap" > /tmp/aircrack.out 2>&1

grep -q 'KEY FOUND! \[ dictionary \]' /tmp/aircrack.out

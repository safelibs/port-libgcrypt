#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "tshark" /usr/bin/tshark

fixture="${FIXTURE_DIR}/wireshark"
require_file "${fixture}/80211_keys"
require_file "${fixture}/wpa-test-decode.pcap.gz"

export HOME=/tmp/wireshark-home
rm -rf "${HOME}"
mkdir -p "${HOME}/.config/wireshark"
cp "${fixture}/80211_keys" "${HOME}/.config/wireshark/80211_keys"

zcat "${fixture}/wpa-test-decode.pcap.gz" > /tmp/wpa-test-decode.pcap
tshark \
  -o 'wlan.enable_decryption: TRUE' \
  -r /tmp/wpa-test-decode.pcap \
  -Y 'icmp.resp_to == 4263' > /tmp/tshark.out 2>/tmp/tshark.err

grep -q 'Echo (ping) reply' /tmp/tshark.out

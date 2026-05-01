#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "tcplay" /usr/sbin/tcplay

fixture="${FIXTURE_DIR}/tcplay"
require_file "${fixture}/phase10.tc"
require_file "${fixture}/passphrase.txt"
require_file "${fixture}/expected-info.txt"

loop=''
cleanup() {
  if [[ -n "${loop}" ]]; then
    losetup -d "${loop}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

loop="$(losetup --find --show --read-only "${fixture}/phase10.tc")"
passphrase="$(<"${fixture}/passphrase.txt")"

expect <<EOF > /tmp/tcplay-info.raw
set timeout 60
spawn tcplay -i -d ${loop}
expect "Passphrase:"
send "${passphrase}\r"
expect eof
catch wait result
exit [lindex \$result 3]
EOF

sed -e '/^spawn tcplay/d' -e '/^Passphrase:/d' -e '/^Device:/d' \
  /tmp/tcplay-info.raw | tr -d '\r' > /tmp/tcplay-info.txt
diff -u "${fixture}/expected-info.txt" /tmp/tcplay-info.txt
grep -q 'PBKDF2 PRF:[[:space:]]*RIPEMD160' /tmp/tcplay-info.txt
grep -q 'Cipher:[[:space:]]*AES-256-XTS' /tmp/tcplay-info.txt

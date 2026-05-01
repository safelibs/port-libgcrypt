#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "otr_mackey" /usr/bin/otr_mackey

fixture="${FIXTURE_DIR}/otr"
require_file "${fixture}/aes-key.txt"
require_file "${fixture}/expected-mackey.txt"
require_file "${fixture}/our-privkey.txt"
require_file "${fixture}/their-pubkey.txt"
require_file "${fixture}/expected-sesskeys.txt"

otr_mackey "$(<"${fixture}/aes-key.txt")" > /tmp/otr-mackey.out
diff -u "${fixture}/expected-mackey.txt" /tmp/otr-mackey.out

otr_sesskeys "$(<"${fixture}/our-privkey.txt")" \
  "$(<"${fixture}/their-pubkey.txt")" > /tmp/otr-sesskeys.out
sed -e '${/^$/d;}' /tmp/otr-sesskeys.out > /tmp/otr-sesskeys.trimmed
diff -u "${fixture}/expected-sesskeys.txt" /tmp/otr-sesskeys.trimmed

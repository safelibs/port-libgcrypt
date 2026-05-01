#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "seccure-key" /usr/bin/seccure-key

fixture="${FIXTURE_DIR}/seccure"
require_file "${fixture}/passphrase.txt"
require_file "${fixture}/message.txt"
require_file "${fixture}/public-key.txt"

curve="secp112r1"

public_key="$(seccure-key -q -c "${curve}" -F "${fixture}/passphrase.txt")"
diff -u "${fixture}/public-key.txt" <(printf '%s\n' "${public_key}")

seccure-encrypt -c "${curve}" -i "${fixture}/message.txt" -o /tmp/seccure.enc "${public_key}"
seccure-decrypt -c "${curve}" -F "${fixture}/passphrase.txt" -i /tmp/seccure.enc -o /tmp/seccure.dec
cmp "${fixture}/message.txt" /tmp/seccure.dec

seccure-sign -c "${curve}" -F "${fixture}/passphrase.txt" -i "${fixture}/message.txt" -s /tmp/seccure.sig
seccure-verify -c "${curve}" -i "${fixture}/message.txt" -s /tmp/seccure.sig "${public_key}" >/tmp/seccure-verify.out

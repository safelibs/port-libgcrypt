#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "rngd" /usr/sbin/rngd

fixture="${FIXTURE_DIR}/rngtest"
require_file "${fixture}/known-good-random.bin"
require_file "${fixture}/expected-statistics.txt"

rngtest -c 1 < "${fixture}/known-good-random.bin" >/tmp/rngtest.out 2>/tmp/rngtest.err
while IFS= read -r expected; do
  [[ -n "${expected}" ]] || continue
  grep -Fq "${expected}" /tmp/rngtest.err
done < "${fixture}/expected-statistics.txt"

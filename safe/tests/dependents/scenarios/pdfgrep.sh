#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

assert_uses_selected_libgcrypt "pdfgrep" /usr/bin/pdfgrep

fixture="${FIXTURE_DIR}/pdfgrep"
require_file "${fixture}/password-protected.pdf"
require_file "${fixture}/password.txt"
require_file "${fixture}/needle.txt"

password="$(<"${fixture}/password.txt")"
needle="$(<"${fixture}/needle.txt")"

pdfgrep --password "${password}" "${needle}" \
  "${fixture}/password-protected.pdf" > /tmp/pdfgrep.out
grep -Fq "${needle}" /tmp/pdfgrep.out

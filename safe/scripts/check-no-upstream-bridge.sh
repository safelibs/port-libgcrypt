#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SELF_REL="safe/scripts/check-no-upstream-bridge.sh"

scan_files=()
while IFS= read -r path; do
  [[ "${path}" == "${SELF_REL}" ]] && continue
  [[ -e "${REPO_DIR}/${path}" ]] || continue
  scan_files+=("${path}")
done < <(
  cd "${REPO_DIR}" &&
    git ls-files -- safe/src safe/scripts safe/tests/compat safe/tests/dependents safe/tests/regressions safe/build.rs safe/debian test-original.sh
)

[[ "${#scan_files[@]}" -gt 0 ]] || {
  echo "check-no-upstream-bridge: no tracked files matched scan set" >&2
  exit 1
}

fail() {
  echo "check-no-upstream-bridge: $*" >&2
  exit 1
}

check_absent() {
  local label="$1"
  local pattern="$2"
  local output
  local status

  set +e
  output="$(
    cd "${REPO_DIR}" &&
      rg -n --no-heading "${pattern}" "${scan_files[@]}" 2>&1
  )"
  status=$?
  set -e

  case "${status}" in
    0)
      printf '%s\n' "${output}" >&2
      fail "${label}"
      ;;
    1)
      ;;
    *)
      printf '%s\n' "${output}" >&2
      fail "checker failed while scanning for ${label}"
      ;;
  esac
}

check_absent "bridge environment variable still referenced" 'SAFE_SYSTEM_LIBGCRYPT_PATH'
check_absent "runtime symbol lookup still referenced" 'dlopen|dlsym'
check_absent \
  "hard-coded upstream libgcrypt.so.20 path still referenced" \
  "(^|[[:space:]\"'])/(lib|usr/lib|opt)/[^[:space:]\"'\$]*libgcrypt\\.so\\.20"
check_absent \
  "bridge-era dl linker flags still referenced" \
  'rustc-link-lib=dl|(^|[^[:alnum:]_])-ldl([^[:alnum:]_]|$)'

echo "check-no-upstream-bridge: ok"

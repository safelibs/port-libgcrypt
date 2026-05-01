#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
MANIFEST_PATH="${SAFE_DIR}/tests/regressions/manifest.json"
RUN_ALL=0
LIST_ONLY=0
REQUESTED=()

usage() {
  cat <<'EOF'
Usage: run-regression-tests.sh --all
       run-regression-tests.sh --list
       run-regression-tests.sh REGRESSION_ID [...]
EOF
}

fail() {
  echo "run-regression-tests: $*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --all)
      RUN_ALL=1
      shift
      ;;
    --list)
      LIST_ONLY=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        REQUESTED+=("$1")
        shift
      done
      ;;
    -*)
      usage >&2
      exit 1
      ;;
    *)
      REQUESTED+=("$1")
      shift
      ;;
  esac
done

[[ -f "${MANIFEST_PATH}" ]] || fail "missing manifest: ${MANIFEST_PATH}"
if [[ "${LIST_ONLY}" -eq 0 && "${RUN_ALL}" -eq 0 && "${#REQUESTED[@]}" -eq 0 ]]; then
  usage >&2
  exit 1
fi
if [[ "${RUN_ALL}" -eq 1 && "${#REQUESTED[@]}" -gt 0 ]]; then
  fail "--all cannot be combined with explicit regression IDs"
fi

load_entries() {
  python3 - "${MANIFEST_PATH}" "${RUN_ALL}" "${LIST_ONLY}" "${REQUESTED[@]}" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
run_all = sys.argv[2] == "1"
list_only = sys.argv[3] == "1"
requested = sys.argv[4:]

def fail(message: str) -> None:
    raise SystemExit(f"run-regression-tests: {message}")

try:
    manifest = json.loads(manifest_path.read_text())
except json.JSONDecodeError as err:
    fail(f"manifest is not valid JSON: {err}")

if manifest.get("manifest_version") != 1:
    fail("manifest_version must be 1")

regressions = manifest.get("regressions")
if not isinstance(regressions, list):
    fail("manifest regressions must be a list")

by_id = {}
for index, regression in enumerate(regressions):
    if not isinstance(regression, dict):
        fail(f"regression {index} must be an object")
    regression_id = regression.get("id")
    kind = regression.get("kind")
    path = regression.get("path")
    if not all(isinstance(value, str) and value for value in (regression_id, kind, path)):
        fail(f"regression {index} must have non-empty string id, kind, and path")
    if "\t" in regression_id or "\t" in kind or "\t" in path:
        fail(f"regression {regression_id} contains a tab in id, kind, or path")
    path_obj = Path(path)
    if path_obj.is_absolute() or ".." in path_obj.parts:
        fail(f"regression {regression_id} path must be a repository-relative path")
    if regression_id in by_id:
        fail(f"duplicate regression id: {regression_id}")
    by_id[regression_id] = regression

if list_only:
    selected = regressions
elif run_all:
    selected = regressions
else:
    selected = []
    for regression_id in requested:
        if regression_id not in by_id:
            fail(f"unknown regression id: {regression_id}")
        selected.append(by_id[regression_id])

for regression in selected:
    print(f"{regression['id']}\t{regression['kind']}\t{regression['path']}")
PY
}

if [[ "${LIST_ONLY}" -eq 1 ]]; then
  load_entries
  exit 0
fi

ran=0
while IFS=$'\t' read -r regression_id kind path; do
  [[ -n "${regression_id}" ]] || continue
  case "${kind}" in
    shell)
      target="${REPO_DIR}/${path}"
      [[ -f "${target}" ]] || fail "missing regression file for ${regression_id}: ${path}"
      echo "run-regression-tests: ${regression_id}"
      bash "${target}"
      ;;
    *)
      fail "unsupported regression kind for ${regression_id}: ${kind}"
      ;;
  esac
  ran=$((ran + 1))
done < <(load_entries)

[[ "${ran}" -gt 0 ]] || fail "no regressions selected"
echo "run-regression-tests: ok (${ran} regression(s))"

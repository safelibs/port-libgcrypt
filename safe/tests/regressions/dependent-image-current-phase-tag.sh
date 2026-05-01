#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DEPENDENT_IMAGE="${REPO_DIR}/safe/scripts/build-dependent-image.sh"

fail() {
  echo "dependent-image-current-phase-tag: $*" >&2
  exit 1
}

[[ -x "${BUILD_DEPENDENT_IMAGE}" ]] || fail "build-dependent-image.sh is not executable"

head_commit="$(git -C "${REPO_DIR}" rev-parse HEAD)"
mapfile -t head_phase_tags < <(git -C "${REPO_DIR}" tag --points-at HEAD --list 'phase/*' | sort)
[[ "${#head_phase_tags[@]}" -gt 0 ]] || fail "no local phase tag points at HEAD"
EXPECTED_TAG="${head_phase_tags[0]}"

expected_commit="$(git -C "${REPO_DIR}" rev-parse --verify "${EXPECTED_TAG}^{commit}" 2>/dev/null)" \
  || fail "missing required local phase tag: ${EXPECTED_TAG}"

[[ "${expected_commit}" == "${head_commit}" ]] \
  || fail "${EXPECTED_TAG} does not point at HEAD"

actual_tag="$("${BUILD_DEPENDENT_IMAGE}" --print-phase-tag)"
[[ "${actual_tag}" == "${EXPECTED_TAG}" ]] \
  || fail "build-dependent-image selected ${actual_tag:-<none>}, expected ${EXPECTED_TAG}"

echo "dependent-image-current-phase-tag: ok"

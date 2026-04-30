#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
ROOT_TOOLCHAIN="${REPO_DIR}/rust-toolchain.toml"
SAFE_TOOLCHAIN="${SAFE_DIR}/rust-toolchain.toml"
EXPECTED_RELEASE="1.85.1"

fail() {
  echo "check-rust-toolchain: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || fail "missing file: $1"
}

toml_string_value() {
  local key="$1"
  local path="$2"

  awk -F'"' -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      print $2
      exit
    }
  ' "${path}"
}

toml_array_value() {
  local key="$1"
  local path="$2"

  sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "${path}" \
    | head -n1 \
    | tr -d '[:space:]'
}

tool_release() {
  local output="$1"

  awk -F': ' '/^release:/ { print $2; exit }' <<<"${output}"
}

require_release() {
  local tool="$1"
  local release="$2"

  if [[ "${release}" != "${EXPECTED_RELEASE}" ]]; then
    if [[ "${release}" == "1.75."* || "${release}" == "1.75" ]]; then
      fail "active ${tool} is Ubuntu 24.04 packaged Rust ${release}; expected pinned Rust ${EXPECTED_RELEASE}"
    fi
    fail "active ${tool} release is ${release:-unknown}; expected pinned Rust ${EXPECTED_RELEASE}"
  fi
}

require_file "${ROOT_TOOLCHAIN}"
require_file "${SAFE_TOOLCHAIN}"

cmp -s "${ROOT_TOOLCHAIN}" "${SAFE_TOOLCHAIN}" \
  || fail "root and safe rust-toolchain.toml files differ"

channel="$(toml_string_value channel "${ROOT_TOOLCHAIN}")"
profile="$(toml_string_value profile "${ROOT_TOOLCHAIN}")"
components="$(toml_array_value components "${ROOT_TOOLCHAIN}")"

[[ "${channel}" == "${EXPECTED_RELEASE}" ]] \
  || fail "toolchain channel is ${channel:-unset}; expected ${EXPECTED_RELEASE}"
[[ "${profile}" == "minimal" ]] \
  || fail "toolchain profile is ${profile:-unset}; expected minimal"
[[ "${components}" == '["rustfmt"]' ]] \
  || fail "toolchain components are ${components:-unset}; expected [\"rustfmt\"]"

cd "${REPO_DIR}"

export RUSTUP_AUTO_INSTALL=0

if command -v rustup >/dev/null 2>&1; then
  installed_toolchains="$(rustup toolchain list 2>&1)" \
    || fail "rustup could not list installed toolchains: ${installed_toolchains}"
  expected_release_regex="${EXPECTED_RELEASE//./\\.}"
  if ! grep -Eq "^${expected_release_regex}(-|[[:space:]]|$)" <<<"${installed_toolchains}"; then
    fail "pinned Rust ${EXPECTED_RELEASE} is not installed; install it outside this checker with rustfmt before building"
  fi
fi

rustc_output="$(rustc -Vv 2>&1)" \
  || fail "rustc did not run under pinned ${EXPECTED_RELEASE}: ${rustc_output}"
cargo_output="$(cargo -Vv 2>&1)" \
  || fail "cargo did not run under pinned ${EXPECTED_RELEASE}: ${cargo_output}"

rustc_release="$(tool_release "${rustc_output}")"
cargo_release="$(tool_release "${cargo_output}")"

require_release rustc "${rustc_release}"
require_release cargo "${cargo_release}"

if command -v rustup >/dev/null 2>&1; then
  rustc_path="$(rustup which rustc 2>&1)" \
    || fail "rustup could not resolve pinned rustc ${EXPECTED_RELEASE}: ${rustc_path}"
  cargo_path="$(rustup which cargo 2>&1)" \
    || fail "rustup could not resolve pinned cargo ${EXPECTED_RELEASE}: ${cargo_path}"
  rustc_dir="$(dirname "$(realpath "${rustc_path}")")"
  cargo_dir="$(dirname "$(realpath "${cargo_path}")")"

  [[ "${rustc_dir}" == "${cargo_dir}" ]] \
    || fail "rustc and cargo come from different toolchain directories: ${rustc_dir} vs ${cargo_dir}"
  case "${rustc_path}" in
    *"/toolchains/${EXPECTED_RELEASE}-"*/bin/rustc|*"/toolchains/${EXPECTED_RELEASE}/bin/rustc")
      ;;
    *)
      fail "rustc path is not the pinned ${EXPECTED_RELEASE} toolchain: ${rustc_path}"
      ;;
  esac
else
  rustc_cmd="$(realpath "$(command -v rustc)")"
  cargo_cmd="$(realpath "$(command -v cargo)")"
  [[ "$(dirname "${rustc_cmd}")" == "$(dirname "${cargo_cmd}")" ]] \
    || fail "rustc and cargo are not from the same toolchain directory"
fi

echo "check-rust-toolchain: ok (${EXPECTED_RELEASE})"

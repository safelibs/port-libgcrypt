#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
DIST_DIR=
OVERRIDE_ROOT=
PORT_LOCK=
ARTIFACT_ROOT=
IMAGE="ubuntu:24.04"
LIBRARY="libgcrypt"

usage() {
  cat <<'EOF'
Usage: check-validator-package-dev-probe.sh --dist PATH --override-root PATH --port-lock PATH --artifact-root PATH [--image IMAGE]
EOF
}

fail() {
  echo "check-validator-package-dev-probe: $*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST_DIR="$2"
      shift 2
      ;;
    --override-root)
      OVERRIDE_ROOT="$2"
      shift 2
      ;;
    --port-lock)
      PORT_LOCK="$2"
      shift 2
      ;;
    --artifact-root)
      ARTIFACT_ROOT="$2"
      shift 2
      ;;
    --image)
      IMAGE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done

[[ -n "${DIST_DIR}" ]] || fail "--dist is required"
[[ -n "${OVERRIDE_ROOT}" ]] || fail "--override-root is required"
[[ -n "${PORT_LOCK}" ]] || fail "--port-lock is required"
[[ -n "${ARTIFACT_ROOT}" ]] || fail "--artifact-root is required"
[[ -d "${DIST_DIR}" ]] || fail "missing dist directory: ${DIST_DIR}"
[[ -d "${OVERRIDE_ROOT}" ]] || fail "missing override root: ${OVERRIDE_ROOT}"
[[ -f "${PORT_LOCK}" ]] || fail "missing port lock: ${PORT_LOCK}"

DIST_DIR="$(realpath "${DIST_DIR}")"
OVERRIDE_ROOT="$(realpath "${OVERRIDE_ROOT}")"
PORT_LOCK="$(realpath "${PORT_LOCK}")"
ARTIFACT_ROOT="$(realpath -m "${ARTIFACT_ROOT}")"
[[ "${ARTIFACT_ROOT}" != "/" ]] || fail "refusing to use / as artifact root"

rm -rf "${ARTIFACT_ROOT}"
mkdir -p "${ARTIFACT_ROOT}"

python3 - "${REPO_DIR}" "${DIST_DIR}" "${OVERRIDE_ROOT}" "${PORT_LOCK}" "${ARTIFACT_ROOT}" "${LIBRARY}" <<'PY'
from __future__ import annotations

import hashlib
import json
import shlex
import sys
from pathlib import Path

CANONICAL_PACKAGES = ("libgcrypt20", "libgcrypt20-dev")
PREFIX_BY_PACKAGE = {
    "libgcrypt20": "RUNTIME",
    "libgcrypt20-dev": "DEV",
}


def fail(message: str) -> None:
    raise SystemExit(f"check-validator-package-dev-probe: {message}")


def load_json(path: Path, *, label: str) -> dict:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    except json.JSONDecodeError as exc:
        fail(f"{label} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object")
    return data


def require_string(data: dict, key: str, *, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{context} missing required string field {key}")
    return value


def require_int(data: dict, key: str, *, context: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{context} missing required integer field {key}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_deb_file(path: Path, deb: dict, *, label: str) -> None:
    if not path.is_file():
        fail(f"missing {label}: {path}")
    if path.stat().st_size != deb["size"]:
        fail(f"{label} size mismatch for {path.name}")
    if sha256(path) != deb["sha256"]:
        fail(f"{label} sha256 mismatch for {path.name}")


repo_dir = Path(sys.argv[1])
dist_dir = Path(sys.argv[2])
override_root = Path(sys.argv[3])
port_lock = Path(sys.argv[4])
artifact_root = Path(sys.argv[5])
library = sys.argv[6]

payload = load_json(port_lock, label="port lock")
if payload.get("schema_version") != 1 or payload.get("mode") != "port":
    fail("port lock must have schema_version 1 and mode port")
libraries = payload.get("libraries")
if not isinstance(libraries, list):
    fail("port lock libraries must be a list")
matches = [item for item in libraries if isinstance(item, dict) and item.get("library") == library]
if len(matches) != 1:
    fail(f"port lock must contain exactly one {library} entry")
lock_entry = matches[0]
for key in ("repository", "release_tag", "tag_ref", "commit"):
    require_string(lock_entry, key, context=f"port lock {library}")
debs = lock_entry.get("debs")
if not isinstance(debs, list):
    fail(f"port lock {library} debs must be a list")
if len(debs) != len(CANONICAL_PACKAGES):
    fail(f"port lock must contain exactly {len(CANONICAL_PACKAGES)} deb entries")

by_package: dict[str, dict] = {}
for deb in debs:
    if not isinstance(deb, dict):
        fail("port lock deb entries must be objects")
    package = require_string(deb, "package", context="port lock deb")
    if package in by_package:
        fail(f"duplicate port lock deb package: {package}")
    filename = require_string(deb, "filename", context=f"port lock {package}")
    if Path(filename).name != filename or not filename.endswith(".deb"):
        fail(f"port lock {package} filename must be a plain .deb basename")
    for key in ("architecture", "sha256", "version"):
        require_string(deb, key, context=f"port lock {package}")
    require_int(deb, "size", context=f"port lock {package}")
    by_package[package] = deb
if tuple(by_package) != CANONICAL_PACKAGES:
    fail("port lock debs must be in canonical libgcrypt20, libgcrypt20-dev order")
if lock_entry.get("unported_original_packages") != []:
    fail("local libgcrypt port lock must have no unported original packages")

override_leaf = override_root / library
if not override_leaf.is_dir():
    fail(f"missing override deb leaf: {override_leaf}")
expected_names = [by_package[package]["filename"] for package in CANONICAL_PACKAGES]
actual_override_entries = sorted(path.name for path in override_leaf.iterdir())
if actual_override_entries != sorted(expected_names):
    fail(
        "override deb leaf must contain exactly the locked debs: "
        f"expected={sorted(expected_names)} actual={actual_override_entries}"
    )
actual_dist_debs = sorted(path.name for path in dist_dir.glob("*.deb") if path.is_file())
if actual_dist_debs != sorted(expected_names):
    fail(
        "dist deb set must match the locked override debs: "
        f"expected={sorted(expected_names)} actual={actual_dist_debs}"
    )

for package in CANONICAL_PACKAGES:
    deb = by_package[package]
    validate_deb_file(override_leaf / deb["filename"], deb, label="override deb")
    validate_deb_file(dist_dir / deb["filename"], deb, label="dist deb")

expected_json = {
    "library": library,
    "repository": lock_entry["repository"],
    "release_tag": lock_entry["release_tag"],
    "tag_ref": lock_entry["tag_ref"],
    "commit": lock_entry["commit"],
    "debs": [by_package[package] for package in CANONICAL_PACKAGES],
}
(artifact_root / "expected-debs.json").write_text(json.dumps(expected_json, indent=2, sort_keys=True) + "\n")

env_lines = [
    f"LIBRARY={shlex.quote(library)}",
    f"PORT_REPOSITORY={shlex.quote(lock_entry['repository'])}",
    f"PORT_RELEASE_TAG={shlex.quote(lock_entry['release_tag'])}",
    f"PORT_TAG_REF={shlex.quote(lock_entry['tag_ref'])}",
    f"PORT_COMMIT={shlex.quote(lock_entry['commit'])}",
]
for package in CANONICAL_PACKAGES:
    prefix = PREFIX_BY_PACKAGE[package]
    deb = by_package[package]
    env_lines.extend(
        [
            f"{prefix}_PACKAGE={shlex.quote(deb['package'])}",
            f"{prefix}_FILENAME={shlex.quote(deb['filename'])}",
            f"{prefix}_VERSION={shlex.quote(deb['version'])}",
            f"{prefix}_ARCHITECTURE={shlex.quote(deb['architecture'])}",
            f"{prefix}_SHA256={shlex.quote(deb['sha256'])}",
            f"{prefix}_SIZE={deb['size']}",
        ]
    )
(artifact_root / "expected-debs.env").write_text("\n".join(env_lines) + "\n")

(artifact_root / "host-validation.txt").write_text(
    "\n".join(
        [
            f"repo_dir={repo_dir}",
            f"dist_dir={dist_dir}",
            f"override_root={override_root}",
            f"port_lock={port_lock}",
            f"override_leaf={override_leaf}",
            f"image_lock_commit={lock_entry['commit']}",
            "host_pre_docker_validation=passed",
        ]
    )
    + "\n"
)

(artifact_root / "package-surface-probe.c").write_text(
    """#include <gcrypt.h>
#include <stdio.h>

int
main(void)
{
  const char *version = gcry_check_version(NULL);
  if (version == NULL)
    {
      fputs("gcry_check_version returned NULL\\n", stderr);
      return 1;
    }
  puts(version);
  return 0;
}
"""
)
PY

cat >"${ARTIFACT_ROOT}/container-probe.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="/artifacts"
INPUT_DIR="/input-debs"
EXPECTED_ENV="${ARTIFACT_ROOT}/expected-debs.env"
PROBE_SOURCE="${ARTIFACT_ROOT}/package-surface-probe.c"
COMPILE_COMMANDS="${ARTIFACT_ROOT}/compiler-commands.txt"
RESULT_JSON="${ARTIFACT_ROOT}/probe-result.json"
last_step="start"

fail() {
  echo "check-validator-package-dev-probe: $*" >&2
  exit 1
}

write_result() {
  local status="$1"
  local exit_code="$2"
  local step="$3"
  cat >"${RESULT_JSON}" <<JSON
{
  "status": "${status}",
  "exit_code": ${exit_code},
  "last_step": "${step}",
  "runtime_package": "${RUNTIME_PACKAGE:-}",
  "runtime_filename": "${RUNTIME_FILENAME:-}",
  "dev_package": "${DEV_PACKAGE:-}",
  "dev_filename": "${DEV_FILENAME:-}"
}
JSON
}

finish() {
  local rc=$?
  trap - EXIT
  if [[ "${rc}" -eq 0 ]]; then
    write_result "passed" 0 "${last_step}"
  else
    write_result "failed" "${rc}" "${last_step}"
  fi
  exit "${rc}"
}
trap finish EXIT

[[ -f "${EXPECTED_ENV}" ]] || fail "missing expected deb metadata"
# shellcheck disable=SC1090
. "${EXPECTED_ENV}"
[[ -f "${PROBE_SOURCE}" ]] || fail "missing package surface probe source"
: >"${COMPILE_COMMANDS}"

check_input_deb() {
  local prefix="$1"
  local package_var="${prefix}_PACKAGE"
  local filename_var="${prefix}_FILENAME"
  local version_var="${prefix}_VERSION"
  local architecture_var="${prefix}_ARCHITECTURE"
  local sha256_var="${prefix}_SHA256"
  local size_var="${prefix}_SIZE"
  local package="${!package_var}"
  local filename="${!filename_var}"
  local version="${!version_var}"
  local architecture="${!architecture_var}"
  local expected_sha256="${!sha256_var}"
  local expected_size="${!size_var}"
  local path="${INPUT_DIR}/${filename}"
  local actual_size actual_sha256 actual_package actual_version actual_architecture

  [[ -f "${path}" ]] || fail "missing mounted deb: ${filename}"
  actual_size="$(stat -c '%s' "${path}")"
  [[ "${actual_size}" == "${expected_size}" ]] || fail "${filename} size mismatch in container"
  actual_sha256="$(sha256sum "${path}" | awk '{print $1}')"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || fail "${filename} sha256 mismatch in container"
  actual_package="$(dpkg-deb -f "${path}" Package)"
  actual_version="$(dpkg-deb -f "${path}" Version)"
  actual_architecture="$(dpkg-deb -f "${path}" Architecture)"
  [[ "${actual_package}" == "${package}" ]] || fail "${filename} package field mismatch"
  [[ "${actual_version}" == "${version}" ]] || fail "${filename} version field mismatch"
  [[ "${actual_architecture}" == "${architecture}" ]] || fail "${filename} architecture field mismatch"
}

record_mounted_debs() {
  {
    for prefix in RUNTIME DEV; do
      local package_var="${prefix}_PACKAGE"
      local filename_var="${prefix}_FILENAME"
      local version_var="${prefix}_VERSION"
      local architecture_var="${prefix}_ARCHITECTURE"
      local sha256_var="${prefix}_SHA256"
      local size_var="${prefix}_SIZE"
      local package="${!package_var}"
      local filename="${!filename_var}"
      local version="${!version_var}"
      local architecture="${!architecture_var}"
      local expected_sha256="${!sha256_var}"
      local expected_size="${!size_var}"

      echo "package=${package}"
      echo "filename=${filename}"
      echo "version=${version}"
      echo "architecture=${architecture}"
      echo "size=${expected_size}"
      echo "sha256=${expected_sha256}"
      echo
    done
  } >"${ARTIFACT_ROOT}/mounted-deb-metadata.txt"
}

install_packages() {
  last_step="install-packages"
  set +e
  {
    apt-get update
    apt-get install -y --no-install-recommends \
      gcc \
      pkg-config \
      "${INPUT_DIR}/${RUNTIME_FILENAME}" \
      "${INPUT_DIR}/${DEV_FILENAME}"
  } 2>&1 | tee "${ARTIFACT_ROOT}/install.log"
  local rc=${PIPESTATUS[0]}
  set -e
  return "${rc}"
}

verify_installed_package() {
  local prefix="$1"
  local package_var="${prefix}_PACKAGE"
  local filename_var="${prefix}_FILENAME"
  local version_var="${prefix}_VERSION"
  local architecture_var="${prefix}_ARCHITECTURE"
  local sha256_var="${prefix}_SHA256"
  local size_var="${prefix}_SIZE"
  local package="${!package_var}"
  local filename="${!filename_var}"
  local version="${!version_var}"
  local architecture="${!architecture_var}"
  local expected_sha256="${!sha256_var}"
  local expected_size="${!size_var}"
  local actual_package actual_version actual_architecture actual_status actual_size actual_sha256

  actual_package="$(dpkg-query -W -f='${Package}' "${package}")"
  actual_version="$(dpkg-query -W -f='${Version}' "${package}")"
  actual_architecture="$(dpkg-query -W -f='${Architecture}' "${package}")"
  actual_status="$(dpkg-query -W -f='${db:Status-Status}' "${package}")"
  [[ "${actual_package}" == "${package}" ]] || fail "installed ${package} package name mismatch"
  [[ "${actual_version}" == "${version}" ]] || fail "installed ${package} version mismatch"
  [[ "${actual_architecture}" == "${architecture}" ]] || fail "installed ${package} architecture mismatch"
  [[ "${actual_status}" == "installed" ]] || fail "installed ${package} status mismatch"

  actual_size="$(stat -c '%s' "${INPUT_DIR}/${filename}")"
  actual_sha256="$(sha256sum "${INPUT_DIR}/${filename}" | awk '{print $1}')"
  [[ "${actual_size}" == "${expected_size}" ]] || fail "installed source ${filename} size mismatch"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || fail "installed source ${filename} sha256 mismatch"
  [[ "$(dpkg-deb -f "${INPUT_DIR}/${filename}" Package)" == "${package}" ]] || fail "installed source ${filename} package mismatch"
  [[ "$(dpkg-deb -f "${INPUT_DIR}/${filename}" Version)" == "${version}" ]] || fail "installed source ${filename} version mismatch"
  [[ "$(dpkg-deb -f "${INPUT_DIR}/${filename}" Architecture)" == "${architecture}" ]] || fail "installed source ${filename} architecture mismatch"
}

record_installed_packages() {
  {
    for prefix in RUNTIME DEV; do
      local package_var="${prefix}_PACKAGE"
      local filename_var="${prefix}_FILENAME"
      local sha256_var="${prefix}_SHA256"
      local size_var="${prefix}_SIZE"
      local package="${!package_var}"
      local filename="${!filename_var}"
      local expected_sha256="${!sha256_var}"
      local expected_size="${!size_var}"

      echo "package=${package}"
      dpkg-query -W -f='Package=${Package}\nVersion=${Version}\nArchitecture=${Architecture}\nStatus=${db:Status-Status}\nMulti-Arch=${Multi-Arch}\nDepends=${Depends}\nProvides=${Provides}\nConflicts=${Conflicts}\n' "${package}"
      echo "filename=${filename}"
      echo "size=${expected_size}"
      echo "sha256=${expected_sha256}"
      echo
    done
  } >"${ARTIFACT_ROOT}/installed-package-metadata.txt"
}

record_command() {
  local label="$1"
  shift
  {
    printf '%s: ' "${label}"
    printf '%q ' "$@"
    printf '\n'
  } >>"${COMPILE_COMMANDS}"
}

run_recorded() {
  local label="$1"
  shift
  last_step="${label}"
  record_command "${label}" "$@"
  "$@" >"${ARTIFACT_ROOT}/${label}.stdout" 2>"${ARTIFACT_ROOT}/${label}.stderr"
}

split_words() {
  local value="$1"
  local array_name="$2"
  if [[ -n "${value}" ]]; then
    read -r -a "${array_name}" <<<"${value}"
  else
    eval "${array_name}=()"
  fi
}

record_pkg_config_outputs() {
  last_step="pkg-config-output"
  {
    echo '$ pkg-config --modversion libgcrypt'
    pkg-config --modversion libgcrypt
    echo '$ pkg-config --cflags libgcrypt'
    pkg-config --cflags libgcrypt
    echo '$ pkg-config --libs libgcrypt'
    pkg-config --libs libgcrypt
  } >"${ARTIFACT_ROOT}/pkg-config-output.txt"
}

record_libgcrypt_config_outputs() {
  last_step="libgcrypt-config-output"
  {
    echo '$ libgcrypt-config --version'
    libgcrypt-config --version
    echo '$ libgcrypt-config --api-version'
    libgcrypt-config --api-version
    echo '$ libgcrypt-config --cflags'
    libgcrypt-config --cflags
    echo '$ libgcrypt-config --libs'
    libgcrypt-config --libs
  } >"${ARTIFACT_ROOT}/libgcrypt-config-output.txt"
}

compile_and_run_direct() {
  local multiarch
  multiarch="$(gcc -print-multiarch)"
  run_recorded \
    compile-direct \
    gcc \
    -I/usr/include \
    "${PROBE_SOURCE}" \
    -o "${ARTIFACT_ROOT}/probe-direct" \
    -L"/usr/lib/${multiarch}" \
    -Wl,-rpath,"/usr/lib/${multiarch}" \
    -lgcrypt
  run_recorded run-direct "${ARTIFACT_ROOT}/probe-direct"
}

compile_and_run_pkg_config() {
  local cflags libs
  local -a cflag_words=()
  local -a lib_words=()

  record_pkg_config_outputs
  cflags="$(pkg-config --cflags libgcrypt)"
  libs="$(pkg-config --libs libgcrypt)"
  split_words "${cflags}" cflag_words
  split_words "${libs}" lib_words
  run_recorded \
    compile-pkg-config \
    gcc \
    "${cflag_words[@]}" \
    "${PROBE_SOURCE}" \
    -o "${ARTIFACT_ROOT}/probe-pkg-config" \
    "${lib_words[@]}"
  run_recorded run-pkg-config "${ARTIFACT_ROOT}/probe-pkg-config"
}

compile_and_run_libgcrypt_config() {
  local cflags libs
  local -a cflag_words=()
  local -a lib_words=()

  record_libgcrypt_config_outputs
  cflags="$(libgcrypt-config --cflags)"
  libs="$(libgcrypt-config --libs)"
  split_words "${cflags}" cflag_words
  split_words "${libs}" lib_words
  run_recorded \
    compile-libgcrypt-config \
    gcc \
    "${cflag_words[@]}" \
    "${PROBE_SOURCE}" \
    -o "${ARTIFACT_ROOT}/probe-libgcrypt-config" \
    "${lib_words[@]}"
  run_recorded run-libgcrypt-config "${ARTIFACT_ROOT}/probe-libgcrypt-config"
}

last_step="validate-mounted-debs"
check_input_deb RUNTIME
check_input_deb DEV
record_mounted_debs
install_packages
last_step="verify-installed-packages"
verify_installed_package RUNTIME
verify_installed_package DEV
record_installed_packages
compile_and_run_direct
compile_and_run_pkg_config
compile_and_run_libgcrypt_config
last_step="complete"
EOF
chmod +x "${ARTIFACT_ROOT}/container-probe.sh"

DOCKER_CMD=(
  docker run --rm
  -e DEBIAN_FRONTEND=noninteractive
  -v "${ARTIFACT_ROOT}:/artifacts"
  -v "${OVERRIDE_ROOT}/${LIBRARY}:/input-debs:ro"
  "${IMAGE}"
  bash /artifacts/container-probe.sh
)

printf '%q ' "${DOCKER_CMD[@]}" >"${ARTIFACT_ROOT}/docker-command.txt"
printf '\n' >>"${ARTIFACT_ROOT}/docker-command.txt"

set +e
"${DOCKER_CMD[@]}" 2>&1 | tee "${ARTIFACT_ROOT}/container.log"
docker_rc=${PIPESTATUS[0]}
set -e

if [[ "${docker_rc}" -ne 0 ]]; then
  if [[ ! -f "${ARTIFACT_ROOT}/probe-result.json" ]]; then
    cat >"${ARTIFACT_ROOT}/probe-result.json" <<JSON
{
  "status": "failed",
  "exit_code": ${docker_rc},
  "last_step": "docker-run"
}
JSON
  fi
  fail "package/development probe failed; see ${ARTIFACT_ROOT}/container.log"
fi

grep -q '"status": "passed"' "${ARTIFACT_ROOT}/probe-result.json" \
  || fail "probe result did not report success"

echo "check-validator-package-dev-probe: ok"

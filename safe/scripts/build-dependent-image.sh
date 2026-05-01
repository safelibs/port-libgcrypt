#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
METADATA_DIR="${SAFE_DIR}/tests/dependents/metadata"
IMPLEMENTATION=
TAG=
PRINT_PHASE_TAG=0
PRINT_DOCKERFILE=0

usage() {
  cat <<'EOF'
Usage: build-dependent-image.sh --implementation original|safe --tag IMAGE_TAG
       build-dependent-image.sh --print-phase-tag
       build-dependent-image.sh --print-dockerfile
EOF
}

fail() {
  echo "build-dependent-image: $*" >&2
  exit 1
}

current_phase_tag() {
  git -C "${REPO_DIR}" tag --points-at HEAD --list 'phase/*' | sort | head -n 1
}

write_dockerfile() {
  cat <<'EOF'
ARG BASE_REF
FROM ${BASE_REF}

ARG IMPLEMENTATION
ARG PHASE_COMMIT
ARG PHASE_TAG

ENV DEBIAN_FRONTEND=noninteractive
ENV IMPLEMENTATION=${IMPLEMENTATION}
ENV PHASE_COMMIT=${PHASE_COMMIT}
ENV PHASE_TAG=${PHASE_TAG}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY . /opt/libgcrypt-dependent
WORKDIR /opt/libgcrypt-dependent

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    cp safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources /etc/apt/sources.list.d/ubuntu.sources

RUN set -euo pipefail; \
    snapshot_apt_opts=( \
      -o Acquire::Retries=8 \
      -o Acquire::ForceIPv4=true \
      -o Acquire::Queue-Mode=access \
      -o Acquire::http::Pipeline-Depth=0 \
      -o Acquire::https::Pipeline-Depth=0 \
      -o Acquire::http::Timeout=20 \
      -o Acquire::https::Timeout=20 \
      -o Acquire::https::Verify-Peer=false \
      -o APT::Update::Error-Mode=any \
    ); \
    apt_bootstrap_ca_certificates_from_snapshot() { \
      local attempt; \
      for attempt in 1 2 3 4 5 6 7 8; do \
        rm -rf /var/lib/apt/lists/*; \
        if apt-get "${snapshot_apt_opts[@]}" update && \
           apt-cache policy ca-certificates | grep -F '20240203' >/dev/null && \
           apt-get "${snapshot_apt_opts[@]}" install -y --no-install-recommends ca-certificates=20240203; then \
          rm -rf /var/lib/apt/lists/*; \
          return 0; \
        fi; \
        sleep "${attempt}"; \
      done; \
      return 1; \
    }; \
    apt_bootstrap_ca_certificates_from_snapshot

RUN set -euo pipefail; \
    snapshot_apt_opts=( \
      -o Acquire::Retries=8 \
      -o Acquire::ForceIPv4=true \
      -o Acquire::Queue-Mode=access \
      -o Acquire::http::Pipeline-Depth=0 \
      -o Acquire::https::Pipeline-Depth=0 \
      -o Acquire::http::Timeout=20 \
      -o Acquire::https::Timeout=20 \
      -o APT::Update::Error-Mode=any \
    ); \
    install_locked_packages_once() { \
      if [ "${IMPLEMENTATION}" = "safe" ]; then \
        apt-get "$@" install -y --no-install-recommends \
          ./safe/dist/libgcrypt20_*.deb \
          ./safe/dist/libgcrypt20-dev_*.deb; \
      fi; \
      xargs -r apt-get "$@" install -y --no-install-recommends < "apt-packages.${IMPLEMENTATION}"; \
    }; \
    locked_packages_visible() { \
      local spec package version; \
      while IFS= read -r spec; do \
        [ -n "${spec}" ] || continue; \
        package="${spec%%=*}"; \
        version="${spec#*=}"; \
        apt-cache policy "${package}" | grep -F " ${version}" >/dev/null || return 1; \
      done < "apt-packages.${IMPLEMENTATION}"; \
    }; \
    apt_install_locked_packages_from_snapshot() { \
      local attempt; \
      for attempt in 1 2 3 4 5 6 7 8; do \
        rm -rf /var/lib/apt/lists/*; \
        if apt-get "${snapshot_apt_opts[@]}" update && locked_packages_visible; then \
          if install_locked_packages_once "${snapshot_apt_opts[@]}"; then \
            rm -rf /var/lib/apt/lists/*; \
            return 0; \
          fi; \
        fi; \
        sleep "${attempt}"; \
      done; \
      return 1; \
    }; \
    apt_install_locked_packages_from_snapshot || { \
      echo "pinned Ubuntu snapshot unavailable for locked dependent package closure" >&2; \
      exit 1; \
    }

RUN python3 safe/tests/dependents/validate-installed-packages.py

RUN multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH)" && \
    expected="$(readlink -f "/usr/lib/${multiarch}/libgcrypt.so.20")" && \
    printf 'IMPLEMENTATION=%s\nLIBGCRYPT_EXPECTED_REALPATH=%s\n' "${IMPLEMENTATION}" "${expected}" \
      > /opt/libgcrypt-dependent/implementation.env
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --implementation)
      IMPLEMENTATION="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --print-phase-tag)
      PRINT_PHASE_TAG=1
      shift
      ;;
    --print-dockerfile)
      PRINT_DOCKERFILE=1
      shift
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

if [[ "${PRINT_PHASE_TAG}" -eq 1 ]]; then
  current_phase_tag
  exit 0
fi

if [[ "${PRINT_DOCKERFILE}" -eq 1 ]]; then
  write_dockerfile
  exit 0
fi

[[ "${IMPLEMENTATION}" == "original" || "${IMPLEMENTATION}" == "safe" ]] \
  || fail "--implementation must be original or safe"
[[ -n "${TAG}" ]] || fail "--tag is required"

"${SCRIPT_DIR}/check-dependent-metadata.sh"

phase_commit="$(git -C "${REPO_DIR}" rev-parse HEAD)"
phase_tag="$(current_phase_tag)"

if [[ "${IMPLEMENTATION}" == "safe" ]]; then
  "${SCRIPT_DIR}/check-rust-toolchain.sh"
  "${SCRIPT_DIR}/build-debs.sh"
  "${SCRIPT_DIR}/check-deb-metadata.sh" --dist "${SAFE_DIR}/dist"

  python3 - "${REPO_DIR}" "${phase_commit}" "${phase_tag}" <<'PY'
import glob
import hashlib
import json
import subprocess
import sys
from pathlib import Path

repo = Path(sys.argv[1])
phase_commit = sys.argv[2]
phase_tag = sys.argv[3] or None
dist = repo / "safe" / "dist"
metadata = repo / "safe" / "tests" / "dependents" / "metadata"
manifest_path = dist / "safe-debs.manifest.json"


def fail(message: str) -> None:
    raise SystemExit(f"build-dependent-image: {message}")


def run(args: list[str]) -> str:
    return subprocess.check_output(args, text=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deb_field(path: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(path), field]).strip()


if not manifest_path.is_file():
    fail("safe/dist/safe-debs.manifest.json is absent")
manifest = json.loads(manifest_path.read_text())
if manifest.get("phase_commit") != phase_commit:
    fail("safe deb manifest is stale relative to selected phase commit")
if manifest.get("phase_tag") != phase_tag:
    fail("safe deb manifest phase_tag is stale relative to selected phase tag")

safe_lock = json.loads((metadata / "safe-debs.noble.lock").read_text())
manifest_by_name = {item.get("package_name"): item for item in manifest.get("packages", [])}
for policy in safe_lock["packages"]:
    name = policy["package_name"]
    matches = [Path(path) for path in glob.glob(str(repo / policy["file_glob"]))]
    if len(matches) != 1:
        fail(f"{policy['file_glob']} must match exactly one .deb")
    deb = matches[0]
    item = manifest_by_name.get(name)
    if item is None:
        fail(f"safe deb manifest is missing {name}")
    expected = {
        "package_name": deb_field(deb, "Package"),
        "architecture": deb_field(deb, "Architecture"),
        "version": deb_field(deb, "Version"),
        "source_package_name": policy["source_package"],
        "source_version": policy["source_version"],
        "filename": deb.name,
        "sha256": sha256(deb),
    }
    for key, value in expected.items():
        if item.get(key) != value:
            fail(f"safe deb manifest {name} {key} mismatch")
PY
fi

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

context="${tmpdir}/context"
mkdir -p \
  "${context}/safe/tests" \
  "${context}/safe/scripts" \
  "${context}/safe/dist"

cp -a "${SAFE_DIR}/tests/dependents" "${context}/safe/tests/"
mkdir -p "${context}/safe/tests/compat"
cp -a "${SAFE_DIR}/tests/compat/tool-fixtures" "${context}/safe/tests/compat/"
cp -a "${SCRIPT_DIR}/run-dependent-image-tests.sh" "${context}/safe/scripts/"
cp -a "${REPO_DIR}/dependents.json" "${context}/"
if [[ "${IMPLEMENTATION}" == "safe" ]]; then
  cp -a "${SAFE_DIR}/dist/." "${context}/safe/dist/"
fi

python3 - "${REPO_DIR}" "${context}" <<'PY'
import json
import sys
from pathlib import Path

repo = Path(sys.argv[1])
context = Path(sys.argv[2])
lock = json.loads(
    (repo / "safe" / "tests" / "dependents" / "metadata" / "install-packages.noble.lock").read_text()
)
for implementation in ("original", "safe"):
    lines = []
    for item in lock["requested_packages"]:
        if implementation == "safe" and item["implementation"] == "original":
            continue
        lines.append(f"{item['package']}={item['version']}")
    (context / f"apt-packages.{implementation}").write_text("\n".join(lines) + "\n")
PY

base_ref="$(<"${METADATA_DIR}/base-image.noble.digest")"
write_dockerfile > "${context}/Dockerfile"

docker build \
  --build-arg "BASE_REF=${base_ref}" \
  --build-arg "IMPLEMENTATION=${IMPLEMENTATION}" \
  --build-arg "PHASE_COMMIT=${phase_commit}" \
  --build-arg "PHASE_TAG=${phase_tag}" \
  -t "${TAG}" \
  "${context}"

echo "build-dependent-image: built ${TAG} (${IMPLEMENTATION})"

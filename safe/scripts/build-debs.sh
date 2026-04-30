#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${SAFE_DIR}/.." && pwd)"
DIST_DIR="${SAFE_DIR}/dist"
MANIFEST_PATH="${DIST_DIR}/safe-debs.manifest.json"

usage() {
  cat <<'EOF'
Usage: build-debs.sh
EOF
}

fail() {
  echo "build-debs: $*" >&2
  exit 1
}

if [[ "$#" -ne 0 ]]; then
  usage >&2
  exit 1
fi

cleanup_cargo_home=
if [[ -z "${CARGO_HOME:-}" ]]; then
  CARGO_HOME="$(mktemp -d)"
  export CARGO_HOME
  cleanup_cargo_home=1
fi

trap '[[ -n "${cleanup_cargo_home}" ]] && rm -rf "${CARGO_HOME}"' EXIT

mkdir -p "${CARGO_HOME}"
if find "${CARGO_HOME}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  fail "CARGO_HOME must be an empty directory"
fi

export CARGO_NET_OFFLINE=true
version="$(dpkg-parsechangelog -l"${SAFE_DIR}/debian/changelog" -SVersion)"

"${SCRIPT_DIR}/check-rust-toolchain.sh"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.deb
rm -f "${REPO_DIR}"/libgcrypt20-dev_"${version}"_*.deb
rm -f "${REPO_DIR}"/libgcrypt20-dbgsym_"${version}"_*.ddeb
rm -f "${REPO_DIR}"/libgcrypt20-dev-dbgsym_"${version}"_*.ddeb
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.buildinfo
rm -f "${REPO_DIR}"/libgcrypt20_"${version}"_*.changes

(
  cd "${SAFE_DIR}"
  dpkg-buildpackage -b -us -uc
)

shopt -s nullglob
artifacts=(
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.deb
  "${REPO_DIR}"/libgcrypt20-dev_"${version}"_*.deb
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.buildinfo
  "${REPO_DIR}"/libgcrypt20_"${version}"_*.changes
)
shopt -u nullglob

if [[ "${#artifacts[@]}" -eq 0 ]]; then
  fail "dpkg-buildpackage did not produce any artifacts for ${version}"
fi

cp -f -- "${artifacts[@]}" "${DIST_DIR}/"
rm -f "${REPO_DIR}"/libgcrypt20-dbgsym_"${version}"_*.ddeb
rm -f "${REPO_DIR}"/libgcrypt20-dev-dbgsym_"${version}"_*.ddeb

python3 - "${REPO_DIR}" "${SAFE_DIR}" "${DIST_DIR}" "${MANIFEST_PATH}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

repo_dir = Path(sys.argv[1])
safe_dir = Path(sys.argv[2])
dist_dir = Path(sys.argv[3])
manifest_path = Path(sys.argv[4])


def run(args: list[str]) -> str:
    return subprocess.check_output(args, text=True)


def deb_field(deb: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(deb), field]).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


debs = sorted(dist_dir.glob("*.deb"), key=lambda path: path.name)
if len(debs) != 2:
    raise SystemExit(f"expected exactly two .deb files in {dist_dir}, found {len(debs)}")

source_package = run(
    ["dpkg-parsechangelog", f"-l{safe_dir / 'debian' / 'changelog'}", "-SSource"]
).strip()

packages = []
for deb in debs:
    packages.append(
        {
            "package_name": deb_field(deb, "Package"),
            "source_package_name": source_package,
            "architecture": deb_field(deb, "Architecture"),
            "version": deb_field(deb, "Version"),
            "filename": deb.name,
            "sha256": sha256(deb),
        }
    )

manifest = {
    "manifest_version": 1,
    "phase_commit": run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"]).strip(),
    "source_package_name": source_package,
    "toolchain": {
        "rustc_vv": run(["rustc", "-Vv"]),
        "cargo_vv": run(["cargo", "-Vv"]),
    },
    "packages": packages,
}

manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY

echo "build-debs: wrote artifacts and manifest to ${DIST_DIR}"

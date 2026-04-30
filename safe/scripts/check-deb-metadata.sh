#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR=

usage() {
  cat <<'EOF'
Usage: check-deb-metadata.sh --dist PATH
EOF
}

fail() {
  echo "check-deb-metadata: $*" >&2
  exit 1
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST_DIR="$2"
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
[[ -d "${DIST_DIR}" ]] || fail "missing dist directory: ${DIST_DIR}"

shopt -s nullglob
debs=("${DIST_DIR}"/*.deb)
runtime_debs=("${DIST_DIR}"/libgcrypt20_*.deb)
dev_debs=("${DIST_DIR}"/libgcrypt20-dev_*.deb)
shopt -u nullglob

[[ "${#runtime_debs[@]}" -eq 1 ]] || fail "expected exactly one libgcrypt20 .deb"
[[ "${#dev_debs[@]}" -eq 1 ]] || fail "expected exactly one libgcrypt20-dev .deb"
[[ "${#debs[@]}" -eq 2 ]] || fail "expected exactly two binary packages in ${DIST_DIR}"

runtime_deb="${runtime_debs[0]}"
dev_deb="${dev_debs[0]}"

"${SCRIPT_DIR}/check-rust-toolchain.sh" >/dev/null

python3 - "${SAFE_DIR}" "${DIST_DIR}" <<'PY'
import hashlib
import json
import subprocess
import sys
from pathlib import Path

EXPECTED_RELEASE = "1.85.1"
safe_dir = Path(sys.argv[1])
dist_dir = Path(sys.argv[2])
repo_dir = safe_dir.parent
manifest_path = dist_dir / "safe-debs.manifest.json"


def fail(message: str) -> None:
    raise SystemExit(f"check-deb-metadata: {message}")


def run(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True)
    except subprocess.CalledProcessError as err:
        fail(f"command failed: {' '.join(args)}: {err}")


def release(output: str) -> str:
    for line in output.splitlines():
        if line.startswith("release: "):
            return line.split(": ", 1)[1]
    return ""


def deb_field(deb: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(deb), field]).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if not manifest_path.is_file():
    fail(f"missing manifest: {manifest_path}")

try:
    manifest = json.loads(manifest_path.read_text())
except json.JSONDecodeError as err:
    fail(f"manifest is not valid JSON: {err}")

if manifest.get("manifest_version") != 1:
    fail("manifest_version must be 1")

expected_commit = run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"]).strip()
if manifest.get("phase_commit") != expected_commit:
    fail("manifest phase_commit does not match HEAD")

rustc_vv = run(["rustc", "-Vv"])
cargo_vv = run(["cargo", "-Vv"])
if release(rustc_vv) != EXPECTED_RELEASE:
    fail(f"active rustc is not pinned {EXPECTED_RELEASE}")
if release(cargo_vv) != EXPECTED_RELEASE:
    fail(f"active cargo is not pinned {EXPECTED_RELEASE}")

toolchain = manifest.get("toolchain")
if not isinstance(toolchain, dict):
    fail("manifest toolchain must be an object")
if toolchain.get("rustc_vv") != rustc_vv:
    fail("manifest rustc -Vv output does not match active pinned toolchain")
if toolchain.get("cargo_vv") != cargo_vv:
    fail("manifest cargo -Vv output does not match active pinned toolchain")

source_package = run(
    ["dpkg-parsechangelog", f"-l{safe_dir / 'debian' / 'changelog'}", "-SSource"]
).strip()
if manifest.get("source_package_name") != source_package:
    fail("manifest source_package_name does not match debian/changelog")

debs = sorted(dist_dir.glob("*.deb"), key=lambda path: path.name)
expected_packages = [
    {
        "package_name": deb_field(deb, "Package"),
        "source_package_name": source_package,
        "architecture": deb_field(deb, "Architecture"),
        "version": deb_field(deb, "Version"),
        "filename": deb.name,
        "sha256": sha256(deb),
    }
    for deb in debs
]

actual_packages = manifest.get("packages")
if not isinstance(actual_packages, list):
    fail("manifest packages must be a list")
actual_packages = sorted(actual_packages, key=lambda item: item.get("filename", ""))
if actual_packages != expected_packages:
    fail("manifest packages do not match built .deb metadata and SHA256 values")
PY

expected_symbols="$(mktemp)"
trap 'rm -f "${expected_symbols}"' EXIT
python3 - "${SAFE_DIR}" >"${expected_symbols}" <<'PY'
from pathlib import Path
import sys

safe_dir = Path(sys.argv[1])
vers = (safe_dir / "abi" / "libgcrypt.vers").read_text().splitlines()
orig = (safe_dir.parent / "original" / "libgcrypt20-1.10.3" / "debian" / "libgcrypt20.symbols").read_text().splitlines()

minvers = {"gcry_md_get": "1.10.0", "gcry_pk_register": "1.10.0"}
for line in orig[2:]:
    if not line.startswith(" "):
        continue
    parts = line.split()
    if len(parts) >= 2 and "@GCRYPT_1.6" in parts[0]:
        minvers.setdefault(parts[0].split("@", 1)[0], parts[1])

symbols = []
in_global = False
for line in vers:
    stripped = line.strip()
    if stripped.startswith("global:"):
        in_global = True
        continue
    if stripped.startswith("local:"):
        break
    if not in_global or not stripped or stripped.startswith("#"):
        continue
    for token in stripped.split(";"):
        symbol = token.strip()
        if symbol:
            symbols.append(symbol)

print("libgcrypt.so.20 libgcrypt20 #MINVER#")
print("* Build-Depends-Package: libgcrypt20-dev")
print(" GCRYPT_1.6@GCRYPT_1.6 1.10.0")
for symbol in symbols:
    print(f" {symbol}@GCRYPT_1.6 {minvers[symbol]}")
PY

cmp -s "${SAFE_DIR}/debian/libgcrypt20.symbols" "${expected_symbols}" \
  || fail "safe/debian/libgcrypt20.symbols does not match safe/abi/libgcrypt.vers"

grep -q ' gcry_md_get@GCRYPT_1.6 ' "${SAFE_DIR}/debian/libgcrypt20.symbols" \
  || fail "gcry_md_get missing from symbols file"
grep -q ' gcry_pk_register@GCRYPT_1.6 ' "${SAFE_DIR}/debian/libgcrypt20.symbols" \
  || fail "gcry_pk_register missing from symbols file"

runtime_pkg="$(dpkg-deb -f "${runtime_deb}" Package)"
runtime_multiarch="$(dpkg-deb -f "${runtime_deb}" Multi-Arch)"
runtime_predepends="$(dpkg-deb -f "${runtime_deb}" Pre-Depends)"
runtime_depends="$(dpkg-deb -f "${runtime_deb}" Depends)"
dev_pkg="$(dpkg-deb -f "${dev_deb}" Package)"
dev_depends="$(dpkg-deb -f "${dev_deb}" Depends)"
dev_provides="$(dpkg-deb -f "${dev_deb}" Provides)"
dev_conflicts="$(dpkg-deb -f "${dev_deb}" Conflicts)"

[[ "${runtime_pkg}" == "libgcrypt20" ]] || fail "unexpected runtime package name: ${runtime_pkg}"
[[ "${runtime_multiarch}" == "same" ]] || fail "runtime Multi-Arch must be same"
[[ -n "${runtime_predepends}" ]] || fail "runtime Pre-Depends must be non-empty"
grep -Eq '(^|, )libc6([ ,]|$)' <<<"${runtime_depends}" \
  || fail "runtime Depends must include libc6"
grep -Eq '(^|, )libgpg-error0[^ ,]*([ ,]|$)' <<<"${runtime_depends}" \
  || fail "runtime Depends must include libgpg-error0"

[[ "${dev_pkg}" == "libgcrypt20-dev" ]] || fail "unexpected dev package name: ${dev_pkg}"
grep -Eq '(^|, )libgcrypt-dev([ ,]|$)' <<<"${dev_provides}" \
  || fail "dev package must provide libgcrypt-dev"
grep -Eq '(^|, )libgcrypt-dev([ ,]|$)' <<<"${dev_conflicts}" \
  || fail "dev package must conflict with libgcrypt-dev"
grep -Fq 'libc6-dev | libc-dev' <<<"${dev_depends}" \
  || fail "dev Depends must include libc6-dev | libc-dev"
grep -Eq 'libgcrypt20 \(= .+\)' <<<"${dev_depends}" \
  || fail "dev Depends must include libgcrypt20 (= \${binary:Version})"
grep -Eq '(^|, )libgpg-error-dev([ ,]|$)' <<<"${dev_depends}" \
  || fail "dev Depends must include libgpg-error-dev"

runtime_listing="$(dpkg-deb -c "${runtime_deb}")"
dev_listing="$(dpkg-deb -c "${dev_deb}")"

for pattern in \
  '/usr/lib/.*/libgcrypt\.so\.20$' \
  '/usr/lib/.*/libgcrypt\.so\.20\.4\.3$' \
  '/usr/share/libgcrypt20/clean-up-unmanaged-libraries$' \
  '/usr/share/doc/libgcrypt20/AUTHORS(\.gz)?$' \
  '/usr/share/doc/libgcrypt20/NEWS(\.gz)?$' \
  '/usr/share/doc/libgcrypt20/README(\.gz)?$' \
  '/usr/share/doc/libgcrypt20/THANKS(\.gz)?$'
do
  grep -Eq "${pattern}" <<<"${runtime_listing}" || fail "runtime package missing ${pattern}"
done

for pattern in \
  '/usr/bin/dumpsexp$' \
  '/usr/bin/hmac256$' \
  '/usr/bin/mpicalc$' \
  '/usr/bin/libgcrypt-config$' \
  '/usr/include/gcrypt\.h$' \
  '/usr/lib/.*/libgcrypt\.so$' \
  '/usr/lib/.*/libgcrypt\.a$' \
  '/usr/lib/.*/pkgconfig/libgcrypt\.pc$' \
  '/usr/share/aclocal/libgcrypt\.m4$' \
  '/usr/share/man/man8/dumpsexp\.8(\.gz)?$' \
  '/usr/share/man/man1/hmac256\.1(\.gz)?$' \
  '/usr/share/man/man1/libgcrypt-config\.1(\.gz)?$'
do
  grep -Eq "${pattern}" <<<"${dev_listing}" || fail "dev package missing ${pattern}"
done

for unexpected in '/usr/bin/getrandom$' '/usr/sbin/gcryptrnd$'; do
  grep -Eq "${unexpected}" <<<"${runtime_listing}${dev_listing}" && fail "unexpected payload entry ${unexpected}"
done

echo "check-deb-metadata: ok"

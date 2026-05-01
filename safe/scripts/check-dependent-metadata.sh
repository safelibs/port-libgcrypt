#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

python3 - "${REPO_DIR}" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

repo = Path(sys.argv[1])
metadata = repo / "safe" / "tests" / "dependents" / "metadata"


def fail(message: str) -> None:
    raise SystemExit(f"check-dependent-metadata: {message}")


def load(rel: str):
    path = repo / rel
    if not path.is_file():
        fail(f"missing {rel}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as err:
        fail(f"{rel} is not valid JSON: {err}")


def require_file(rel: str, executable: bool = False) -> None:
    path = repo / rel
    if not path.is_file():
        fail(f"referenced path does not exist: {rel}")
    if executable and not os.access(path, os.X_OK):
        fail(f"referenced scenario is not executable: {rel}")


dependents = load("dependents.json")
manifest = load("safe/tests/dependents/metadata/matrix-manifest.json")
evidence = load("safe/tests/dependents/metadata/package-evidence.noble.json")
install_lock = load("safe/tests/dependents/metadata/install-packages.noble.lock")
safe_lock = load("safe/tests/dependents/metadata/safe-debs.noble.lock")

expected_baseline = {
    "libapt-pkg6.0t64",
    "gpg",
    "gnome-keyring",
    "libssh-gcrypt-4",
    "libxmlsec1t64-gcrypt",
    "munge",
    "aircrack-ng",
    "wireshark-common",
}
expected_new = {
    "gpgv",
    "gpgsm",
    "seccure",
    "pdfgrep",
    "rng-tools5",
    "libotr5-bin",
    "tcplay",
}
expected_libraries = {
    "libapt-pkg6.0t64",
    "libssh-gcrypt-4",
    "libxmlsec1t64-gcrypt",
}

dep_rows = dependents.get("dependents")
if not isinstance(dep_rows, list):
    fail("dependents.json dependents must be a list")
dep_packages = [row.get("binary_package") for row in dep_rows]
if len(dep_packages) != 15 or len(set(dep_packages)) != 15:
    fail("dependents.json must contain 15 rows with 15 unique binary_package values")
if not expected_baseline.issubset(dep_packages):
    fail("dependents.json no longer preserves all 8 baseline package identities")
if not expected_new.issubset(dep_packages):
    fail("dependents.json is missing one or more phase 10 executable packages")

manifest_rows = manifest.get("rows")
if not isinstance(manifest_rows, list):
    fail("matrix manifest rows must be a list")
manifest_packages = [row.get("binary_package") for row in manifest_rows]
if len(manifest_packages) != 15 or len(set(manifest_packages)) != 15:
    fail("matrix manifest must contain 15 rows with 15 unique binary_package values")
if set(manifest_packages) != set(dep_packages):
    fail("matrix manifest package set differs from dependents.json")

library_rows = [row for row in manifest_rows if row.get("kind") == "library_exception"]
exec_rows = [row for row in manifest_rows if row.get("kind") == "executable_application"]
if {row["binary_package"] for row in library_rows} != expected_libraries:
    fail("matrix manifest must retain exactly the 3 library-flavored exceptions")
if len(exec_rows) != 12:
    fail("matrix manifest must contain exactly 12 executable application rows")
if set(manifest.get("library_exception_packages", [])) != expected_libraries:
    fail("library_exception_packages field drifted")
if set(manifest.get("executable_application_packages", [])) != {
    row["binary_package"] for row in exec_rows
}:
    fail("executable_application_packages field drifted")

for row in manifest_rows:
    if row.get("kind") == "library_exception":
        probe = row.get("compile_probe")
        if not isinstance(probe, dict):
            fail(f"{row['binary_package']} is missing compile_probe metadata")
        require_file(probe["source"])
    else:
        scenario = row.get("scenario")
        if not scenario:
            fail(f"{row['binary_package']} is missing scenario path")
        require_file(scenario, executable=True)
    for fixture in row.get("fixtures", []):
        require_file(fixture)
    for helper in row.get("helpers", []):
        require_file(helper)
    loader = row.get("loader_check", {})
    if not loader.get("binary"):
        fail(f"{row['binary_package']} is missing loader_check binary")

for rel in (
    "safe/tests/dependents/probes/apt-hashes-test.cpp",
    "safe/tests/dependents/probes/libssh-test.c",
    "safe/tests/dependents/probes/xmlsec-gcrypt-verify-rsa.c",
):
    require_file(rel)

for rel in (
    "safe/tests/dependents/metadata/base-image.noble.digest",
    "safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources",
    "safe/tests/dependents/metadata/install-packages.noble.lock",
    "safe/tests/dependents/metadata/safe-debs.noble.lock",
):
    require_file(rel)

base_ref = (metadata / "base-image.noble.digest").read_text().strip()
if not re.fullmatch(r"ubuntu:24[.]04@sha256:[0-9a-f]{64}", base_ref):
    fail("base image digest must be an ubuntu:24.04@sha256 reference")
base_digest = base_ref.split("@", 1)[1]

sources = (metadata / "ubuntu-snapshot.noble.sources").read_text()
if "snapshot.ubuntu.com/ubuntu/20260409T000000Z/" not in sources:
    fail("snapshot sources must point at the committed Noble snapshot")
for forbidden in ("archive.ubuntu.com", "security.ubuntu.com"):
    if forbidden in sources:
        fail(f"snapshot sources must not reference mutable {forbidden}")
if "Types: deb\n" not in sources or "Suites: noble noble-updates noble-backports noble-security" not in sources:
    fail("snapshot sources must cover Noble binary pockets")

if install_lock.get("lock_version") != 1:
    fail("install lock version must be 1")
if install_lock.get("base_image", {}).get("reference") != base_ref:
    fail("install lock base image reference differs from base-image digest file")
if install_lock.get("snapshot", {}).get("source_file") != "safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources":
    fail("install lock snapshot source file identity drifted")

packages = install_lock.get("packages")
if not isinstance(packages, list) or len(packages) < 100:
    fail("install lock does not look like a full package closure")
lock_by_name = {item.get("package"): item for item in packages}
if len(lock_by_name) != len(packages):
    fail("install lock contains duplicate package names")
for required in set(dep_packages) | {"libgcrypt20", "libgcrypt20-dev", "build-essential", "pkg-config"}:
    if required not in lock_by_name:
        fail(f"install lock is missing required package {required}")
for item in packages:
    origin = item.get("origin")
    implementation = item.get("implementation")
    if origin not in {"base-image", "ubuntu-snapshot"}:
        fail(f"invalid install lock origin for {item.get('package')}: {origin}")
    if implementation not in {"both", "original"}:
        fail(f"invalid install lock implementation for {item.get('package')}: {implementation}")
    for field in ("package", "architecture", "version", "source_package", "source_version"):
        if not item.get(field):
            fail(f"install lock package is missing {field}")
    if origin == "base-image" and item.get("base_image_digest") != base_digest:
        fail(f"base-image lock entry lacks pinned digest: {item['package']}")
    if origin == "ubuntu-snapshot":
        for field in ("snapshot_id", "snapshot_source_file", "snapshot_source_sha256"):
            if not item.get(field):
                fail(f"snapshot lock entry lacks {field}: {item['package']}")

requested = install_lock.get("requested_packages")
if not isinstance(requested, list) or not requested:
    fail("install lock requested_packages must be a non-empty list")
for item in requested:
    if not item.get("package") or not item.get("version"):
        fail("requested_packages entries must pin package and version")
    if item.get("implementation") not in {"both", "original"}:
        fail("requested_packages entries must identify implementation")

if safe_lock.get("lock_version") != 1:
    fail("safe deb lock version must be 1")
safe_packages = safe_lock.get("packages")
if not isinstance(safe_packages, list) or len(safe_packages) != 2:
    fail("safe deb lock must contain exactly two package policies")
if {item.get("package_name") for item in safe_packages} != {"libgcrypt20", "libgcrypt20-dev"}:
    fail("safe deb lock must cover only libgcrypt20 and libgcrypt20-dev")
for item in safe_packages:
    if item.get("origin") != "local-safe-deb" or item.get("implementation") != "safe":
        fail("safe deb lock entries must be local-safe-deb safe policies")
    if "sha256" in item:
        fail("safe deb lock must not commit rebuilt .deb SHA256 values")
    for field in ("package_name", "architecture", "source_package", "source_version", "version", "file_glob"):
        if not item.get(field):
            fail(f"safe deb lock entry missing {field}")
    if item["source_version"] != "1.10.3+safe1" or item["version"] != "1.10.3+safe1":
        fail("safe deb lock version must match safe/debian/changelog")

evidence_rows = evidence.get("dependents")
if not isinstance(evidence_rows, list) or len(evidence_rows) != 15:
    fail("package evidence must contain 15 dependent rows")
if {row.get("binary_package") for row in evidence_rows} != set(dep_packages):
    fail("package evidence package set differs from dependents.json")

print("check-dependent-metadata: ok")
PY

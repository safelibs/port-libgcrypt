#!/usr/bin/env python3
import glob
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"validate-installed-packages: {message}")


def run(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True)
    except subprocess.CalledProcessError as err:
        fail(f"command failed: {' '.join(args)}: {err}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dpkg_field(deb: Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(deb), field]).strip()


def installed_packages() -> dict[str, dict[str, str]]:
    fmt = "${binary:Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\n"
    packages: dict[str, dict[str, str]] = {}
    for line in run(["dpkg-query", "-W", f"-f={fmt}"]).splitlines():
        binary, arch, version, source_package, source_version = line.split("\t")
        name = binary.split(":", 1)[0]
        if name in packages:
            fail(f"duplicate installed package name in validation set: {name}")
        packages[name] = {
            "binary_package": binary,
            "architecture": arch,
            "version": version,
            "source_package": source_package or name,
            "source_version": source_version or version,
        }
    return packages


def require_metadata(actual: dict[str, str], expected: dict[str, str], label: str) -> None:
    for field, expected_field in (
        ("architecture", "architecture"),
        ("version", "version"),
        ("source_package", "source_package"),
        ("source_version", "source_version"),
    ):
        if actual.get(field) != expected.get(expected_field):
            fail(
                f"{label} {field} mismatch: {actual.get(field)!r} != "
                f"{expected.get(expected_field)!r}"
            )


def validate_safe_manifest(
    repo_dir: Path,
    safe_lock: dict,
    actual: dict[str, dict[str, str]],
) -> None:
    manifest_path = repo_dir / "safe" / "dist" / "safe-debs.manifest.json"
    if not manifest_path.is_file():
        fail(f"missing safe deb manifest: {manifest_path}")

    manifest = json.loads(manifest_path.read_text())
    if manifest.get("manifest_version") != 1:
        fail("safe deb manifest version must be 1")

    expected_commit = os.environ.get("PHASE_COMMIT", "")
    if not expected_commit:
        fail("PHASE_COMMIT is required for safe validation")
    if manifest.get("phase_commit") != expected_commit:
        fail("safe deb manifest phase_commit is stale")

    expected_tag = os.environ.get("PHASE_TAG") or None
    if manifest.get("phase_tag") != expected_tag:
        fail("safe deb manifest phase_tag does not match selected phase tag")

    packages = manifest.get("packages")
    if not isinstance(packages, list):
        fail("safe deb manifest packages must be a list")

    by_name = {item.get("package_name"): item for item in packages}
    if set(by_name) != {item["package_name"] for item in safe_lock["packages"]}:
        fail("safe deb manifest package names do not match safe-debs lock")

    for policy in safe_lock["packages"]:
        name = policy["package_name"]
        if name not in actual:
            fail(f"safe package is not installed: {name}")
        require_metadata(actual[name], policy, name)

        matches = [Path(path) for path in glob.glob(str(repo_dir / policy["file_glob"]))]
        if len(matches) != 1:
            fail(f"{name} file_glob must match exactly one file")

        deb = matches[0]
        manifest_item = by_name[name]
        expected_item = {
            "package_name": dpkg_field(deb, "Package"),
            "source_package_name": policy["source_package"],
            "source_version": policy["source_version"],
            "architecture": dpkg_field(deb, "Architecture"),
            "version": dpkg_field(deb, "Version"),
            "filename": deb.name,
            "sha256": sha256(deb),
        }
        for key, value in expected_item.items():
            if manifest_item.get(key) != value:
                fail(f"safe deb manifest {name} {key} mismatch")


def main() -> None:
    implementation = os.environ.get("IMPLEMENTATION")
    if implementation not in {"original", "safe"}:
        fail("IMPLEMENTATION must be original or safe")

    repo_dir = Path(__file__).resolve().parents[3]
    metadata_dir = repo_dir / "safe" / "tests" / "dependents" / "metadata"
    install_lock = json.loads((metadata_dir / "install-packages.noble.lock").read_text())
    safe_lock = json.loads((metadata_dir / "safe-debs.noble.lock").read_text())
    actual = installed_packages()

    install_by_name = {item["package"]: item for item in install_lock["packages"]}
    libgcrypt_names = {"libgcrypt20", "libgcrypt20-dev"}

    if implementation == "original":
        expected_names = set(install_by_name)
    else:
        expected_names = set(install_by_name) - libgcrypt_names
        expected_names.update(item["package_name"] for item in safe_lock["packages"])

    actual_names = set(actual)
    if actual_names != expected_names:
        extra = sorted(actual_names - expected_names)
        missing = sorted(expected_names - actual_names)
        fail(f"installed package set mismatch; extra={extra} missing={missing}")

    for name in sorted(expected_names):
        if implementation == "safe" and name in libgcrypt_names:
            continue
        require_metadata(actual[name], install_by_name[name], name)

    if implementation == "safe":
        validate_safe_manifest(repo_dir, safe_lock, actual)

    print(f"validate-installed-packages: ok ({implementation})")


if __name__ == "__main__":
    main()

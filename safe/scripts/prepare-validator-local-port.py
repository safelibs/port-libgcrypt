#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse


CANONICAL_PACKAGES = ("libgcrypt20", "libgcrypt20-dev")
LIBRARY = "libgcrypt"
LOCAL_RELEASE_TAG = "local-libgcrypt-safe"


def fail(message: str) -> None:
    raise SystemExit(f"prepare-validator-local-port: {message}")


def run(args: list[str], *, cwd: Path | None = None) -> str:
    try:
        return subprocess.check_output(args, cwd=cwd, text=True).strip()
    except subprocess.CalledProcessError as exc:
        fail(f"command failed: {' '.join(args)}: {exc}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, *, label: str) -> dict:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        fail(f"missing {label}: {path}")
    except json.JSONDecodeError as exc:
        fail(f"{label} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        fail(f"{label} must be a JSON object: {path}")
    return data


def require_string(data: dict, key: str, *, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{context} missing required string field {key}")
    return value


def require_manifest_fields(manifest: dict) -> None:
    for key in ("phase_commit", "phase_tag"):
        require_string(manifest, key, context="manifest")
    toolchain = manifest.get("toolchain")
    if not isinstance(toolchain, dict):
        fail("manifest missing required object field toolchain")
    require_string(toolchain, "rustc_vv", context="manifest toolchain")
    require_string(toolchain, "cargo_vv", context="manifest toolchain")

    packages = manifest.get("packages")
    if not isinstance(packages, list):
        fail("manifest packages must be a list")
    for index, item in enumerate(packages, start=1):
        if not isinstance(item, dict):
            fail(f"manifest package #{index} must be an object")
        for key in (
            "package_name",
            "filename",
            "architecture",
            "version",
            "source_package_name",
            "source_version",
            "sha256",
        ):
            require_string(item, key, context=f"manifest package #{index}")


def repository_name(repo_dir: Path) -> str:
    url = run(["git", "-C", str(repo_dir), "remote", "get-url", "origin"])
    if url.startswith("git@github.com:"):
        owner_name = url.split(":", 1)[1]
    else:
        parsed = urlparse(url)
        owner_name = parsed.path.lstrip("/")
    if owner_name.endswith(".git"):
        owner_name = owner_name[:-4]
    parts = [part for part in owner_name.split("/") if part]
    if len(parts) < 2:
        fail(f"could not derive GitHub owner/name from origin remote: {url}")
    return "/".join(parts[-2:])


def validate_lock_policy(lock: dict) -> list[dict]:
    if lock.get("lock_version") != 1:
        fail("safe-debs lock_version must be 1")
    policies = lock.get("packages")
    if not isinstance(policies, list):
        fail("safe-debs packages must be a list")
    by_name = {item.get("package_name"): item for item in policies if isinstance(item, dict)}
    if set(by_name) != set(CANONICAL_PACKAGES):
        fail("safe-debs lock must contain exactly libgcrypt20 and libgcrypt20-dev")
    ordered = []
    for name in CANONICAL_PACKAGES:
        policy = by_name[name]
        if policy.get("origin") != "local-safe-deb" or policy.get("implementation") != "safe":
            fail(f"{name} policy must be a local safe deb")
        for key in ("package_name", "architecture", "source_package", "source_version", "version", "file_glob"):
            require_string(policy, key, context=f"safe-debs policy {name}")
        if "sha256" in policy:
            fail("safe-debs policy must not commit rebuilt sha256 values")
        ordered.append(policy)
    return ordered


def validate_manifest_packages(
    *,
    repo_dir: Path,
    dist_dir: Path,
    manifest: dict,
    policies: list[dict],
) -> list[dict]:
    packages = manifest["packages"]
    by_name = {item["package_name"]: item for item in packages}
    if set(by_name) != set(CANONICAL_PACKAGES) or len(packages) != len(CANONICAL_PACKAGES):
        fail("manifest must contain exactly libgcrypt20 and libgcrypt20-dev")

    prepared: list[dict] = []
    for policy in policies:
        name = policy["package_name"]
        item = by_name[name]
        expected = {
            "package_name": policy["package_name"],
            "architecture": policy["architecture"],
            "version": policy["version"],
            "source_package_name": policy["source_package"],
            "source_version": policy["source_version"],
        }
        for key, value in expected.items():
            if item.get(key) != value:
                fail(f"manifest {name} {key} mismatch: {item.get(key)!r} != {value!r}")

        matches = [Path(path) for path in glob.glob(str(repo_dir / policy["file_glob"]))]
        if len(matches) != 1:
            fail(f"{policy['file_glob']} must match exactly one .deb")
        deb = matches[0]
        if deb.parent.resolve() != dist_dir.resolve():
            fail(f"{name} file_glob resolved outside requested dist: {deb}")
        if item["filename"] != deb.name:
            fail(f"manifest {name} filename mismatch: {item['filename']!r} != {deb.name!r}")
        if item["sha256"] != sha256(deb):
            fail(f"manifest {name} sha256 does not match {deb}")
        prepared.append(
            {
                "package": name,
                "filename": deb.name,
                "architecture": item["architecture"],
                "sha256": item["sha256"],
                "version": item["version"],
                "size": deb.stat().st_size,
                "source": deb,
            }
        )
    return prepared


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validator-dir", required=True, type=Path)
    parser.add_argument("--dist", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_dir = Path(__file__).resolve().parents[2]
    validator_dir = args.validator_dir.resolve()
    dist_dir = args.dist.resolve()
    output_root = args.output_root.resolve()

    if not (validator_dir / ".git").is_dir():
        fail(f"validator checkout is missing: {validator_dir}")
    if not dist_dir.is_dir():
        fail(f"dist directory is missing: {dist_dir}")

    manifest = load_json(dist_dir / "safe-debs.manifest.json", label="safe deb manifest")
    require_manifest_fields(manifest)
    lock = load_json(
        repo_dir / "safe" / "tests" / "dependents" / "metadata" / "safe-debs.noble.lock",
        label="safe-debs lock",
    )
    policies = validate_lock_policy(lock)
    prepared = validate_manifest_packages(
        repo_dir=repo_dir,
        dist_dir=dist_dir,
        manifest=manifest,
        policies=policies,
    )

    override_dir = output_root / "override-debs" / LIBRARY
    proof_dir = output_root / "proof"
    if override_dir.exists():
        shutil.rmtree(override_dir)
    override_dir.mkdir(parents=True, exist_ok=True)
    proof_dir.mkdir(parents=True, exist_ok=True)

    deb_entries = []
    for item in prepared:
        source = item.pop("source")
        dest = override_dir / item["filename"]
        shutil.copy2(source, dest)
        if dest.stat().st_size != item["size"]:
            fail(f"copied size mismatch for {dest}")
        if sha256(dest) != item["sha256"]:
            fail(f"copied sha256 mismatch for {dest}")
        deb_entries.append(dict(item))

    lock_payload = {
        "schema_version": 1,
        "mode": "port",
        "libraries": [
            {
                "library": LIBRARY,
                "repository": repository_name(repo_dir),
                "release_tag": LOCAL_RELEASE_TAG,
                "tag_ref": f"refs/tags/{LOCAL_RELEASE_TAG}",
                "commit": run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"]),
                "debs": deb_entries,
                "unported_original_packages": [],
            }
        ],
    }
    write_json(proof_dir / "local-port-debs-lock.json", lock_payload)
    print(f"prepare-validator-local-port: wrote {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

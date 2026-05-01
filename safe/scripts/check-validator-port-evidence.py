#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


CANONICAL_PACKAGES = ("libgcrypt20", "libgcrypt20-dev")


def fail(message: str) -> None:
    raise SystemExit(f"check-validator-port-evidence: {message}")


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


def require_int(data: dict, key: str, *, context: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{context} missing required integer field {key}")
    return value


def load_port_lock(path: Path, *, library: str) -> dict:
    payload = load_json(path, label="port lock")
    if payload.get("schema_version") != 1 or payload.get("mode") != "port":
        fail("port lock must have schema_version 1 and mode port")
    libraries = payload.get("libraries")
    if not isinstance(libraries, list):
        fail("port lock libraries must be a list")
    matches = [item for item in libraries if isinstance(item, dict) and item.get("library") == library]
    if len(matches) != 1:
        fail(f"port lock must contain exactly one {library} entry")
    entry = matches[0]
    for key in ("repository", "release_tag", "tag_ref", "commit"):
        require_string(entry, key, context=f"port lock {library}")
    debs = entry.get("debs")
    if not isinstance(debs, list):
        fail(f"port lock {library} debs must be a list")
    by_package = {}
    for deb in debs:
        if not isinstance(deb, dict):
            fail(f"port lock {library} deb entries must be objects")
        package = require_string(deb, "package", context=f"port lock {library} deb")
        if package in by_package:
            fail(f"duplicate port lock deb package: {package}")
        for key in ("filename", "architecture", "sha256", "version"):
            require_string(deb, key, context=f"port lock {library}/{package}")
        require_int(deb, "size", context=f"port lock {library}/{package}")
        by_package[package] = deb
    if tuple(by_package) != CANONICAL_PACKAGES:
        fail("port lock debs must be in canonical libgcrypt20, libgcrypt20-dev order")
    if entry.get("unported_original_packages") != []:
        fail("local libgcrypt port lock must have no unported original packages")
    return entry


def expected_debs(lock_entry: dict) -> list[dict]:
    return [deb for deb in lock_entry["debs"]]


def validate_override_root(override_root: Path, *, library: str, lock_entry: dict) -> None:
    leaf = override_root / library
    if not leaf.is_dir():
        fail(f"missing override deb leaf: {leaf}")
    expected = {deb["filename"]: deb for deb in expected_debs(lock_entry)}
    actual = sorted(path for path in leaf.glob("*.deb") if path.is_file())
    actual_names = {path.name for path in actual}
    if actual_names != set(expected):
        fail(
            "override deb filenames do not match lock: "
            f"missing={sorted(set(expected) - actual_names)} extra={sorted(actual_names - set(expected))}"
        )
    for path in actual:
        deb = expected[path.name]
        if path.stat().st_size != deb["size"]:
            fail(f"override deb size mismatch: {path.name}")
        if sha256(path) != deb["sha256"]:
            fail(f"override deb sha256 mismatch: {path.name}")


def lock_port_debs_for_result(lock_entry: dict) -> list[dict]:
    return [
        {
            "package": deb["package"],
            "filename": deb["filename"],
            "architecture": deb["architecture"],
            "sha256": deb["sha256"],
            "size": deb["size"],
        }
        for deb in expected_debs(lock_entry)
    ]


def lock_installed_packages_for_result(lock_entry: dict) -> list[dict]:
    return [
        {
            "package": deb["package"],
            "version": deb["version"],
            "architecture": deb["architecture"],
            "filename": deb["filename"],
        }
        for deb in expected_debs(lock_entry)
    ]


def validate_result(result_path: Path, *, lock_entry: dict) -> None:
    result = load_json(result_path, label="port result")
    if result.get("status") == "skipped":
        return
    if result.get("mode") != "port":
        fail(f"{result_path} is not a port-mode result")
    if result.get("override_debs_installed") is not True:
        fail(f"{result_path} did not prove override deb installation")
    if result.get("port_repository") != lock_entry["repository"]:
        fail(f"{result_path} port_repository is stale")
    if result.get("port_commit") != lock_entry["commit"]:
        fail(f"{result_path} port_commit is stale")
    if result.get("port_release_tag") != lock_entry["release_tag"]:
        fail(f"{result_path} port_release_tag is stale")
    if result.get("port_tag_ref") != lock_entry["tag_ref"]:
        fail(f"{result_path} port_tag_ref is stale")
    if result.get("unported_original_packages") != []:
        fail(f"{result_path} unexpectedly allowed original libgcrypt packages")
    if result.get("port_debs") != lock_port_debs_for_result(lock_entry):
        fail(f"{result_path} port_debs do not match lock")
    if result.get("override_installed_packages") != lock_installed_packages_for_result(lock_entry):
        fail(f"{result_path} override_installed_packages do not match lock")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, action="append", type=Path)
    parser.add_argument("--port-lock", required=True, type=Path)
    parser.add_argument("--override-root", required=True, type=Path)
    parser.add_argument("--library", default="libgcrypt")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lock_entry = load_port_lock(args.port_lock, library=args.library)
    validate_override_root(args.override_root, library=args.library, lock_entry=lock_entry)

    for root in args.artifact_root:
        result_dir = root / "port" / "results" / args.library
        if not result_dir.is_dir():
            fail(f"artifact root has no port results for {args.library}: {root}")
        result_paths = sorted(path for path in result_dir.glob("*.json") if path.name != "summary.json")
        if not result_paths:
            fail(f"artifact root contains no port testcase results: {root}")
        for result_path in result_paths:
            validate_result(result_path, lock_entry=lock_entry)

    print("check-validator-port-evidence: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

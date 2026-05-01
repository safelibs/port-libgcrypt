#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
export VALIDATOR_LIBGCRYPT_SCRIPT_DIR="${SCRIPT_DIR}"
export VALIDATOR_LIBGCRYPT_REPO_DIR="${REPO_DIR}"

exec python3 - "$@" <<'PY'
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


LIBRARY = "libgcrypt"
CANONICAL_PACKAGES = ("libgcrypt20", "libgcrypt20-dev")
APT_PACKAGES = list(CANONICAL_PACKAGES)
DETERMINISTIC_TIMESTAMP = "1970-01-01T00:00:00Z"
IMAGE_TAG = "safelibs-validator-libgcrypt"
SCRIPT_DIR = Path(os.environ["VALIDATOR_LIBGCRYPT_SCRIPT_DIR"]).resolve()
REPO_DIR = Path(os.environ["VALIDATOR_LIBGCRYPT_REPO_DIR"]).resolve()
SKIP_FILE = SCRIPT_DIR / "validator-libgcrypt-skips.json"
HEADER_DIRECTIVE_RE = re.compile(r"^#\s*@([a-z][a-z_-]*)\s*:\s*(.*)$")
ALLOWED_HEADER_FIELDS = {"testcase", "title", "description", "timeout", "tags", "client"}
REQUIRED_HEADER_FIELDS = {"testcase", "title", "description", "timeout", "tags"}
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$")


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    description: str
    timeout: int
    tags: tuple[str, ...]
    kind: str
    script_path: Path
    container_path: str
    client: str | None = None


@dataclass(frozen=True)
class SkipEntry:
    testcase_id: str
    mode: str
    validator_commit: str
    reason: str
    report_section: str


@dataclass(frozen=True)
class RunOutcome:
    exit_code: int
    timed_out: bool = False


def fail(message: str) -> None:
    raise RunnerError(message)


def shell_join(args: list[str]) -> str:
    import shlex

    return " ".join(shlex.quote(str(arg)) for arg in args)


def run_text(args: list[str], *, cwd: Path | None = None) -> str:
    try:
        return subprocess.check_output(args, cwd=cwd, text=True).strip()
    except subprocess.CalledProcessError as exc:
        fail(f"command failed: {shell_join(args)}: {exc}")


def validator_commit(validator_dir: Path) -> str:
    return run_text(["git", "-C", str(validator_dir), "rev-parse", "HEAD"])


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


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


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


def mode_parts(mode: str) -> tuple[str, ...]:
    return () if mode == "original" else ("port",)


def artifact_path(artifact_root: Path, mode: str, *parts: str) -> Path:
    root = artifact_root.resolve(strict=False)
    target = root.joinpath(*mode_parts(mode), *parts).resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RunnerError(f"artifact path escapes artifact root: {target}") from exc
    return target


def result_path(artifact_root: Path, mode: str, case_id: str) -> Path:
    return artifact_path(artifact_root, mode, "results", LIBRARY, f"{case_id}.json")


def log_path(artifact_root: Path, mode: str, case_id: str) -> Path:
    return artifact_path(artifact_root, mode, "logs", LIBRARY, f"{case_id}.log")


def cast_path(artifact_root: Path, mode: str, case_id: str) -> Path:
    return artifact_path(artifact_root, mode, "casts", LIBRARY, f"{case_id}.cast")


def cleanup_selected_artifacts(
    *,
    artifact_root: Path,
    mode: str,
    selected_cases: list[Case],
    record_casts: bool,
) -> None:
    for case in selected_cases:
        for path in (
            result_path(artifact_root, mode, case.id),
            log_path(artifact_root, mode, case.id),
            cast_path(artifact_root, mode, case.id) if record_casts else None,
        ):
            if path is not None and path.exists():
                path.unlink()


def parse_header(script_path: Path, *, kind: str, validator_dir: Path) -> Case:
    current: dict[str, str] | None = None
    blocks: list[dict[str, str]] = []
    for raw_line in script_path.read_text().splitlines():
        line = raw_line.rstrip()
        if line.startswith("#!"):
            continue
        if not line:
            break
        if not line.startswith("#"):
            break
        match = HEADER_DIRECTIVE_RE.match(line)
        if match is None:
            continue
        key, value = match.group(1), match.group(2).strip()
        if key not in ALLOWED_HEADER_FIELDS:
            fail(f"unknown @{key} directive in {script_path}")
        if key == "testcase":
            if current is not None:
                blocks.append(current)
            current = {"testcase": value}
            continue
        if current is None:
            fail(f"@{key} directive precedes @testcase in {script_path}")
        if key in current:
            fail(f"duplicate @{key} directive in {script_path}")
        current[key] = value
    if current is not None:
        blocks.append(current)
    if len(blocks) != 1:
        fail(f"{script_path} must contain exactly one @testcase header block")
    block = blocks[0]
    missing = REQUIRED_HEADER_FIELDS - set(block)
    if missing:
        fail(f"{script_path} is missing required directives: {sorted(missing)}")
    case_id = block["testcase"].strip()
    if not CASE_ID_RE.fullmatch(case_id):
        fail(f"invalid testcase id in {script_path}: {case_id!r}")
    if case_id != script_path.stem:
        fail(f"testcase id {case_id!r} does not match script filename {script_path.name!r}")
    try:
        timeout = int(block["timeout"], 10)
    except ValueError as exc:
        raise RunnerError(f"@timeout must be an integer for {case_id}") from exc
    if timeout < 1 or timeout > 7200:
        fail(f"@timeout must be between 1 and 7200 for {case_id}")
    title = block["title"].strip()
    description = block["description"].strip()
    if not title or not description:
        fail(f"@title and @description must be non-empty for {case_id}")
    tags = tuple(tag.strip() for tag in block["tags"].split(",") if tag.strip())
    client = block.get("client", "").strip() or None
    if kind == "source" and client is not None:
        fail(f"source testcase must not define @client for {case_id}")
    if kind == "usage" and client is None:
        fail(f"usage testcase must define @client for {case_id}")
    rel = script_path.relative_to(validator_dir / "tests" / LIBRARY)
    return Case(
        id=case_id,
        title=title,
        description=description,
        timeout=timeout,
        tags=tags,
        kind=kind,
        script_path=script_path,
        container_path=f"/validator/tests/{LIBRARY}/{rel.as_posix()}",
        client=client,
    )


def enumerate_cases(validator_dir: Path) -> list[Case]:
    library_root = validator_dir / "tests" / LIBRARY
    cases: list[Case] = []
    for kind in ("source", "usage"):
        kind_dir = library_root / "tests" / "cases" / kind
        if not kind_dir.is_dir():
            continue
        for script_path in sorted(kind_dir.glob("*.sh")):
            if not script_path.is_file():
                continue
            if not os.access(script_path, os.X_OK):
                fail(f"testcase script is not executable: {script_path}")
            cases.append(parse_header(script_path, kind=kind, validator_dir=validator_dir))
    if not cases:
        fail(f"no {LIBRARY} cases found under {library_root}")
    ids = [case.id for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        fail(f"duplicate testcase IDs: {', '.join(duplicates)}")
    return cases


def select_cases(
    all_cases: list[Case],
    *,
    case_ids: list[str] | None,
    case_globs: list[str] | None,
    kind: str | None,
) -> list[Case]:
    selected = list(all_cases)
    if kind is not None:
        selected = [case for case in selected if case.kind == kind]
    if case_ids:
        wanted = set(case_ids)
        selected = [case for case in selected if case.id in wanted]
        found = {case.id for case in selected}
        missing = sorted(wanted - found)
        if missing:
            fail(f"unknown selected testcase IDs: {', '.join(missing)}")
    if case_globs:
        selected = [
            case
            for case in selected
            if any(fnmatch.fnmatchcase(case.id, pattern) for pattern in case_globs)
        ]
    if not selected:
        fail("selected zero libgcrypt testcases")
    return selected


def load_skips(*, validator_dir: Path, mode: str, selected_cases: list[Case], all_cases: list[Case]) -> list[SkipEntry]:
    commit = validator_commit(validator_dir)
    data = load_json(SKIP_FILE, label="validator skip file")
    if data.get("schema_version") != 1:
        fail("skip file schema_version must be 1")
    if data.get("validator_commit") != commit:
        fail("skip file validator_commit does not match checked-out validator HEAD")
    raw_skips = data.get("skips")
    if not isinstance(raw_skips, list):
        fail("skip file skips must be a list")
    all_ids = {case.id for case in all_cases}
    selected_ids = {case.id for case in selected_cases}
    active: list[SkipEntry] = []
    for index, raw in enumerate(raw_skips, start=1):
        if not isinstance(raw, dict):
            fail(f"skip entry #{index} must be an object")
        entry_commit = require_string(raw, "validator_commit", context=f"skip entry #{index}")
        if entry_commit != commit:
            fail(f"skip entry #{index} is for a different validator commit")
        entry_mode = require_string(raw, "mode", context=f"skip entry #{index}")
        if entry_mode not in {"original", "port"}:
            fail(f"skip entry #{index} mode must be original or port")
        testcase_id = require_string(raw, "testcase_id", context=f"skip entry #{index}")
        if not CASE_ID_RE.fullmatch(testcase_id):
            fail(f"skip entry #{index} testcase_id must name one exact testcase")
        reason = require_string(raw, "reason", context=f"skip entry #{index}")
        report_section = require_string(raw, "report_section", context=f"skip entry #{index}")
        if entry_mode == mode and testcase_id not in all_ids:
            fail(f"skip entry #{index} names unknown testcase {testcase_id}")
        if entry_mode == mode and testcase_id in selected_ids:
            active.append(
                SkipEntry(
                    testcase_id=testcase_id,
                    mode=entry_mode,
                    validator_commit=entry_commit,
                    reason=reason,
                    report_section=report_section,
                )
            )
    active_ids = [entry.testcase_id for entry in active]
    duplicates = sorted({case_id for case_id in active_ids if active_ids.count(case_id) > 1})
    if duplicates:
        fail(f"duplicate active skip entries: {', '.join(duplicates)}")
    return active


def load_port_lock(lock_path: Path, *, override_root: Path) -> dict:
    payload = load_json(lock_path, label="port deb lock")
    if payload.get("schema_version") != 1 or payload.get("mode") != "port":
        fail("port deb lock must have schema_version 1 and mode port")
    libraries = payload.get("libraries")
    if not isinstance(libraries, list):
        fail("port deb lock libraries must be a list")
    matches = [item for item in libraries if isinstance(item, dict) and item.get("library") == LIBRARY]
    if len(matches) != 1:
        fail(f"port deb lock must contain exactly one {LIBRARY} entry")
    entry = matches[0]
    metadata = {
        "repository": require_string(entry, "repository", context="port lock libgcrypt"),
        "tag_ref": require_string(entry, "tag_ref", context="port lock libgcrypt"),
        "commit": require_string(entry, "commit", context="port lock libgcrypt"),
        "release_tag": require_string(entry, "release_tag", context="port lock libgcrypt"),
        "unported_original_packages": entry.get("unported_original_packages"),
    }
    if metadata["tag_ref"] != f"refs/tags/{metadata['release_tag']}":
        fail("port lock tag_ref must equal refs/tags/<release_tag>")
    if metadata["unported_original_packages"] != []:
        fail("local libgcrypt port lock must have no unported original packages")
    raw_debs = entry.get("debs")
    if not isinstance(raw_debs, list):
        fail("port lock debs must be a list")
    by_package = {}
    for raw in raw_debs:
        if not isinstance(raw, dict):
            fail("port lock deb entries must be objects")
        package = require_string(raw, "package", context="port lock deb")
        if package in by_package:
            fail(f"duplicate port lock deb package: {package}")
        for key in ("filename", "architecture", "sha256", "version"):
            require_string(raw, key, context=f"port lock {package}")
        require_int(raw, "size", context=f"port lock {package}")
        by_package[package] = raw
    if tuple(by_package) != CANONICAL_PACKAGES:
        fail("port lock debs must be in canonical libgcrypt20, libgcrypt20-dev order")
    override_leaf = (override_root / LIBRARY).resolve()
    if not override_leaf.is_dir():
        fail(f"missing override deb leaf: {override_leaf}")
    expected_names = {by_package[name]["filename"] for name in CANONICAL_PACKAGES}
    actual_paths = sorted(path for path in override_leaf.glob("*.deb") if path.is_file())
    actual_names = {path.name for path in actual_paths}
    if actual_names != expected_names:
        fail(
            "override deb files do not match port lock: "
            f"missing={sorted(expected_names - actual_names)} extra={sorted(actual_names - expected_names)}"
        )
    ordered_debs = []
    for package in CANONICAL_PACKAGES:
        deb = by_package[package]
        path = override_leaf / deb["filename"]
        if path.stat().st_size != deb["size"]:
            fail(f"override deb size mismatch for {path.name}")
        if sha256(path) != deb["sha256"]:
            fail(f"override deb sha256 mismatch for {path.name}")
        ordered_debs.append(dict(deb))
    return {
        **metadata,
        "debs_with_versions": ordered_debs,
        "port_debs": [
            {
                "package": deb["package"],
                "filename": deb["filename"],
                "architecture": deb["architecture"],
                "sha256": deb["sha256"],
                "size": deb["size"],
            }
            for deb in ordered_debs
        ],
    }


def official_probe(validator_dir: Path) -> tuple[bool, str]:
    command = [
        "python3",
        str(validator_dir / "tools" / "testcases.py"),
        "--config",
        str(validator_dir / "repositories.yml"),
        "--tests-root",
        str(validator_dir / "tests"),
        "--list-summary",
        "--library",
        LIBRARY,
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode == 0, output


def run_official(
    *,
    validator_dir: Path,
    mode: str,
    artifact_root: Path,
    override_root: Path | None,
    port_lock: Path | None,
    record_casts: bool,
) -> int:
    command = [
        "bash",
        str(validator_dir / "test.sh"),
        "--config",
        str(validator_dir / "repositories.yml"),
        "--tests-root",
        str(validator_dir / "tests"),
        "--artifact-root",
        str(artifact_root),
        "--library",
        LIBRARY,
        "--mode",
        mode,
    ]
    if mode == "port":
        assert override_root is not None and port_lock is not None
        command.extend(["--override-deb-root", str(override_root), "--port-deb-lock", str(port_lock)])
    if record_casts:
        command.append("--record-casts")
    print(shell_join(command), flush=True)
    completed = subprocess.run(command, check=False)
    return int(completed.returncode)


def append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def cleanup_container(container_name: str, *, docker_bin: str, env: dict[str, str] | None = None) -> None:
    subprocess.run(
        [docker_bin, "rm", "-f", container_name],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )


def kill_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=2)


def run_docker_command(
    command: list[str],
    *,
    timeout: int,
    log_file: Path,
    container_name: str,
    docker_bin: str = "docker",
    env: dict[str, str] | None = None,
) -> RunOutcome:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as log_handle:
        log_handle.write(f"$ {shell_join(command)}\n")
        log_handle.flush()
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
            env=env,
        )
        try:
            output, _ = process.communicate(timeout=timeout)
            if output:
                log_handle.write(output)
            return RunOutcome(int(process.returncode or 0), timed_out=False)
        except subprocess.TimeoutExpired as exc:
            partial = exc.output or ""
            if partial:
                log_handle.write(partial)
            kill_process_group(process)
            cleanup_container(container_name, docker_bin=docker_bin, env=env)
            try:
                output, _ = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                output = ""
            if output:
                log_handle.write(output)
            message = f"testcase timed out after {timeout} seconds"
            log_handle.write(message + "\n")
            return RunOutcome(124, timed_out=True)
        finally:
            cleanup_container(container_name, docker_bin=docker_bin, env=env)
            log_handle.flush()


def docker_build(
    *,
    validator_dir: Path,
    artifact_root: Path,
    mode: str,
    docker_bin: str = "docker",
    env: dict[str, str] | None = None,
) -> bool:
    build_log = artifact_path(artifact_root, mode, "logs", LIBRARY, "docker-build.log")
    build_log.parent.mkdir(parents=True, exist_ok=True)
    command = [
        docker_bin,
        "build",
        "-t",
        IMAGE_TAG,
        "-f",
        str(validator_dir / "tests" / LIBRARY / "Dockerfile"),
        str(validator_dir / "tests"),
    ]
    completed = subprocess.run(command, text=True, capture_output=True, check=False, env=env)
    build_log.write_text(
        f"$ {shell_join(command)}\n{completed.stdout or ''}{completed.stderr or ''}",
        encoding="utf-8",
    )
    return completed.returncode == 0


def read_override_installed(status_dir: Path, *, port_metadata: dict) -> list[dict[str, str]]:
    marker = status_dir / "override-installed"
    status_path = status_dir / "override-installed-packages.tsv"
    if not marker.is_file():
        fail("port override debs were not installed")
    if not status_path.is_file():
        fail("override-installed marker exists but package status file is missing")
    records_by_package: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(status_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 4 or any(not part for part in parts):
            fail(f"invalid override-installed-packages.tsv line {line_number}")
        package, version, architecture, filename = parts
        if package in records_by_package:
            fail(f"duplicate override install status for package {package}")
        records_by_package[package] = {
            "package": package,
            "version": version,
            "architecture": architecture,
            "filename": filename,
        }
    expected = [
        {
            "package": deb["package"],
            "version": deb["version"],
            "architecture": deb["architecture"],
            "filename": deb["filename"],
        }
        for deb in port_metadata["debs_with_versions"]
    ]
    actual = [records_by_package.get(package) for package in CANONICAL_PACKAGES]
    if actual != expected:
        fail("override install status does not match local port lock")
    return expected


def result_payload(
    *,
    case: Case,
    artifact_root: Path,
    mode: str,
    status: str,
    exit_code: int,
    override_debs_installed: bool,
    record_casts: bool,
    port_metadata: dict | None = None,
    override_installed_packages: list[dict[str, str]] | None = None,
    error: str | None = None,
    skipped: SkipEntry | None = None,
) -> dict:
    rpath = result_path(artifact_root, mode, case.id)
    lpath = log_path(artifact_root, mode, case.id)
    cpath = cast_path(artifact_root, mode, case.id)
    payload = {
        "schema_version": 2,
        "library": LIBRARY,
        "mode": mode,
        "testcase_id": case.id,
        "title": case.title,
        "description": case.description,
        "kind": case.kind,
        "client_application": case.client,
        "tags": list(case.tags),
        "requires": [],
        "status": status,
        "started_at": DETERMINISTIC_TIMESTAMP,
        "finished_at": DETERMINISTIC_TIMESTAMP,
        "duration_seconds": 0.0,
        "result_path": str(rpath.resolve(strict=False).relative_to(artifact_root.resolve(strict=False))),
        "log_path": str(lpath.resolve(strict=False).relative_to(artifact_root.resolve(strict=False))),
        "cast_path": str(cpath.resolve(strict=False).relative_to(artifact_root.resolve(strict=False)))
        if record_casts and cpath.is_file()
        else None,
        "exit_code": exit_code,
        "command": ["bash", case.container_path],
        "apt_packages": APT_PACKAGES,
        "override_debs_installed": override_debs_installed,
    }
    if mode == "port":
        if port_metadata is None and skipped is None:
            fail("port result requires port metadata")
        if port_metadata is not None:
            payload.update(
                {
                    "port_repository": port_metadata["repository"],
                    "port_tag_ref": port_metadata["tag_ref"],
                    "port_commit": port_metadata["commit"],
                    "port_release_tag": port_metadata["release_tag"],
                    "port_debs": port_metadata["port_debs"],
                    "unported_original_packages": port_metadata["unported_original_packages"],
                    "override_installed_packages": override_installed_packages or [],
                }
            )
    if error is not None:
        payload["error"] = error
    if skipped is not None:
        payload["validator_commit"] = skipped.validator_commit
        payload["skip_reason"] = skipped.reason
        payload["report_section"] = skipped.report_section
    return payload


def write_skip_result(
    *,
    case: Case,
    skip: SkipEntry,
    artifact_root: Path,
    mode: str,
    record_casts: bool,
    port_metadata: dict | None,
) -> dict:
    lpath = log_path(artifact_root, mode, case.id)
    lpath.parent.mkdir(parents=True, exist_ok=True)
    lpath.write_text(f"skipped: {skip.reason}\nreport: {skip.report_section}\n", encoding="utf-8")
    payload = result_payload(
        case=case,
        artifact_root=artifact_root,
        mode=mode,
        status="skipped",
        exit_code=0,
        override_debs_installed=False,
        record_casts=record_casts,
        port_metadata=port_metadata,
        skipped=skip,
    )
    write_json(result_path(artifact_root, mode, case.id), payload)
    return payload


def write_failed_unrun(
    *,
    case: Case,
    artifact_root: Path,
    mode: str,
    error: str,
    record_casts: bool,
    port_metadata: dict | None,
) -> dict:
    lpath = log_path(artifact_root, mode, case.id)
    lpath.parent.mkdir(parents=True, exist_ok=True)
    lpath.write_text(error + "\n", encoding="utf-8")
    payload = result_payload(
        case=case,
        artifact_root=artifact_root,
        mode=mode,
        status="failed",
        exit_code=1,
        override_debs_installed=False,
        record_casts=record_casts,
        port_metadata=port_metadata,
        error=error,
    )
    write_json(result_path(artifact_root, mode, case.id), payload)
    return payload


def write_cast_if_requested(*, artifact_root: Path, mode: str, case: Case, record_casts: bool) -> None:
    if not record_casts:
        return
    lpath = log_path(artifact_root, mode, case.id)
    cpath = cast_path(artifact_root, mode, case.id)
    cpath.parent.mkdir(parents=True, exist_ok=True)
    text = lpath.read_text(encoding="utf-8") if lpath.is_file() else ""
    cpath.write_text(
        json.dumps({"version": 2, "width": 120, "height": 40, "timestamp": 0}) + "\n"
        + json.dumps([0.0, "o", text])
        + "\n",
        encoding="utf-8",
    )


def execute_case(
    *,
    validator_dir: Path,
    case: Case,
    artifact_root: Path,
    mode: str,
    port_metadata: dict | None,
    override_root: Path | None,
    record_casts: bool,
    status_parent: Path | None = None,
    docker_bin: str = "docker",
    docker_env: dict[str, str] | None = None,
) -> dict:
    rpath = result_path(artifact_root, mode, case.id)
    lpath = log_path(artifact_root, mode, case.id)
    for path in (rpath, lpath, cast_path(artifact_root, mode, case.id) if record_casts else None):
        if path is not None and path.exists():
            path.unlink()

    status_root = status_parent or Path(tempfile.gettempdir())
    status_root.mkdir(parents=True, exist_ok=True)
    status_dir = Path(tempfile.mkdtemp(prefix=f"validator-status-{mode}-{case.id}-", dir=status_root))
    container_name = f"safelibs-validator-{LIBRARY}-{mode}-{case.id}-{os.getpid()}"
    command = [
        docker_bin,
        "run",
        "--rm",
        "--name",
        container_name,
        "--mount",
        f"type=bind,src={status_dir.resolve()},dst=/validator/status",
    ]
    if mode == "port":
        assert override_root is not None
        override_leaf = (override_root / LIBRARY).resolve()
        command.extend(
            [
                "--mount",
                f"type=bind,src={override_leaf},dst=/override-debs,readonly",
            ]
        )
    command.extend(
        [
            "--env",
            "VALIDATOR_STATUS_DIR=/validator/status",
            "--entrypoint",
            f"/validator/tests/{LIBRARY}/docker-entrypoint.sh",
            IMAGE_TAG,
            case.id,
            "--",
            case.container_path,
        ]
    )

    outcome = RunOutcome(1)
    error: str | None = None
    override_debs_installed = False
    override_installed_packages: list[dict[str, str]] = []
    try:
        outcome = run_docker_command(
            command,
            timeout=case.timeout,
            log_file=lpath,
            container_name=container_name,
            docker_bin=docker_bin,
            env=docker_env,
        )
        if outcome.timed_out:
            error = f"testcase timed out after {case.timeout} seconds"
        elif outcome.exit_code != 0:
            error = f"testcase command exited with status {outcome.exit_code}"

        if mode == "port":
            override_debs_installed = (status_dir / "override-installed").is_file()
            if outcome.timed_out:
                pass
            else:
                try:
                    assert port_metadata is not None
                    override_installed_packages = read_override_installed(status_dir, port_metadata=port_metadata)
                    override_debs_installed = True
                except RunnerError as exc:
                    status_error = str(exc)
                    append_log(lpath, status_error + "\n")
                    error = status_error if error is None else f"{error}; {status_error}"
                    outcome = RunOutcome(1, timed_out=False)
    finally:
        shutil.rmtree(status_dir, ignore_errors=True)

    status = "passed" if outcome.exit_code == 0 and not outcome.timed_out and error is None else "failed"
    write_cast_if_requested(artifact_root=artifact_root, mode=mode, case=case, record_casts=record_casts)
    payload = result_payload(
        case=case,
        artifact_root=artifact_root,
        mode=mode,
        status=status,
        exit_code=outcome.exit_code,
        override_debs_installed=override_debs_installed,
        record_casts=record_casts,
        port_metadata=port_metadata,
        override_installed_packages=override_installed_packages,
        error=error,
    )
    write_json(rpath, payload)
    return payload


def write_summary(
    *,
    artifact_root: Path,
    mode: str,
    results: list[dict],
    official_available: bool,
    fallback_reason: str | None,
    any_skipped: bool,
) -> dict:
    summary_path = artifact_path(artifact_root, mode, "results", LIBRARY, "summary.json")
    summary = {
        "schema_version": 2,
        "library": LIBRARY,
        "mode": mode,
        "cases": len(results),
        "source_cases": sum(1 for result in results if result.get("kind") == "source"),
        "usage_cases": sum(1 for result in results if result.get("kind") == "usage"),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "skipped": sum(1 for result in results if result.get("status") == "skipped"),
        "casts": sum(1 for result in results if result.get("cast_path") is not None),
        "duration_seconds": 0.0,
        "official_path_available": official_available,
        "official_fallback_reason": fallback_reason,
        "official_proof_eligible": not any_skipped,
    }
    write_json(summary_path, summary)
    return summary


def inspect_selected_results(*, artifact_root: Path, mode: str, selected_cases: list[Case]) -> bool:
    any_failed = False
    for case in selected_cases:
        path = result_path(artifact_root, mode, case.id)
        data = load_json(path, label=f"result {case.id}")
        if data.get("status") == "skipped":
            continue
        if data.get("status") != "passed":
            any_failed = True
    return any_failed


def fallback_run(
    *,
    validator_dir: Path,
    mode: str,
    artifact_root: Path,
    selected_cases: list[Case],
    active_skips: list[SkipEntry],
    port_metadata: dict | None,
    override_root: Path | None,
    record_casts: bool,
    official_available: bool,
    fallback_reason: str | None,
) -> int:
    artifact_root.mkdir(parents=True, exist_ok=True)
    cleanup_selected_artifacts(
        artifact_root=artifact_root,
        mode=mode,
        selected_cases=selected_cases,
        record_casts=record_casts,
    )
    skips_by_id = {entry.testcase_id: entry for entry in active_skips}
    runnable_cases = [case for case in selected_cases if case.id not in skips_by_id]
    results: list[dict] = []
    if runnable_cases:
        if not docker_build(validator_dir=validator_dir, artifact_root=artifact_root, mode=mode):
            for case in selected_cases:
                if case.id in skips_by_id:
                    results.append(
                        write_skip_result(
                            case=case,
                            skip=skips_by_id[case.id],
                            artifact_root=artifact_root,
                            mode=mode,
                            record_casts=record_casts,
                            port_metadata=port_metadata,
                        )
                    )
                else:
                    results.append(
                        write_failed_unrun(
                            case=case,
                            artifact_root=artifact_root,
                            mode=mode,
                            error="docker build failed for libgcrypt",
                            record_casts=record_casts,
                            port_metadata=port_metadata,
                        )
                    )
            write_summary(
                artifact_root=artifact_root,
                mode=mode,
                results=results,
                official_available=official_available,
                fallback_reason=fallback_reason,
                any_skipped=bool(active_skips),
            )
            return 1

    for case in selected_cases:
        skip = skips_by_id.get(case.id)
        if skip is not None:
            results.append(
                write_skip_result(
                    case=case,
                    skip=skip,
                    artifact_root=artifact_root,
                    mode=mode,
                    record_casts=record_casts,
                    port_metadata=port_metadata,
                )
            )
            continue
        results.append(
            execute_case(
                validator_dir=validator_dir,
                case=case,
                artifact_root=artifact_root,
                mode=mode,
                port_metadata=port_metadata,
                override_root=override_root,
                record_casts=record_casts,
            )
        )

    write_summary(
        artifact_root=artifact_root,
        mode=mode,
        results=results,
        official_available=official_available,
        fallback_reason=fallback_reason,
        any_skipped=bool(active_skips),
    )
    return 1 if inspect_selected_results(artifact_root=artifact_root, mode=mode, selected_cases=selected_cases) else 0


def make_fake_docker(tempdir: Path) -> tuple[Path, Path]:
    state = tempdir / "fake-docker-state"
    state.mkdir()
    fake = tempdir / "docker"
    fake.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
state=${FAKE_DOCKER_STATE:?}
cmd=${1:-}
shift || true
case "$cmd" in
  build)
    exit 0
    ;;
  rm)
    for arg in "$@"; do
      case "$arg" in
        -*) ;;
        *) rm -f "$state/$arg" ;;
      esac
    done
    exit 0
    ;;
  run)
    name=
    while (($#)); do
      case "$1" in
        --name)
          name=$2
          shift 2
          ;;
        --name=*)
          name=${1#--name=}
          shift
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -n "$name" ]]; then
      : >"$state/$name"
    fi
    sleep 5
    ;;
  *)
    exit 2
    ;;
esac
""",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake, state


def self_test_timeout() -> int:
    with tempfile.TemporaryDirectory(prefix="validator-libgcrypt-timeout-self-test-") as raw:
        tempdir = Path(raw)
        fake_docker, state = make_fake_docker(tempdir)
        status_parent = tempdir / "status"
        artifact_root = tempdir / "artifacts"
        script_path = tempdir / "synthetic-timeout.sh"
        script_path.write_text("#!/usr/bin/env bash\n# @testcase: synthetic-timeout\n", encoding="utf-8")
        case = Case(
            id="synthetic-timeout",
            title="synthetic timeout",
            description="synthetic timeout",
            timeout=1,
            tags=("self-test",),
            kind="source",
            script_path=script_path,
            container_path="/validator/tests/libgcrypt/tests/cases/source/synthetic-timeout.sh",
        )
        env = os.environ.copy()
        env["FAKE_DOCKER_STATE"] = str(state)
        result = execute_case(
            validator_dir=tempdir,
            case=case,
            artifact_root=artifact_root,
            mode="original",
            port_metadata=None,
            override_root=None,
            record_casts=False,
            status_parent=status_parent,
            docker_bin=str(fake_docker),
            docker_env=env,
        )
        expected_error = "testcase timed out after 1 seconds"
        if result.get("status") != "failed":
            fail("self-test did not record a failed timeout result")
        if result.get("exit_code") != 124:
            fail("self-test timeout result did not use exit_code 124")
        if result.get("error") != expected_error:
            fail("self-test timeout result error did not match expected timeout text")
        log_text = log_path(artifact_root, "original", case.id).read_text(encoding="utf-8")
        if expected_error not in log_text:
            fail("self-test timeout log did not contain timeout text")
        if status_parent.exists() and any(status_parent.iterdir()):
            fail("self-test left a temporary status directory behind")
        if any(state.iterdir()):
            fail("self-test left a named fake container behind")
    print("run-validator-libgcrypt: timeout self-test ok")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test-timeout", action="store_true")
    parser.add_argument("--validator-dir", type=Path)
    parser.add_argument("--mode", choices=("original", "port"))
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--override-root", type=Path)
    parser.add_argument("--port-lock", type=Path)
    parser.add_argument("--case", action="append")
    parser.add_argument("--case-glob", action="append")
    parser.add_argument("--kind", choices=("source", "usage"))
    parser.add_argument("--record-casts", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test_timeout:
        return args
    if args.validator_dir is None or args.mode is None or args.artifact_root is None:
        parser.error("--validator-dir, --mode, and --artifact-root are required")
    if args.mode == "port" and (args.override_root is None or args.port_lock is None):
        parser.error("--mode port requires --override-root and --port-lock")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test_timeout:
        return self_test_timeout()

    validator_dir = args.validator_dir.resolve()
    if not (validator_dir / ".git").is_dir():
        fail(f"missing validator checkout: {validator_dir}")
    artifact_root = args.artifact_root.resolve()
    all_cases = enumerate_cases(validator_dir)
    selected_cases = select_cases(
        all_cases,
        case_ids=args.case,
        case_globs=args.case_glob,
        kind=args.kind,
    )
    print("selected libgcrypt testcases:", " ".join(case.id for case in selected_cases), flush=True)

    active_skips = load_skips(
        validator_dir=validator_dir,
        mode=args.mode,
        selected_cases=selected_cases,
        all_cases=all_cases,
    )
    port_metadata = None
    if args.mode == "port":
        assert args.override_root is not None and args.port_lock is not None
        port_metadata = load_port_lock(args.port_lock.resolve(), override_root=args.override_root.resolve())

    official_available, official_output = official_probe(validator_dir)
    filters_requested = bool(args.case or args.case_glob or args.kind)
    if official_available and not filters_requested and not active_skips:
        official_rc = run_official(
            validator_dir=validator_dir,
            mode=args.mode,
            artifact_root=artifact_root,
            override_root=args.override_root.resolve() if args.override_root else None,
            port_lock=args.port_lock.resolve() if args.port_lock else None,
            record_casts=args.record_casts,
        )
        selected_failed = inspect_selected_results(
            artifact_root=artifact_root,
            mode=args.mode,
            selected_cases=selected_cases,
        )
        return 1 if official_rc != 0 or selected_failed else 0

    if not official_available:
        fallback_reason = "official libgcrypt matrix path unavailable: " + official_output.strip().replace("\n", " ")
    elif filters_requested:
        fallback_reason = "focused testcase selection requested"
    else:
        fallback_reason = "active skip entries require port-owned skip results"
    return fallback_run(
        validator_dir=validator_dir,
        mode=args.mode,
        artifact_root=artifact_root,
        selected_cases=selected_cases,
        active_skips=active_skips,
        port_metadata=port_metadata,
        override_root=args.override_root.resolve() if args.override_root else None,
        record_casts=args.record_casts,
        official_available=official_available,
        fallback_reason=fallback_reason,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except RunnerError as exc:
        print(f"run-validator-libgcrypt: {exc}", file=sys.stderr)
        raise SystemExit(1)
PY

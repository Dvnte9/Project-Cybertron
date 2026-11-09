#!/usr/bin/env python3
"""A small, local file-integrity checker using SHA-256."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_BASELINE = ".integrity-baseline.json"
CHUNK_SIZE = 1024 * 1024
MAX_TEXT_SNAPSHOT_BYTES = 64 * 1024
MAX_TOTAL_TEXT_SNAPSHOT_BYTES = 2 * 1024 * 1024
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(Exception):
    """An expected operational or input error suitable for a CLI message."""


def _absolute_path(path: Path) -> Path:
    """Make a normalized absolute path without resolving a final symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def _hash_file(path: Path, capture_text: bool = False) -> tuple[str, int, str | None, str | None]:
    """Hash a regular file; optionally capture a small UTF-8 text snapshot."""
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # Windows
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise IntegrityError("not a regular file (it may have changed during scanning)")

        digest = hashlib.sha256()
        snapshot_bytes = bytearray() if capture_text else None
        snapshot_status: str | None = None
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            if snapshot_bytes is not None and snapshot_status is None:
                if b"\x00" in chunk:
                    snapshot_status = "binary_or_non_utf8"
                    snapshot_bytes = None
                elif len(snapshot_bytes) + len(chunk) > MAX_TEXT_SNAPSHOT_BYTES:
                    snapshot_status = "too_large"
                    snapshot_bytes = None
                else:
                    snapshot_bytes.extend(chunk)

        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise IntegrityError("file changed while it was being read")

        snapshot: str | None = None
        if snapshot_bytes is not None:
            try:
                snapshot = snapshot_bytes.decode("utf-8")
                snapshot_status = "text"
            except UnicodeDecodeError:
                snapshot_status = "binary_or_non_utf8"
        return digest.hexdigest(), after.st_size, snapshot, snapshot_status
    finally:
        os.close(fd)


def scan_directory(
    root: Path, baseline: Path, include_text_snapshots: bool = False
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Hash regular files beneath root; optionally retain bounded UTF-8 text."""
    files: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    baseline_abs = _absolute_path(baseline)
    snapshot_budget = MAX_TOTAL_TEXT_SNAPSHOT_BYTES

    def walk(directory: Path) -> None:
        nonlocal snapshot_budget
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(f"{directory}: {exc}")
            return

        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    walk(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if _absolute_path(path) == baseline_abs:
                    continue

                digest, size, snapshot, snapshot_status = _hash_file(
                    path, capture_text=include_text_snapshots
                )
                relative = path.relative_to(root).as_posix()
                record: dict[str, Any] = {"sha256": digest, "size": size}
                if include_text_snapshots:
                    if snapshot is not None:
                        snapshot_size = len(snapshot.encode("utf-8"))
                        if snapshot_size > snapshot_budget:
                            record["text_snapshot_status"] = "snapshot_budget_exceeded"
                        else:
                            record["text_snapshot"] = snapshot
                            record["text_snapshot_status"] = "text"
                            snapshot_budget -= snapshot_size
                    else:
                        record["text_snapshot_status"] = snapshot_status
                files[relative] = record
            except (OSError, IntegrityError) as exc:
                errors.append(f"{path}: {exc}")

    walk(root)
    return files, errors


def _read_baseline(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise IntegrityError(f"baseline not found: {path} (run 'init' first)") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot read baseline {path}: {exc}") from exc

    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise IntegrityError("unsupported or invalid baseline schema")
    if not isinstance(data.get("root"), str) or not isinstance(data.get("files"), dict):
        raise IntegrityError("invalid baseline structure")

    for name, record in data["files"].items():
        if not isinstance(name, str) or not name or Path(name).is_absolute():
            raise IntegrityError("baseline contains an invalid file path")
        if ".." in Path(name).parts:
            raise IntegrityError("baseline contains a path outside the scanned directory")
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("sha256"), str)
            or not HASH_PATTERN.fullmatch(record["sha256"])
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or record["size"] < 0
        ):
            raise IntegrityError(f"invalid file record in baseline: {name}")
        if "text_snapshot" in record:
            snapshot = record["text_snapshot"]
            try:
                snapshot_size = len(snapshot.encode("utf-8")) if isinstance(snapshot, str) else -1
            except UnicodeEncodeError:
                snapshot_size = -1
            if snapshot_size < 0 or snapshot_size > MAX_TEXT_SNAPSHOT_BYTES or record.get("text_snapshot_status") != "text":
                raise IntegrityError(f"invalid text snapshot in baseline: {name}")
        if "text_snapshot_status" in record and (
            not isinstance(record["text_snapshot_status"], str)
            or record["text_snapshot_status"] not in {
                "text", "too_large", "binary_or_non_utf8", "snapshot_budget_exceeded"
            }
        ):
            raise IntegrityError(f"invalid text snapshot status in baseline: {name}")
    return data


def _write_baseline(path: Path, root: Path, files: dict[str, dict[str, Any]]) -> None:
    data = {"schema_version": SCHEMA_VERSION, "root": str(root), "files": files}
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.",
            suffix=".tmp", delete=False,
        ) as handle:
            temporary_name = handle.name
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except OSError as exc:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise IntegrityError(f"cannot write baseline {path}: {exc}") from exc


def _text_diff(path: str, before: str, after: str) -> str:
    """Build a unified diff for bounded text snapshots."""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"baseline/{path}",
            tofile=f"current/{path}",
            lineterm="\n",
        )
    )


def _snapshot_diff(path: str, before: dict[str, Any] | None, after: dict[str, Any] | None) -> str | None:
    """Return a diff when all existing sides have a saved/eligible text snapshot."""
    if before is not None and not isinstance(before.get("text_snapshot"), str):
        return None
    if after is not None and not isinstance(after.get("text_snapshot"), str):
        return None
    old_text = before["text_snapshot"] if before is not None else ""
    new_text = after["text_snapshot"] if after is not None else ""
    return _text_diff(path, old_text, new_text)


def _resolve_inputs(root_arg: str, baseline_arg: str | None) -> tuple[Path, Path]:
    try:
        root = Path(root_arg).expanduser().resolve(strict=True)
    except OSError as exc:
        raise IntegrityError(f"cannot access scan directory {root_arg!r}: {exc}") from exc
    if not root.is_dir():
        raise IntegrityError(f"scan path is not a directory: {root}")

    baseline = Path(baseline_arg).expanduser() if baseline_arg else root / DEFAULT_BASELINE
    baseline = _absolute_path(baseline if baseline.is_absolute() else Path.cwd() / baseline)
    return root, baseline


def run_init(root_arg: str, baseline_arg: str | None, include_text_snapshots: bool = False) -> int:
    root, baseline = _resolve_inputs(root_arg, baseline_arg)
    files, errors = scan_directory(root, baseline, include_text_snapshots=include_text_snapshots)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print("Baseline not written because scanning was incomplete.", file=sys.stderr)
        return 2

    _write_baseline(baseline, root, files)
    print(f"Baseline created: {baseline}")
    print(f"Recorded {len(files)} file(s) under {root}")
    return 0


def run_check(root_arg: str, baseline_arg: str | None) -> int:
    root, baseline = _resolve_inputs(root_arg, baseline_arg)
    saved = _read_baseline(baseline)
    if saved["root"] != str(root):
        raise IntegrityError(
            f"baseline was created for {saved['root']}; current directory is {root}"
        )

    current, errors = scan_directory(root, baseline, include_text_snapshots=True)
    old_files = saved["files"]
    old_names, new_names = set(old_files), set(current)
    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)
    changed = sorted(
        name for name in old_names & new_names
        if old_files[name]["sha256"] != current[name]["sha256"]
    )

    for name in added:
        print(f"NEW:     {name}")
        diff = _snapshot_diff(name, None, current[name])
        if diff:
            print(diff, end="" if diff.endswith("\n") else "\n")
    for name in changed:
        print(f"CHANGED: {name}")
        diff = _snapshot_diff(name, old_files[name], current[name])
        if diff:
            print(diff, end="" if diff.endswith("\n") else "\n")
        else:
            print("  Content diff unavailable (no eligible baseline text snapshot).")
    for name in removed:
        print(f"MISSING: {name}")
        diff = _snapshot_diff(name, old_files[name], None)
        if diff:
            print(diff, end="" if diff.endswith("\n") else "\n")
    for error in errors:
        print(f"ERROR:   {error}", file=sys.stderr)

    if errors:
        print("Check incomplete; resolve errors and run it again.", file=sys.stderr)
        return 2
    if added or changed or removed:
        print(f"Integrity differences found: {len(added)} new, {len(changed)} changed, {len(removed)} missing.")
        return 1
    print(f"OK: {len(current)} file(s) match the baseline.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and check a SHA-256 baseline for files in a local directory."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("init", "create or replace a baseline"),
        ("check", "compare files with an existing baseline"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument("directory", help="directory to scan")
        subparser.add_argument(
            "--baseline", help=f"baseline JSON path (default: <directory>/{DEFAULT_BASELINE})"
        )
        if command == "init":
            subparser.add_argument(
                "--include-text-snapshots",
                action="store_true",
                help=f"store UTF-8 text files up to {MAX_TEXT_SNAPSHOT_BYTES // 1024} KiB in the baseline to enable diffs",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            return run_init(args.directory, args.baseline, args.include_text_snapshots)
        return run_check(args.directory, args.baseline)
    except (IntegrityError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""A small, local file-integrity checker using SHA-256."""

from __future__ import annotations

import argparse
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
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(Exception):
    """An expected operational or input error suitable for a CLI message."""


def _absolute_path(path: Path) -> Path:
    """Make a normalized absolute path without resolving a final symlink."""
    return Path(os.path.abspath(os.fspath(path)))


def _hash_file(path: Path) -> tuple[str, int]:
    """Hash a regular file, avoiding symlinks where the platform supports it."""
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
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise IntegrityError("file changed while it was being read")
        return digest.hexdigest(), after.st_size
    finally:
        os.close(fd)


def scan_directory(root: Path, baseline: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Return hashes of regular files beneath root, never following symlinks."""
    files: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    baseline_abs = _absolute_path(baseline)

    def walk(directory: Path) -> None:
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

                digest, size = _hash_file(path)
                relative = path.relative_to(root).as_posix()
                files[relative] = {"sha256": digest, "size": size}
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


def run_init(root_arg: str, baseline_arg: str | None) -> int:
    root, baseline = _resolve_inputs(root_arg, baseline_arg)
    files, errors = scan_directory(root, baseline)
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

    current, errors = scan_directory(root, baseline)
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
    for name in changed:
        print(f"CHANGED: {name}")
    for name in removed:
        print(f"MISSING: {name}")
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            return run_init(args.directory, args.baseline)
        return run_check(args.directory, args.baseline)
    except (IntegrityError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

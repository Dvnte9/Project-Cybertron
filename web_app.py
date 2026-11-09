#!/usr/bin/env python3
"""Small same-origin web dashboard for the local file integrity checker."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from typing import Any

from integrity_checker import (
    DEFAULT_BASELINE,
    IntegrityError,
    _read_baseline,
    _snapshot_diff,
    _write_baseline,
    scan_directory,
)

WEB_DIR = Path(__file__).parent / "web"
MAX_REQUEST_BYTES = 4096


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], root: Path, allowed_roots: list[Path] | None = None):
        super().__init__(address, DashboardHandler)
        self.state_lock = threading.RLock()
        self.scan_root = root.resolve(strict=True)
        roots = [path.resolve(strict=True) for path in (allowed_roots or [self.scan_root])]
        if not any(self._is_within(self.scan_root, allowed) for allowed in roots):
            roots.append(self.scan_root)
        self.allowed_roots = tuple(dict.fromkeys(roots))
        self.baseline_path = self.scan_root / DEFAULT_BASELINE

    @staticmethod
    def _is_within(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def resolve_allowed_directory(self, candidate: str | Path) -> tuple[Path, Path]:
        """Resolve a folder and its containing startup-authorized scope root."""
        try:
            path = Path(candidate).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise FileNotFoundError(f"Cannot access folder: {candidate}") from exc
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")
        containing = [root for root in self.allowed_roots if self._is_within(path, root)]
        if not containing:
            raise PermissionError("That folder is outside the dashboard's allowed roots")
        # Prefer the narrowest matching root if allowed roots overlap.
        allowed = max(containing, key=lambda item: len(item.parts))
        return path, allowed

    def select_directory(self, candidate: str | Path) -> Path:
        path, _ = self.resolve_allowed_directory(candidate)
        with self.state_lock:
            self.scan_root = path
            self.baseline_path = path / DEFAULT_BASELINE
        return path


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args: Any) -> None:
        # Keep logs useful without echoing request bodies or file contents.
        super().log_message(format, *args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if route == "/api/status":
            with self.server.state_lock:
                self._send_status()
            return
        if route == "/api/directories":
            self._list_directories()
            return

        assets = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/style.css": "style.css"}
        asset = assets.get(route)
        if asset is None:
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        path = WEB_DIR / asset
        try:
            body = path.read_bytes()
        except OSError:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Dashboard asset is missing")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript",):
            content_type += "; charset=utf-8"
        self._send(HTTPStatus.OK, body, content_type)

    def _send_status(self) -> None:
        root = self.server.scan_root
        baseline = self.server.baseline_path
        baseline_exists = baseline.is_file()
        count: int | None = None
        snapshot_count: int | None = None
        baseline_error: str | None = None
        if baseline_exists:
            try:
                files = _read_baseline(baseline)["files"]
                count = len(files)
                snapshot_count = sum("text_snapshot" in record for record in files.values())
            except IntegrityError as exc:
                baseline_error = str(exc)
        self._json(
            HTTPStatus.OK,
            {
                "directory": str(root),
                "baseline_exists": baseline_exists,
                "baseline_file_count": count,
                "text_snapshot_count": snapshot_count,
                "baseline_error": baseline_error,
                "allowed_roots": [str(path) for path in self.server.allowed_roots],
            },
        )

    def _list_directories(self) -> None:
        query = parse_qs(urlsplit(self.path).query)
        with self.server.state_lock:
            active_root = str(self.server.scan_root)
        requested = query.get("path", [active_root])[0]
        try:
            current, allowed_root = self.server.resolve_allowed_directory(requested)
        except PermissionError as exc:
            self._error(HTTPStatus.FORBIDDEN, str(exc))
            return
        except (FileNotFoundError, NotADirectoryError) as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
            return

        folders: list[dict[str, str]] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                            continue
                        child = Path(entry.path).resolve(strict=True)
                        if self.server._is_within(child, allowed_root):
                            folders.append({"name": entry.name, "path": str(child)})
                    except OSError:
                        continue
        except OSError as exc:
            self._error(HTTPStatus.FORBIDDEN, f"Cannot list this folder: {exc}")
            return

        folders.sort(key=lambda item: item["name"].casefold())
        parent = current.parent if current != allowed_root else None
        self._json(
            HTTPStatus.OK,
            {
                "current": str(current),
                "allowed_root": str(allowed_root),
                "allowed_roots": [str(path) for path in self.server.allowed_roots],
                "parent": str(parent) if parent else None,
                "folders": folders,
            },
        )

    def _validate_post(self, route: str) -> dict[str, Any] | None:
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        if not host or not origin or urlsplit(origin).netloc.lower() != host.lower():
            self._error(HTTPStatus.FORBIDDEN, "Only same-origin dashboard requests are allowed")
            return None

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "Invalid request length")
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large")
            return None
        if self.headers.get_content_type() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Expected application/json")
            return None
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "Invalid JSON request")
            return None

        allowed_keys = {
            "/api/init": {"include_text_snapshots"},
            "/api/select-directory": {"directory"},
            "/api/check": set(),
        }[route]
        if not isinstance(payload, dict) or set(payload) - allowed_keys:
            self._error(HTTPStatus.BAD_REQUEST, "Invalid request options")
            return None
        if "include_text_snapshots" in payload and not isinstance(payload["include_text_snapshots"], bool):
            self._error(HTTPStatus.BAD_REQUEST, "include_text_snapshots must be true or false")
            return None
        if "directory" in payload and (
            not isinstance(payload["directory"], str)
            or not payload["directory"]
            or len(payload["directory"]) > 3000
            or "\x00" in payload["directory"]
        ):
            self._error(HTTPStatus.BAD_REQUEST, "directory must be a valid folder path")
            return None
        # Any requested path is resolved and checked against startup-authorized roots.
        return payload

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route not in ("/api/init", "/api/check", "/api/select-directory"):
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        options = self._validate_post(route)
        if options is None:
            return

        if route == "/api/init":
            self._init_baseline(bool(options.get("include_text_snapshots", False)))
        elif route == "/api/check":
            self._check_baseline()
        else:
            self._select_directory(options["directory"])

    def _select_directory(self, requested: str) -> None:
        try:
            self.server.select_directory(requested)
        except PermissionError as exc:
            self._error(HTTPStatus.FORBIDDEN, str(exc))
            return
        except (FileNotFoundError, NotADirectoryError) as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
            return
        with self.server.state_lock:
            self._send_status()

    def _init_baseline(self, include_text_snapshots: bool) -> None:
        with self.server.state_lock:
            self._init_baseline_locked(include_text_snapshots)

    def _init_baseline_locked(self, include_text_snapshots: bool) -> None:
        files, errors = scan_directory(
            self.server.scan_root,
            self.server.baseline_path,
            include_text_snapshots=include_text_snapshots,
        )
        if errors:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "Scan incomplete", "details": errors})
            return
        try:
            _write_baseline(self.server.baseline_path, self.server.scan_root, files)
        except (IntegrityError, OSError) as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
            return
        snapshot_count = sum("text_snapshot" in record for record in files.values())
        self._json(
            HTTPStatus.OK,
            {
                "file_count": len(files),
                "text_snapshot_count": snapshot_count,
                "text_snapshots_enabled": include_text_snapshots,
                "message": "Baseline created",
            },
        )

    def _check_baseline(self) -> None:
        with self.server.state_lock:
            self._check_baseline_locked()

    def _check_baseline_locked(self) -> None:
        try:
            saved = _read_baseline(self.server.baseline_path)
        except IntegrityError as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
            return
        if saved["root"] != str(self.server.scan_root):
            self._error(HTTPStatus.CONFLICT, "Baseline belongs to a different directory")
            return

        current, errors = scan_directory(
            self.server.scan_root,
            self.server.baseline_path,
            include_text_snapshots=True,
        )
        if errors:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "Scan incomplete", "details": errors})
            return

        old_files = saved["files"]
        old_names, current_names = set(old_files), set(current)
        added = sorted(current_names - old_names)
        removed = sorted(old_names - current_names)
        changed = sorted(
            name for name in old_names & current_names
            if old_files[name]["sha256"] != current[name]["sha256"]
        )
        unchanged = len(current_names & old_names) - len(changed)
        diffs: dict[str, str] = {}
        diff_unavailable: list[str] = []
        for name in added + changed + removed:
            diff = _snapshot_diff(name, old_files.get(name), current.get(name))
            if diff is None:
                diff_unavailable.append(name)
            else:
                diffs[name] = diff
        self._json(
            HTTPStatus.OK,
            {
                "added": added,
                "changed": changed,
                "missing": removed,
                "unchanged_count": unchanged,
                "total_count": len(current),
                "has_differences": bool(added or changed or removed),
                "diffs": diffs,
                "diff_unavailable": diff_unavailable,
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local web dashboard for the file integrity checker.")
    parser.add_argument("--directory", required=True, help="initial directory to scan")
    parser.add_argument(
        "--allowed-root", action="append", default=[], metavar="DIR",
        help="allow choosing this directory and its subfolders (repeatable; defaults to --directory only)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="listen address (default: 0.0.0.0 for preview support)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    args = parser.parse_args(argv)

    try:
        root = Path(args.directory).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        print(f"Cannot access scan directory: {exc}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"Scan path is not a directory: {root}", file=sys.stderr)
        return 2

    allowed_roots: list[Path] = []
    try:
        for candidate in args.allowed_root:
            allowed = Path(candidate).expanduser().resolve(strict=True)
            if not allowed.is_dir():
                raise NotADirectoryError(f"Allowed root is not a directory: {allowed}")
            if allowed not in allowed_roots:
                allowed_roots.append(allowed)
    except (OSError, RuntimeError) as exc:
        print(f"Cannot access allowed root: {exc}", file=sys.stderr)
        return 2

    try:
        server = DashboardServer((args.host, args.port), root, allowed_roots or [root])
    except OSError as exc:
        print(f"Cannot start dashboard: {exc}", file=sys.stderr)
        return 2

    print(f"Dashboard serving {root} on http://{args.host}:{args.port}")
    print("Folder selection is restricted to:")
    for allowed in server.allowed_roots:
        print(f"  {allowed}")
    print("Security: folder choices are restricted to these roots. Use this server only in a trusted environment.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

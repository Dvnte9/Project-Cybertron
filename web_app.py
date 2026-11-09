#!/usr/bin/env python3
"""Small same-origin web dashboard for the local file integrity checker."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from integrity_checker import (
    DEFAULT_BASELINE,
    IntegrityError,
    _read_baseline,
    _write_baseline,
    scan_directory,
)

WEB_DIR = Path(__file__).parent / "web"
MAX_REQUEST_BYTES = 4096


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], root: Path):
        super().__init__(address, DashboardHandler)
        self.scan_root = root
        self.baseline_path = root / DEFAULT_BASELINE


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
            baseline_exists = self.server.baseline_path.is_file()
            count: int | None = None
            baseline_error: str | None = None
            if baseline_exists:
                try:
                    count = len(_read_baseline(self.server.baseline_path)["files"])
                except IntegrityError as exc:
                    baseline_error = str(exc)
            self._json(
                HTTPStatus.OK,
                {
                    "directory": str(self.server.scan_root),
                    "baseline_exists": baseline_exists,
                    "baseline_file_count": count,
                    "baseline_error": baseline_error,
                },
            )
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

    def _validate_post(self) -> bool:
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin", "")
        if not host or not origin or urlsplit(origin).netloc.lower() != host.lower():
            self._error(HTTPStatus.FORBIDDEN, "Only same-origin dashboard requests are allowed")
            return False

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "Invalid request length")
            return False
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large")
            return False
        if self.headers.get_content_type() != "application/json":
            self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Expected application/json")
            return False
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "Invalid JSON request")
            return False
        # The browser never chooses a path. The server scans only its startup-configured root.
        if payload != {}:
            self._error(HTTPStatus.BAD_REQUEST, "Request body must be an empty JSON object")
            return False
        return True

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route not in ("/api/init", "/api/check"):
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        if not self._validate_post():
            return

        if route == "/api/init":
            self._init_baseline()
        else:
            self._check_baseline()

    def _init_baseline(self) -> None:
        files, errors = scan_directory(self.server.scan_root, self.server.baseline_path)
        if errors:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "Scan incomplete", "details": errors})
            return
        try:
            _write_baseline(self.server.baseline_path, self.server.scan_root, files)
        except (IntegrityError, OSError) as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
            return
        self._json(HTTPStatus.OK, {"file_count": len(files), "message": "Baseline created"})

    def _check_baseline(self) -> None:
        try:
            saved = _read_baseline(self.server.baseline_path)
        except IntegrityError as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))
            return
        if saved["root"] != str(self.server.scan_root):
            self._error(HTTPStatus.CONFLICT, "Baseline belongs to a different directory")
            return

        current, errors = scan_directory(self.server.scan_root, self.server.baseline_path)
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
        self._json(
            HTTPStatus.OK,
            {
                "added": added,
                "changed": changed,
                "missing": removed,
                "unchanged_count": unchanged,
                "total_count": len(current),
                "has_differences": bool(added or changed or removed),
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local web dashboard for the file integrity checker.")
    parser.add_argument("--directory", required=True, help="the one directory this dashboard may scan")
    parser.add_argument("--host", default="0.0.0.0", help="listen address (default: 0.0.0.0 for preview support)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP port (default: 8000)")
    args = parser.parse_args(argv)

    try:
        root = Path(args.directory).expanduser().resolve(strict=True)
    except OSError as exc:
        print(f"Cannot access scan directory: {exc}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"Scan path is not a directory: {root}", file=sys.stderr)
        return 2

    try:
        server = DashboardServer((args.host, args.port), root)
    except OSError as exc:
        print(f"Cannot start dashboard: {exc}", file=sys.stderr)
        return 2

    print(f"Dashboard serving {root} on http://{args.host}:{args.port}")
    print("Security: this server scans only the configured directory. Use it only in a trusted environment.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from web_app import DashboardServer


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "monitored"
        self.root.mkdir()
        (self.root / "note.txt").write_text("before\n", encoding="utf-8")
        self.allowed_root = Path(self.temp.name).resolve()
        self.server = DashboardServer(("127.0.0.1", 0), self.root.resolve(), [self.allowed_root])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, path, method="GET", payload=None, origin=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if origin is not None:
            headers["Origin"] = origin
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def post(self, path, payload=None, origin=None):
        return self.request(path, method="POST", payload={} if payload is None else payload,
                            origin=origin or self.base_url)

    def test_frontend_javascript_has_valid_syntax(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not installed; cannot syntax-check the browser script")
        script = Path(__file__).resolve().parents[1] / "web" / "app.js"
        subprocess.run([node, "--check", str(script)], check=True, capture_output=True, text=True)

    def test_status_exposes_only_configured_scan_root(self):
        status, data = self.request("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(data["directory"], str(self.root.resolve()))
        self.assertFalse(data["baseline_exists"])

    def test_can_browse_and_select_a_folder_inside_allowed_root(self):
        other = self.allowed_root / "another-project"
        other.mkdir()
        (other / "data.txt").write_text("another folder\\n", encoding="utf-8")

        status, listing = self.request(f"/api/directories?{urlencode({'path': str(self.allowed_root)})}")
        self.assertEqual(status, 200)
        self.assertEqual(listing["allowed_root"], str(self.allowed_root))
        self.assertEqual({item["name"] for item in listing["folders"]}, {"monitored", "another-project"})

        status, selected = self.post("/api/select-directory", {"directory": str(other)})
        self.assertEqual(status, 200)
        self.assertEqual(selected["directory"], str(other.resolve()))
        status, current = self.request("/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(current["directory"], str(other.resolve()))

    def test_rejects_folder_outside_allowed_roots(self):
        outside = Path(self.temp.name).parent
        status, result = self.post("/api/select-directory", {"directory": str(outside)})
        self.assertEqual(status, 403)
        self.assertIn("outside", result["error"])

    def test_init_then_check_reports_text_diff_when_opted_in(self):
        status, created = self.post("/api/init", payload={"include_text_snapshots": True})
        self.assertEqual(status, 200)
        self.assertEqual(created["file_count"], 1)
        self.assertEqual(created["text_snapshot_count"], 1)

        (self.root / "note.txt").write_text("after\n", encoding="utf-8")
        status, result = self.post("/api/check")
        self.assertEqual(status, 200)
        self.assertEqual(result["changed"], ["note.txt"])
        self.assertTrue(result["has_differences"])
        self.assertIn("-before", result["diffs"]["note.txt"])
        self.assertIn("+after", result["diffs"]["note.txt"])

    def test_baseline_without_snapshots_cannot_show_previous_text(self):
        status, _ = self.post("/api/init")
        self.assertEqual(status, 200)
        (self.root / "note.txt").write_text("after\n", encoding="utf-8")
        status, result = self.post("/api/check")
        self.assertEqual(status, 200)
        self.assertNotIn("note.txt", result["diffs"])
        self.assertIn("note.txt", result["diff_unavailable"])

    def test_rejects_cross_origin_and_arbitrary_path_requests(self):
        status, _ = self.post("/api/init", origin="https://attacker.invalid")
        self.assertEqual(status, 403)
        status, _ = self.post("/api/init", payload={"directory": "/etc"})
        self.assertEqual(status, 400)

    def test_check_before_init_returns_clear_error(self):
        status, data = self.post("/api/check")
        self.assertEqual(status, 404)
        self.assertIn("run 'init' first", data["error"])


if __name__ == "__main__":
    unittest.main()

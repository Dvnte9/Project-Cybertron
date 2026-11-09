import io
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

import integrity_checker


class IntegrityCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "sample"
        self.root.mkdir()
        (self.root / "hello.txt").write_text("hello\n", encoding="utf-8")
        self.baseline = self.root / integrity_checker.DEFAULT_BASELINE

    def tearDown(self):
        self.temp.cleanup()

    def test_init_and_clean_check(self):
        self.assertEqual(integrity_checker.run_init(str(self.root), None), 0)
        self.assertEqual(integrity_checker.run_check(str(self.root), None), 0)
        data = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(set(data["files"]), {"hello.txt"})

    def test_reports_added_changed_and_missing_files(self):
        (self.root / "to-delete.txt").write_text("delete me\n", encoding="utf-8")
        integrity_checker.run_init(str(self.root), None)
        (self.root / "hello.txt").write_text("changed\n", encoding="utf-8")
        (self.root / "new.txt").write_text("new\n", encoding="utf-8")
        (self.root / "to-delete.txt").unlink()
        self.assertEqual(integrity_checker.run_check(str(self.root), None), 1)

    def test_changed_and_new_files_are_detected(self):
        integrity_checker.run_init(str(self.root), None)
        (self.root / "hello.txt").write_text("changed\n", encoding="utf-8")
        (self.root / "new.txt").write_text("new\n", encoding="utf-8")
        self.assertEqual(integrity_checker.run_check(str(self.root), None), 1)

    def test_rejects_baseline_for_another_root(self):
        integrity_checker.run_init(str(self.root), None)
        other = Path(self.temp.name) / "other"
        other.mkdir()
        with self.assertRaises(integrity_checker.IntegrityError):
            integrity_checker.run_check(str(other), str(self.baseline))

    def test_rejects_malformed_baseline(self):
        self.baseline.write_text('{"schema_version": 999}', encoding="utf-8")
        with self.assertRaises(integrity_checker.IntegrityError):
            integrity_checker.run_check(str(self.root), None)

    def test_text_snapshots_are_opt_in_and_bounded(self):
        files, errors = integrity_checker.scan_directory(self.root, self.baseline)
        self.assertEqual(errors, [])
        self.assertNotIn("text_snapshot", files["hello.txt"])

        files, errors = integrity_checker.scan_directory(
            self.root, self.baseline, include_text_snapshots=True
        )
        self.assertEqual(errors, [])
        self.assertEqual(files["hello.txt"]["text_snapshot"], "hello\n")
        self.assertEqual(files["hello.txt"]["text_snapshot_status"], "text")

        binary = self.root / "binary.bin"
        binary.write_bytes(b"\x00\x01\x02")
        files, errors = integrity_checker.scan_directory(
            self.root, self.baseline, include_text_snapshots=True
        )
        self.assertEqual(errors, [])
        self.assertEqual(files["binary.bin"]["text_snapshot_status"], "binary_or_non_utf8")
        self.assertNotIn("text_snapshot", files["binary.bin"])

    def test_cli_prints_diff_for_snapshot_baseline(self):
        self.assertEqual(integrity_checker.run_init(str(self.root), None, True), 0)
        (self.root / "hello.txt").write_text("updated\n", encoding="utf-8")
        output = io.StringIO()
        with redirect_stdout(output):
            result = integrity_checker.run_check(str(self.root), None)
        self.assertEqual(result, 1)
        self.assertIn("-hello", output.getvalue())
        self.assertIn("+updated", output.getvalue())

    def test_does_not_follow_symlinked_files(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside secret\n", encoding="utf-8")
        try:
            (self.root / "linked.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available on this platform")
        files, errors = integrity_checker.scan_directory(self.root, self.baseline)
        self.assertEqual(errors, [])
        self.assertNotIn("linked.txt", files)
        self.assertNotIn("outside.txt", files)


if __name__ == "__main__":
    unittest.main()

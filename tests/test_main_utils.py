import json
import subprocess
import shutil
import sys
import unittest
import uuid
from pathlib import Path

from core.models import CheckResult
from main import (
    apply_ignored_rules,
    cleanup_stale_report_files,
    cleanup_stale_drift_files,
    load_ignore_rule_ids,
    normalize_diff_modules,
    normalize_report_formats,
    resolve_alert_file,
    resolve_drift_output_dir,
    resolve_output_dir,
    resolve_snapshot_ref,
    save_snapshot,
)


class TestMainUtils(unittest.TestCase):
    def setUp(self):
        self.workspace = (Path.cwd() / f".test_tmp_main_{uuid.uuid4().hex}").resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_default_output_dir_without_url(self):
        output = resolve_output_dir(None, None, self.workspace)
        self.assertEqual(output, self.workspace / "output")

    def test_default_output_dir_with_url(self):
        output = resolve_output_dir(None, "https://example.com", self.workspace)
        self.assertEqual(output, self.workspace / "output_url")

    def test_output_dir_must_stay_in_workspace(self):
        with self.assertRaises(ValueError):
            resolve_output_dir("..\\outside", None, self.workspace)

    def test_load_ignore_file(self):
        ignore_file = self.workspace / ".secbaseline-ignore"
        ignore_file.write_text("#comment\nSSH-001\n\nLNX-005\n", encoding="utf-8")
        ignored = load_ignore_rule_ids(ignore_file)
        self.assertEqual(ignored, {"SSH-001", "LNX-005"})

    def test_apply_ignored_rules_marks_skipped(self):
        ignore_file = self.workspace / ".secbaseline-ignore"
        rule_result = CheckResult(
            rule_id="SSH-001",
            name="test",
            module="ssh",
            status="fail",
            severity="high",
            message="x",
            evidence="y",
            recommendation="z",
        )
        patched = apply_ignored_rules([rule_result], {"SSH-001"}, ignore_file)
        self.assertEqual(patched[0].status, "skipped")

    def test_normalize_report_formats_both(self):
        resolved = normalize_report_formats("both")
        self.assertEqual(resolved, {"json", "md", "sarif"})

    def test_normalize_report_formats_two_types(self):
        resolved = normalize_report_formats("json,md")
        self.assertEqual(resolved, {"json", "md"})

    def test_normalize_report_formats_three_types_equals_both(self):
        resolved = normalize_report_formats("json,md,sarif")
        self.assertEqual(resolved, {"json", "md", "sarif"})

    def test_normalize_report_formats_reject_invalid(self):
        with self.assertRaises(ValueError):
            normalize_report_formats("json,xml")

    def test_normalize_diff_modules(self):
        modules = normalize_diff_modules("linux,ssh")
        self.assertEqual(modules, {"linux", "ssh"})

    def test_normalize_diff_modules_reject_invalid(self):
        with self.assertRaises(ValueError):
            normalize_diff_modules("linux,db")

    def test_resolve_drift_output_dir(self):
        drift_dir = resolve_drift_output_dir(self.workspace)
        self.assertEqual(drift_dir, self.workspace / "output_diff")

    def test_resolve_alert_file_auto_suffix(self):
        alert_path = resolve_alert_file("alerts", self.workspace)
        self.assertEqual(alert_path, self.workspace / "alerts" / "alerts.jsonl")

    def test_resolve_alert_file_keep_suffix(self):
        alert_path = resolve_alert_file("custom_alert.jsonl", self.workspace)
        self.assertEqual(alert_path, self.workspace / "alerts" / "custom_alert.jsonl")

    def test_resolve_alert_file_rejects_path(self):
        with self.assertRaises(ValueError):
            resolve_alert_file("alerts/test.jsonl", self.workspace)

    def test_save_snapshot_with_name(self):
        report = {"meta": {}, "summary": {}, "results": []}
        snap = save_snapshot(report, self.workspace, "baseline_v1")
        self.assertTrue(snap.exists())
        self.assertEqual(snap.name, "baseline_v1.json")

    def test_save_snapshot_without_name_uses_timestamp(self):
        report = {"meta": {}, "summary": {}, "results": []}
        snap = save_snapshot(report, self.workspace, None)
        self.assertTrue(snap.exists())
        self.assertRegex(snap.name, r"^\d{8}T\d{12}Z(?:_\d+)?\.json$")

    def test_save_snapshot_without_name_no_collision(self):
        report = {"meta": {}, "summary": {}, "results": []}
        first = save_snapshot(report, self.workspace, None)
        second = save_snapshot(report, self.workspace, None)
        self.assertNotEqual(first.name, second.name)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_save_snapshot_rejects_invalid_name(self):
        report = {"meta": {}, "summary": {}, "results": []}
        with self.assertRaises(ValueError):
            save_snapshot(report, self.workspace, "../bad_name")

    def test_resolve_snapshot_ref_under_snapshots(self):
        snapshots_dir = self.workspace / "snapshots"
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        file_path = snapshots_dir / "baseline_v1.json"
        file_path.write_text("{}", encoding="utf-8")
        resolved = resolve_snapshot_ref("baseline_v1", self.workspace)
        self.assertEqual(resolved, file_path.resolve())

    def test_resolve_snapshot_ref_rejects_path(self):
        with self.assertRaises(ValueError):
            resolve_snapshot_ref("snapshots/baseline_v1.json", self.workspace)

    def test_resolve_snapshot_ref_missing(self):
        with self.assertRaises(ValueError):
            resolve_snapshot_ref("not_exists.json", self.workspace)

    def test_diff_only_mode_respects_custom_output_dir(self):
        snapshots = self.workspace / "snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        sample_report = {"meta": {}, "summary": {}, "results": []}
        (snapshots / "a.json").write_text(json.dumps(sample_report), encoding="utf-8")
        (snapshots / "b.json").write_text(json.dumps(sample_report), encoding="utf-8")

        main_path = Path(__file__).resolve().parents[1] / "main.py"
        completed = subprocess.run(
            [
                sys.executable,
                str(main_path),
                "--target",
                "local",
                "--diff-from",
                "a.json",
                "--diff-to",
                "b.json",
                "--output-dir",
                "custom_diff",
                "--format",
                "json",
            ],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue((self.workspace / "custom_diff" / "drift.json").exists())
        self.assertFalse((self.workspace / "output_diff" / "drift.json").exists())

    def test_cleanup_stale_drift_files(self):
        (self.workspace / "drift.json").write_text("{}", encoding="utf-8")
        (self.workspace / "drift.md").write_text("# old", encoding="utf-8")
        cleanup_stale_drift_files(self.workspace)
        self.assertFalse((self.workspace / "drift.json").exists())
        self.assertFalse((self.workspace / "drift.md").exists())

    def test_cleanup_stale_report_files(self):
        (self.workspace / "report.json").write_text("{}", encoding="utf-8")
        (self.workspace / "report.md").write_text("# old", encoding="utf-8")
        (self.workspace / "report.sarif").write_text("{}", encoding="utf-8")
        cleanup_stale_report_files(self.workspace)
        self.assertFalse((self.workspace / "report.json").exists())
        self.assertFalse((self.workspace / "report.md").exists())
        self.assertFalse((self.workspace / "report.sarif").exists())


if __name__ == "__main__":
    unittest.main()

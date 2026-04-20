import json
import shutil
import unittest
import uuid
from pathlib import Path

from core.dashboard import write_dashboard
from core.fixer import apply_safe_fixes, finalize_fix_summary
from main import _validate_runtime_args, parse_args


class TestFixerAndDashboard(unittest.TestCase):
    def setUp(self):
        self.workspace = (Path.cwd() / f".test_tmp_fix_dash_{uuid.uuid4().hex}").resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_apply_safe_fixes_with_no_fixable_rules(self):
        report = {
            "results": [
                {"rule_id": "LNX-001", "status": "pass"},
                {"rule_id": "HTTP-001", "status": "fail"},
            ]
        }
        summary = apply_safe_fixes(report, self.workspace)
        self.assertEqual(summary["fixable_failed_rules"], [])
        self.assertEqual(summary["actions"], [])
        rollback = Path(summary["rollback_script"])
        self.assertTrue(rollback.exists())
        self.assertTrue((self.workspace / "fixes" / "fix_summary.json").exists())

    def test_finalize_fix_summary_marks_improved(self):
        before_report = {"results": [{"rule_id": "LNX-007", "status": "fail"}]}
        after_report = {"results": [{"rule_id": "LNX-007", "status": "pass"}]}
        summary = {
            "actions": [{"rule_id": "LNX-007", "applied": True, "message": "ok"}],
            "rollback_script": str(self.workspace / "fixes" / "rollback.sh"),
        }
        final = finalize_fix_summary(before_report, after_report, summary, self.workspace)
        self.assertEqual(final["improved_count"], 1)
        self.assertTrue(final["actions"][0]["improved"])

    def test_write_dashboard(self):
        snapshots = self.workspace / "snapshots"
        snapshots.mkdir(parents=True, exist_ok=True)
        old_report = {
            "meta": {"generated_at": "2026-04-20T00:00:00+00:00"},
            "summary": {"total": 1},
            "results": [{"rule_id": "A", "module": "linux", "status": "pass", "severity": "low"}],
        }
        (snapshots / "old.json").write_text(json.dumps(old_report), encoding="utf-8")

        report = {
            "meta": {"generated_at": "2026-04-20T01:00:00+00:00"},
            "summary": {"total": 1, "status": {"fail": 1}, "severity": {"high": 1}},
            "results": [
                {
                    "rule_id": "LNX-007",
                    "module": "linux",
                    "status": "fail",
                    "severity": "high",
                    "message": "bad",
                }
            ],
        }
        path = write_dashboard(report, workspace=self.workspace, output_dir=self.workspace / "output")
        self.assertTrue(path.exists())
        content = path.read_text(encoding="utf-8")
        self.assertIn("SecBaseline 监控面板", content)
        self.assertIn("风险趋势", content)

    def test_validate_fix_and_dashboard_boundaries(self):
        args = parse_args(["--target", "remote", "--host", "1.2.3.4", "--user", "root", "--fix"])
        self.assertIn("only supports", _validate_runtime_args(args, diff_only=False) or "")

        args2 = parse_args(["--target", "local", "--fix", "--interval", "1"])
        self.assertIn("monitor mode", _validate_runtime_args(args2, diff_only=False) or "")

        args3 = parse_args(["--target", "local", "--dashboard", "--diff-from", "a.json", "--diff-to", "b.json"])
        self.assertIn("diff-only", _validate_runtime_args(args3, diff_only=True) or "")


if __name__ == "__main__":
    unittest.main()

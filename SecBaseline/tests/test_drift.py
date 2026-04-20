import shutil
import unittest
import uuid
from pathlib import Path

from core.drift import build_drift_report, load_report_file, write_drift_reports


class TestDrift(unittest.TestCase):
    def setUp(self):
        self.output_dir = (Path.cwd() / f".test_tmp_drift_{uuid.uuid4().hex}").resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_drift_summary_and_trends(self):
        old_report = {
            "meta": {"tool": "SecBaseline", "generated_at": "old"},
            "results": [
                {"rule_id": "A", "module": "linux", "severity": "high", "status": "pass"},
                {"rule_id": "B", "module": "linux", "severity": "high", "status": "fail"},
                {"rule_id": "C", "module": "ssh", "severity": "medium", "status": "warn"},
            ],
        }
        new_report = {
            "meta": {"tool": "SecBaseline", "generated_at": "new"},
            "results": [
                {"rule_id": "A", "module": "linux", "severity": "high", "status": "fail"},
                {"rule_id": "B", "module": "linux", "severity": "high", "status": "pass"},
                {"rule_id": "D", "module": "http", "severity": "low", "status": "warn"},
            ],
        }
        drift = build_drift_report(old_report, new_report)
        self.assertEqual(drift["summary"]["total_rules_compared"], 4)
        self.assertEqual(drift["summary"]["regressions"], 2)
        self.assertEqual(drift["summary"]["improvements"], 2)
        self.assertEqual(drift["summary"]["net_drift_score"], 0)
        self.assertIn("weighted_net_score", drift["summary"])
        self.assertTrue(isinstance(drift["top_regressions"], list))

    def test_write_and_load_drift_reports(self):
        old_report = {"meta": {}, "results": []}
        new_report = {"meta": {}, "results": []}
        drift = build_drift_report(old_report, new_report)
        written = write_drift_reports(drift, self.output_dir)
        self.assertTrue((self.output_dir / "drift.json").exists())
        self.assertTrue((self.output_dir / "drift.md").exists())
        loaded = load_report_file(written["json"])
        self.assertEqual(loaded["summary"]["total_rules_compared"], 0)

    def test_write_drift_json_only(self):
        drift = build_drift_report({"meta": {}, "results": []}, {"meta": {}, "results": []})
        written = write_drift_reports(drift, self.output_dir, drift_formats={"json"})
        self.assertIn("json", written)
        self.assertNotIn("md", written)
        self.assertTrue((self.output_dir / "drift.json").exists())
        self.assertFalse((self.output_dir / "drift.md").exists())

    def test_drift_module_filter_and_view(self):
        old_report = {
            "meta": {},
            "results": [
                {"rule_id": "L1", "module": "linux", "severity": "high", "status": "pass"},
                {"rule_id": "S1", "module": "ssh", "severity": "high", "status": "pass"},
            ],
        }
        new_report = {
            "meta": {},
            "results": [
                {"rule_id": "L1", "module": "linux", "severity": "high", "status": "fail"},
                {"rule_id": "S1", "module": "ssh", "severity": "high", "status": "warn"},
            ],
        }
        drift = build_drift_report(old_report, new_report, module_filter={"linux"}, diff_view="regressions")
        self.assertEqual(drift["summary"]["total_rules_compared"], 1)
        self.assertEqual(len(drift["changes"]), 1)
        self.assertEqual(drift["changes"][0]["rule_id"], "L1")


if __name__ == "__main__":
    unittest.main()

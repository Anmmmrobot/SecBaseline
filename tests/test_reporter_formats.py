import json
import shutil
import unittest
import uuid
from pathlib import Path

from core.models import CheckResult
from core.reporter import build_report, write_reports


class TestReporterFormats(unittest.TestCase):
    def setUp(self):
        self.output_dir = (Path.cwd() / f".test_tmp_report_{uuid.uuid4().hex}").resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_write_sarif(self):
        results = [
            CheckResult(
                rule_id="SSH-001",
                name="Check sshd_config exists",
                module="ssh",
                status="fail",
                severity="high",
                message="missing",
                evidence="actual=None",
                recommendation="fix",
            )
        ]
        report = build_report(results, target="local", url=None)
        written = write_reports(report, self.output_dir, report_formats={"sarif"})
        self.assertIn("sarif", written)
        self.assertTrue((self.output_dir / "report.sarif").exists())
        data = json.loads((self.output_dir / "report.sarif").read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "2.1.0")
        self.assertIn("runs", data)

    def test_write_default_all_formats(self):
        results = [
            CheckResult(
                rule_id="LNX-001",
                name="check",
                module="linux",
                status="pass",
                severity="low",
                message="ok",
                evidence="x",
                recommendation="",
            )
        ]
        report = build_report(results, target="local", url=None)
        written = write_reports(report, self.output_dir)
        self.assertTrue((self.output_dir / "report.json").exists())
        self.assertTrue((self.output_dir / "report.md").exists())
        self.assertTrue((self.output_dir / "report.sarif").exists())
        self.assertEqual(set(written.keys()), {"json", "md", "sarif"})


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

from core.engine import load_rules
from core.models import CheckResult
from core.reporter import build_report


class TestRulePackAndCompliance(unittest.TestCase):
    def test_host_pack_excludes_http(self):
        rules = load_rules(Path("rules"), profile="strict", rule_pack="host")
        modules = {rule.module for rule in rules}
        self.assertIn("linux", modules)
        self.assertIn("ssh", modules)
        self.assertNotIn("http", modules)

    def test_web_pack_only_http(self):
        rules = load_rules(Path("rules"), profile="strict", rule_pack="web")
        modules = {rule.module for rule in rules}
        self.assertEqual(modules, {"http"})

    def test_compliance_mapping_loaded(self):
        rules = load_rules(Path("rules"), profile="basic", rule_pack="full")
        target = [rule for rule in rules if rule.rule_id == "LNX-001"][0]
        self.assertTrue(target.compliance)
        self.assertIn("CIS-LINUX-1.1", target.compliance)

    def test_report_contains_evidence_bundle(self):
        result = CheckResult(
            rule_id="T-001",
            name="demo",
            module="linux",
            status="pass",
            severity="low",
            message="ok",
            evidence="x",
            compliance=["CIS-TEST-1.0"],
            recommendation="noop",
        )
        report = build_report(
            results=[result],
            target="local",
            url=None,
            evidence_bundle={"modules": {"linux": {"demo": True}}},
        )
        self.assertIn("evidence", report)
        self.assertIn("modules", report["evidence"])


if __name__ == "__main__":
    unittest.main()

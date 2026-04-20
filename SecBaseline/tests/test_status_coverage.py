import unittest

from core.models import CheckResult, Rule
from main import build_skipped_results


class TestStatusCoverage(unittest.TestCase):
    def test_skipped_status(self):
        http_rule = Rule(
            rule_id="HTTP-TEST-001",
            name="skip http",
            module="http",
            rule_type="config_equals",
            severity="low",
        )
        results = build_skipped_results([http_rule], "no url")
        self.assertEqual(results[0].status, "skipped")

    def test_warn_status(self):
        result = CheckResult(
            rule_id="SSH-WARN-001",
            name="match warn",
            module="ssh",
            status="warn",
            severity="low",
            message="warn",
            evidence="match",
            recommendation="manual review",
        )
        self.assertEqual(result.status, "warn")


if __name__ == "__main__":
    unittest.main()

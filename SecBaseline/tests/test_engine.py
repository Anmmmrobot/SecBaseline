import unittest

from core.engine import evaluate_rule
from core.models import Rule


class TestEngineInjectedScenarios(unittest.TestCase):
    def test_pass_scenario(self):
        rule = Rule(
            rule_id="T-001",
            name="pass scenario",
            module="linux",
            rule_type="config_equals",
            severity="low",
            key="shadow_restricted",
            expected=True,
        )
        result = evaluate_rule(rule, {"shadow_restricted": True})
        self.assertEqual(result.status, "pass")

    def test_fail_scenario(self):
        rule = Rule(
            rule_id="T-002",
            name="fail scenario",
            module="linux",
            rule_type="config_not_equals",
            severity="low",
            key="Port",
            expected="22",
        )
        result = evaluate_rule(rule, {"Port": "22"})
        self.assertEqual(result.status, "fail")

    def test_fail_when_value_missing_for_not_equals(self):
        rule = Rule(
            rule_id="T-002B",
            name="missing value should fail",
            module="ssh",
            rule_type="config_not_equals",
            severity="low",
            key="PermitRootLogin",
            expected="yes",
        )
        result = evaluate_rule(rule, {"PermitRootLogin": None})
        self.assertEqual(result.status, "fail")

    def test_error_scenario(self):
        rule = Rule(
            rule_id="T-003",
            name="error scenario",
            module="http",
            rule_type="config_equals",
            severity="low",
            key="has_hsts",
            expected=True,
        )
        result = evaluate_rule(rule, {"__error": "timeout"})
        self.assertEqual(result.status, "error")

    def test_regex_match_scenario(self):
        rule = Rule(
            rule_id="T-003B",
            name="regex scenario",
            module="linux",
            rule_type="regex_match",
            severity="low",
            key="os_id",
            expected="^[a-z]+$",
        )
        result = evaluate_rule(rule, {"os_id": "kali"})
        self.assertEqual(result.status, "pass")

    def test_numeric_compare_scenario(self):
        rule = Rule(
            rule_id="T-003C",
            name="numeric scenario",
            module="linux",
            rule_type="numeric_compare",
            severity="low",
            key="uid0_account_count",
            operator="le",
            expected=1,
        )
        result = evaluate_rule(rule, {"uid0_account_count": 1})
        self.assertEqual(result.status, "pass")

    def test_value_in_scenario(self):
        rule = Rule(
            rule_id="T-003D",
            name="value in scenario",
            module="linux",
            rule_type="value_in",
            severity="low",
            key="os_id",
            expected=["kali", "ubuntu"],
        )
        result = evaluate_rule(rule, {"os_id": "kali"})
        self.assertEqual(result.status, "pass")

    def test_value_not_in_scenario(self):
        rule = Rule(
            rule_id="T-003E",
            name="value not in scenario",
            module="linux",
            rule_type="value_not_in",
            severity="low",
            key="has_telnet_port",
            expected=[True],
        )
        result = evaluate_rule(rule, {"has_telnet_port": False})
        self.assertEqual(result.status, "pass")

    def test_command_check_scenario(self):
        rule = Rule(
            rule_id="T-004",
            name="command check",
            module="linux",
            rule_type="command_check",
            severity="low",
            data_key="listening_ports",
            operator="not_contains",
            needle="23",
        )
        result = evaluate_rule(rule, {"listening_ports": "22,80,443"})
        self.assertEqual(result.status, "pass")

    def test_warn_like_low_severity_fail_scenario(self):
        rule = Rule(
            rule_id="T-005",
            name="warn-like",
            module="ssh",
            rule_type="config_not_equals",
            severity="low",
            key="Port",
            expected="22",
        )
        result = evaluate_rule(rule, {"Port": "22"})
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.severity, "low")


if __name__ == "__main__":
    unittest.main()

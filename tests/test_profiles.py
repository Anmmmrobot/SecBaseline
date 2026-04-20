import unittest
from pathlib import Path

from core.engine import load_rules


class TestProfiles(unittest.TestCase):
    def test_basic_profile_excludes_strict_rules(self):
        rules = load_rules(Path("rules"), profile="basic")
        ids = {rule.rule_id for rule in rules}
        self.assertIn("LNX-001", ids)
        self.assertNotIn("LNX-006", ids)
        self.assertNotIn("SSH-006", ids)

    def test_strict_profile_contains_strict_rules(self):
        rules = load_rules(Path("rules"), profile="strict")
        ids = {rule.rule_id for rule in rules}
        self.assertIn("LNX-006", ids)
        self.assertIn("SSH-006", ids)


if __name__ == "__main__":
    unittest.main()

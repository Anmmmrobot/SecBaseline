from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml

from core.models import CheckResult, Rule

VALID_TYPES = {
    "exists",
    "config_equals",
    "config_not_equals",
    "command_check",
    "regex_match",
    "numeric_compare",
    "value_in",
    "value_not_in",
}
VALID_STATUSES = {"pass", "fail", "warn", "skipped", "error"}
PACK_MODULES = {
    "full": {"linux", "ssh", "http"},
    "host": {"linux", "ssh"},
    "web": {"http"},
}


def _load_compliance_map(rules_dir: Path) -> dict[str, list[str]]:
    path = rules_dir / "compliance_map.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"compliance map must be dict: {path}")
    mapping: dict[str, list[str]] = {}
    for rule_id, controls in data.items():
        if isinstance(controls, str):
            mapping[str(rule_id)] = [controls]
        elif isinstance(controls, list):
            mapping[str(rule_id)] = [str(item) for item in controls]
        else:
            raise ValueError(f"invalid compliance controls for rule '{rule_id}' in {path}")
    return mapping


def load_rules(rules_dir: Path, profile: str = "basic", rule_pack: str = "full") -> list[Rule]:
    if rule_pack not in PACK_MODULES:
        raise ValueError(f"Unsupported rule pack '{rule_pack}'")
    allowed_modules = PACK_MODULES[rule_pack]
    compliance_map = _load_compliance_map(rules_dir)
    rules: list[Rule] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        if path.name == "compliance_map.yaml":
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        if not isinstance(data, list):
            raise ValueError(f"Rule file must be list: {path}")
        for item in data:
            rule_type = item.get("type")
            if rule_type not in VALID_TYPES:
                raise ValueError(f"Unsupported rule type '{rule_type}' in {path}")
            module = item.get("module")
            if module not in allowed_modules:
                continue
            profiles = item.get("profiles", ["basic", "strict"])
            if isinstance(profiles, str):
                profiles = [profiles]
            if profile not in profiles:
                continue
            compliance = item.get("compliance", compliance_map.get(item["id"], []))
            if isinstance(compliance, str):
                compliance = [compliance]
            rules.append(
                Rule(
                    rule_id=item["id"],
                    name=item["name"],
                    module=module,
                    rule_type=rule_type,
                    severity=item.get("severity", "low"),
                    key=item.get("key"),
                    expected=item.get("expected"),
                    target=item.get("target"),
                    target_type=item.get("target_type"),
                    data_key=item.get("data_key"),
                    operator=item.get("operator"),
                    needle=item.get("needle"),
                    profiles=profiles,
                    compliance=compliance,
                    recommendation=item.get("recommendation", ""),
                )
            )
    return rules


def _result(rule: Rule, status: str, message: str, evidence: str) -> CheckResult:
    if status not in VALID_STATUSES:
        status = "error"
    return CheckResult(
        rule_id=rule.rule_id,
        name=rule.name,
        module=rule.module,
        status=status,
        severity=rule.severity,
        message=message,
        evidence=evidence,
        compliance=rule.compliance,
        recommendation=rule.recommendation,
    )


def _check_exists(rule: Rule) -> CheckResult:
    if rule.target_type == "file":
        ok = Path(str(rule.target)).exists()
        return _result(
            rule,
            "pass" if ok else "fail",
            f"File existence check: {rule.target}",
            f"exists={ok}",
        )
    if rule.target_type == "command":
        ok = shutil.which(str(rule.target)) is not None
        return _result(
            rule,
            "pass" if ok else "fail",
            f"Command existence check: {rule.target}",
            f"exists={ok}",
        )
    return _result(rule, "error", "Invalid exists rule", "missing target_type")


def _check_config_equals(rule: Rule, data: dict) -> CheckResult:
    if not rule.key:
        return _result(rule, "error", "config_equals missing key", "rule.key is empty")
    actual = data.get(rule.key, None)
    if actual is None:
        return _result(
            rule,
            "fail",
            f"Config key '{rule.key}' is missing",
            "actual=None",
        )
    ok = actual == rule.expected
    return _result(
        rule,
        "pass" if ok else "fail",
        f"Config check {rule.key} == {rule.expected}",
        f"actual={actual}",
    )


def _check_config_not_equals(rule: Rule, data: dict) -> CheckResult:
    if not rule.key:
        return _result(rule, "error", "config_not_equals missing key", "rule.key is empty")
    actual = data.get(rule.key, None)
    if actual is None:
        return _result(
            rule,
            "fail",
            f"Config key '{rule.key}' is missing",
            "actual=None",
        )
    ok = actual != rule.expected
    return _result(
        rule,
        "pass" if ok else "fail",
        f"Config check {rule.key} != {rule.expected}",
        f"actual={actual}",
    )


def _check_command(rule: Rule, data: dict) -> CheckResult:
    if not rule.data_key or not rule.operator or rule.needle is None:
        return _result(rule, "error", "Invalid command_check rule", "missing data_key/operator/needle")
    if rule.data_key not in data:
        return _result(rule, "fail", f"Data key '{rule.data_key}' is missing", "actual=None")
    haystack = str(data.get(rule.data_key, ""))
    if rule.operator == "contains":
        ok = rule.needle in haystack
    elif rule.operator == "not_contains":
        ok = rule.needle not in haystack
    else:
        return _result(rule, "error", "Unsupported command_check operator", f"operator={rule.operator}")
    return _result(
        rule,
        "pass" if ok else "fail",
        f"Command output check: {rule.operator} '{rule.needle}'",
        f"from={rule.data_key}",
    )


def _check_regex_match(rule: Rule, data: dict) -> CheckResult:
    if not rule.key:
        return _result(rule, "error", "regex_match missing key", "rule.key is empty")
    if not isinstance(rule.expected, str) or not rule.expected:
        return _result(rule, "error", "regex_match missing pattern", "expected must be regex string")
    actual = data.get(rule.key, None)
    if actual is None:
        return _result(rule, "fail", f"Config key '{rule.key}' is missing", "actual=None")
    matched = re.search(rule.expected, str(actual)) is not None
    return _result(
        rule,
        "pass" if matched else "fail",
        f"Regex check {rule.key} matches /{rule.expected}/",
        f"actual={actual}",
    )


def _check_numeric_compare(rule: Rule, data: dict) -> CheckResult:
    if not rule.key:
        return _result(rule, "error", "numeric_compare missing key", "rule.key is empty")
    if rule.operator not in {"gt", "ge", "lt", "le", "eq", "ne"}:
        return _result(rule, "error", "Unsupported numeric_compare operator", f"operator={rule.operator}")
    actual_raw = data.get(rule.key, None)
    if actual_raw is None:
        return _result(rule, "fail", f"Config key '{rule.key}' is missing", "actual=None")
    try:
        actual = float(actual_raw)
        expected = float(rule.expected)
    except (TypeError, ValueError):
        return _result(rule, "error", "numeric_compare value is not numeric", f"actual={actual_raw}, expected={rule.expected}")

    match rule.operator:
        case "gt":
            ok = actual > expected
        case "ge":
            ok = actual >= expected
        case "lt":
            ok = actual < expected
        case "le":
            ok = actual <= expected
        case "eq":
            ok = actual == expected
        case "ne":
            ok = actual != expected
        case _:
            return _result(rule, "error", "Unsupported numeric_compare operator", f"operator={rule.operator}")

    return _result(
        rule,
        "pass" if ok else "fail",
        f"Numeric check {rule.key} {rule.operator} {expected}",
        f"actual={actual}",
    )


def _check_value_membership(rule: Rule, data: dict, mode: str) -> CheckResult:
    if not rule.key:
        return _result(rule, "error", f"{mode} missing key", "rule.key is empty")
    if not isinstance(rule.expected, list):
        return _result(rule, "error", f"{mode} expects list value", "expected must be list")
    actual = data.get(rule.key, None)
    if actual is None:
        return _result(rule, "fail", f"Config key '{rule.key}' is missing", "actual=None")

    if isinstance(actual, (list, tuple, set)):
        if mode == "value_in":
            ok = any(item in rule.expected for item in actual)
        else:
            ok = all(item not in rule.expected for item in actual)
    else:
        if mode == "value_in":
            ok = actual in rule.expected
        else:
            ok = actual not in rule.expected

    return _result(
        rule,
        "pass" if ok else "fail",
        f"Membership check {mode} on {rule.key}",
        f"actual={actual}, expected={rule.expected}",
    )


def evaluate_rule(rule: Rule, module_data: dict) -> CheckResult:
    if module_data.get("__error"):
        return _result(rule, "error", f"Collector failed: {module_data['__error']}", "collector_error")

    if rule.rule_type == "exists":
        return _check_exists(rule)
    if rule.rule_type == "config_equals":
        return _check_config_equals(rule, module_data)
    if rule.rule_type == "config_not_equals":
        return _check_config_not_equals(rule, module_data)
    if rule.rule_type == "command_check":
        return _check_command(rule, module_data)
    if rule.rule_type == "regex_match":
        return _check_regex_match(rule, module_data)
    if rule.rule_type == "numeric_compare":
        return _check_numeric_compare(rule, module_data)
    if rule.rule_type == "value_in":
        return _check_value_membership(rule, module_data, "value_in")
    if rule.rule_type == "value_not_in":
        return _check_value_membership(rule, module_data, "value_not_in")
    return _result(rule, "error", "Unknown rule type", rule.rule_type)


def evaluate_rules(rules: list[Rule], module_data: dict) -> list[CheckResult]:
    return [evaluate_rule(rule, module_data) for rule in rules]

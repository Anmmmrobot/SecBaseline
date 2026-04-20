from __future__ import annotations

import json
import shutil
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

FIXABLE_RULES = {"LNX-007", "LNX-009", "LNX-010", "SSH-002", "SSH-003", "SSH-005", "SSH-006"}
SSH_FIX_VALUES = {
    "SSH-002": ("PermitRootLogin", "no"),
    "SSH-003": ("PasswordAuthentication", "no"),
    "SSH-005": ("ClientAliveInterval", "300"),
    "SSH-006": ("MaxAuthTries", "6"),
}


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        output = ((completed.stdout or "") + (completed.stderr or "")).strip()
        if completed.returncode != 0:
            return False, output or f"command failed: {' '.join(cmd)}"
        return True, output
    except Exception as exc:
        return False, str(exc)


def _sysctl_get(key: str) -> tuple[bool, str]:
    return _run(["sysctl", "-n", key])


def _sysctl_set(key: str, value: str) -> tuple[bool, str]:
    return _run(["sysctl", "-w", f"{key}={value}"])


def _update_sshd_config_key(path: Path, key: str, value: str) -> tuple[bool, str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        lowered = key.lower()
        replaced = False
        output: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split(None, 1)
                if parts and parts[0].lower() == lowered and not replaced:
                    output.append(f"{key} {value}")
                    replaced = True
                    continue
            output.append(line)
        if not replaced:
            if output and output[-1].strip():
                output.append("")
            output.append(f"{key} {value}")
        path.write_text("\n".join(output) + "\n", encoding="utf-8")
        return True, "updated"
    except Exception as exc:
        return False, str(exc)


def _status_map(report: dict) -> dict[str, str]:
    return {item["rule_id"]: item.get("status", "") for item in report.get("results", [])}


def _compare_status(before_report: dict, after_report: dict, rule_id: str) -> dict:
    before = _status_map(before_report).get(rule_id)
    after = _status_map(after_report).get(rule_id)
    improved = False
    if before in {"error", "fail", "warn"} and after in {"pass", "skipped"}:
        improved = True
    return {"before_status": before, "after_status": after, "improved": improved}


def apply_safe_fixes(before_report: dict, output_dir: Path) -> dict:
    fixes_dir = output_dir / "fixes"
    fixes_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    rollback_path = fixes_dir / f"rollback_{stamp}.sh"
    summary_path = fixes_dir / "fix_summary.json"

    rollback_lines = ["#!/usr/bin/env sh", "set -e"]
    actions: list[dict] = []

    failed_rules = [
        item["rule_id"]
        for item in before_report.get("results", [])
        if item.get("status") == "fail" and item.get("rule_id") in FIXABLE_RULES
    ]
    unique_failed_rules = sorted(set(failed_rules))
    ssh_backup_path: Path | None = None
    ssh_config = Path("/etc/ssh/sshd_config")

    for rule_id in unique_failed_rules:
        action = {"rule_id": rule_id, "applied": False, "message": "", "post_check": None}
        if rule_id == "LNX-007":
            try:
                current_mode = stat.S_IMODE(Path("/etc/passwd").stat().st_mode)
                rollback_lines.append(f"chmod {current_mode:o} /etc/passwd")
                ok, msg = _run(["chmod", "o-w", "/etc/passwd"])
                action["applied"] = ok
                action["message"] = msg or "chmod o-w /etc/passwd"
            except Exception as exc:
                action["message"] = str(exc)
        elif rule_id == "LNX-009":
            ok_old, old_val = _sysctl_get("kernel.randomize_va_space")
            if ok_old:
                rollback_lines.append(f"sysctl -w kernel.randomize_va_space={old_val.strip()}")
            ok, msg = _sysctl_set("kernel.randomize_va_space", "2")
            action["applied"] = ok
            action["message"] = msg or "set kernel.randomize_va_space=2"
        elif rule_id == "LNX-010":
            ok_old, old_val = _sysctl_get("net.ipv4.ip_forward")
            if ok_old:
                rollback_lines.append(f"sysctl -w net.ipv4.ip_forward={old_val.strip()}")
            ok, msg = _sysctl_set("net.ipv4.ip_forward", "0")
            action["applied"] = ok
            action["message"] = msg or "set net.ipv4.ip_forward=0"
        elif rule_id in SSH_FIX_VALUES:
            key, value = SSH_FIX_VALUES[rule_id]
            if not ssh_config.exists():
                action["message"] = "sshd_config not found"
            else:
                if ssh_backup_path is None:
                    ssh_backup_path = fixes_dir / f"sshd_config.backup.{stamp}"
                    try:
                        shutil.copy2(ssh_config, ssh_backup_path)
                        rollback_lines.append(f"cp '{ssh_backup_path.as_posix()}' /etc/ssh/sshd_config")
                    except Exception as exc:
                        action["message"] = f"backup failed: {exc}"
                        actions.append(action)
                        continue
                ok, msg = _update_sshd_config_key(ssh_config, key, value)
                action["applied"] = ok
                action["message"] = msg or f"set {key} {value}"
        else:
            action["message"] = "rule is not supported by fixer"
        actions.append(action)

    rollback_path.write_text("\n".join(rollback_lines) + "\n", encoding="utf-8")
    try:
        rollback_path.chmod(0o700)
    except Exception:
        pass

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "fixable_failed_rules": unique_failed_rules,
        "actions": actions,
        "rollback_script": str(rollback_path),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def finalize_fix_summary(before_report: dict, after_report: dict, summary: dict, output_dir: Path) -> dict:
    fixes_dir = output_dir / "fixes"
    fixes_dir.mkdir(parents=True, exist_ok=True)
    summary_path = fixes_dir / "fix_summary.json"
    enhanced_actions = []
    for action in summary.get("actions", []):
        merged = dict(action)
        merged.update(_compare_status(before_report, after_report, action["rule_id"]))
        enhanced_actions.append(merged)
    improved_count = len([item for item in enhanced_actions if item.get("improved")])
    summary["actions"] = enhanced_actions
    summary["improved_count"] = improved_count
    summary["rechecked_at"] = datetime.now(UTC).isoformat()
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary

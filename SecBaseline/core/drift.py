from __future__ import annotations

import json
from pathlib import Path

STATUS_RANK = {
    "pass": 0,
    "skipped": 1,
    "warn": 2,
    "fail": 3,
    "error": 4,
}

SEVERITY_WEIGHT = {
    "high": 5,
    "medium": 3,
    "low": 1,
}


def load_report_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _trend_for_pair(old_status: str | None, new_status: str | None) -> str:
    if old_status is None and new_status is not None:
        return "regression" if STATUS_RANK.get(new_status, 0) >= 2 else "no_change"
    if old_status is not None and new_status is None:
        return "improvement" if STATUS_RANK.get(old_status, 0) >= 2 else "no_change"
    if old_status is None and new_status is None:
        return "no_change"

    old_rank = STATUS_RANK.get(old_status, 0)
    new_rank = STATUS_RANK.get(new_status, 0)
    if new_rank > old_rank:
        return "regression"
    if new_rank < old_rank:
        return "improvement"
    return "no_change"


def _change_type(old_status: str | None, new_status: str | None) -> str:
    if old_status is None:
        return "added"
    if new_status is None:
        return "removed"
    if old_status != new_status:
        return "status_changed"
    return "unchanged"


def _priority_label(severity: str, weighted_delta: int) -> str:
    if weighted_delta >= 10:
        return "P1"
    if weighted_delta >= 6:
        return "P2"
    if weighted_delta >= 3:
        return "P3"
    if severity == "high" and weighted_delta > 0:
        return "P2"
    return "P4"


def _apply_view(rows: list[dict], diff_view: str) -> list[dict]:
    if diff_view == "all":
        return rows
    if diff_view == "regressions":
        return [row for row in rows if row["trend"] == "regression"]
    return [row for row in rows if row["change_type"] != "unchanged"]


def build_drift_report(
    old_report: dict,
    new_report: dict,
    module_filter: set[str] | None = None,
    diff_view: str = "changes",
    top_n: int = 10,
) -> dict:
    old_map = {item["rule_id"]: item for item in old_report.get("results", [])}
    new_map = {item["rule_id"]: item for item in new_report.get("results", [])}

    rows: list[dict] = []
    for rule_id in sorted(set(old_map) | set(new_map)):
        old_item = old_map.get(rule_id)
        new_item = new_map.get(rule_id)
        source = new_item or old_item or {}
        module = source.get("module")
        severity = source.get("severity", "low")
        if module_filter and module not in module_filter:
            continue
        old_status = old_item["status"] if old_item else None
        new_status = new_item["status"] if new_item else None
        old_rank = STATUS_RANK.get(old_status, 0) if old_status is not None else 0
        new_rank = STATUS_RANK.get(new_status, 0) if new_status is not None else 0
        risk_delta = new_rank - old_rank
        weight = SEVERITY_WEIGHT.get(severity, 1)
        weighted_delta = risk_delta * weight
        row = {
            "rule_id": rule_id,
            "module": module,
            "severity": severity,
            "old_status": old_status,
            "new_status": new_status,
            "change_type": _change_type(old_status, new_status),
            "trend": _trend_for_pair(old_status, new_status),
            "risk_delta": risk_delta,
            "weighted_delta": weighted_delta,
            "priority": _priority_label(severity, weighted_delta),
        }
        rows.append(row)

    regressions = [row for row in rows if row["trend"] == "regression"]
    improvements = [row for row in rows if row["trend"] == "improvement"]
    weighted_regression_score = sum(max(0, row["weighted_delta"]) for row in regressions)
    weighted_improvement_score = sum(abs(min(0, row["weighted_delta"])) for row in improvements)
    weighted_net_score = weighted_regression_score - weighted_improvement_score

    regressions_sorted = sorted(
        regressions,
        key=lambda row: (row["weighted_delta"], STATUS_RANK.get(row["new_status"], 0)),
        reverse=True,
    )
    top_regressions = regressions_sorted[:top_n]
    visible_rows = _apply_view(rows, diff_view)

    summary = {
        "total_rules_compared": len(rows),
        "visible_rows": len(visible_rows),
        "changed": len([row for row in rows if row["change_type"] != "unchanged"]),
        "regressions": len(regressions),
        "improvements": len(improvements),
        "unchanged": len([row for row in rows if row["change_type"] == "unchanged"]),
        "net_drift_score": len(regressions) - len(improvements),
        "weighted_regression_score": weighted_regression_score,
        "weighted_improvement_score": weighted_improvement_score,
        "weighted_net_score": weighted_net_score,
    }

    return {
        "meta": {
            "mode": "baseline_drift",
            "from": old_report.get("meta", {}),
            "to": new_report.get("meta", {}),
            "module_filter": sorted(module_filter) if module_filter else None,
            "diff_view": diff_view,
            "top_n": top_n,
        },
        "summary": summary,
        "top_regressions": top_regressions,
        "changes": visible_rows,
    }


def _to_markdown(drift: dict) -> str:
    summary = drift["summary"]
    lines = [
        "# SecBaseline Drift Report",
        "",
        "## Summary",
        "",
        f"- Compared: {summary['total_rules_compared']}",
        f"- Visible: {summary['visible_rows']}",
        f"- Changed: {summary['changed']}",
        f"- Regressions: {summary['regressions']}",
        f"- Improvements: {summary['improvements']}",
        f"- Unchanged: {summary['unchanged']}",
        f"- Net Drift Score: {summary['net_drift_score']}",
        f"- Weighted Regression Score: {summary['weighted_regression_score']}",
        f"- Weighted Improvement Score: {summary['weighted_improvement_score']}",
        f"- Weighted Net Score: {summary['weighted_net_score']}",
        "",
        "## Top Regressions",
        "",
        "| priority | rule_id | module | severity | old | new | weighted_delta |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in drift["top_regressions"]:
        lines.append(
            f"| {row['priority']} | {row['rule_id']} | {row['module']} | {row['severity']} | "
            f"{row['old_status']} | {row['new_status']} | {row['weighted_delta']} |"
        )

    lines.extend(
        [
            "",
            "## Changes",
            "",
            "| rule_id | module | severity | old | new | change | trend | weighted_delta |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in drift["changes"]:
        lines.append(
            f"| {row['rule_id']} | {row['module']} | {row['severity']} | {row['old_status']} | "
            f"{row['new_status']} | {row['change_type']} | {row['trend']} | {row['weighted_delta']} |"
        )
    return "\n".join(lines) + "\n"


def write_drift_reports(drift: dict, output_dir: Path, drift_formats: set[str] | None = None) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    selected = {"json", "md"} if drift_formats is None else set(drift_formats)
    selected = selected & {"json", "md"}
    if not selected:
        selected = {"json"}

    json_path = output_dir / "drift.json"
    md_path = output_dir / "drift.md"
    if json_path.exists():
        json_path.unlink()
    if md_path.exists():
        md_path.unlink()

    written: dict[str, Path] = {}
    if "json" in selected:
        json_path.write_text(json.dumps(drift, ensure_ascii=False, indent=2), encoding="utf-8")
        written["json"] = json_path
    if "md" in selected:
        md_path.write_text(_to_markdown(drift), encoding="utf-8")
        written["md"] = md_path
    return written

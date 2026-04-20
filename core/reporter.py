from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from core.models import CheckResult


def build_report(
    results: list[CheckResult],
    target: str,
    url: str | None,
    meta_extra: dict | None = None,
    evidence_bundle: dict | None = None,
) -> dict:
    status_counter = Counter([result.status for result in results])
    severity_counter = Counter([result.severity for result in results])
    meta = {
        "tool": "SecBaseline",
        "generated_at": datetime.now(UTC).isoformat(),
        "target": target,
        "url": url,
    }
    if meta_extra:
        meta.update(meta_extra)
    report = {
        "meta": meta,
        "summary": {
            "total": len(results),
            "status": dict(status_counter),
            "severity": dict(severity_counter),
        },
        "results": [result.to_dict() for result in results],
    }
    if evidence_bundle:
        report["evidence"] = evidence_bundle
    return report


def _to_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# SecBaseline Report",
        "",
        "## Summary",
        "",
        f"- Total: {summary['total']}",
        f"- Status: {summary['status']}",
        f"- Severity: {summary['severity']}",
        "",
        "## Findings",
        "",
        "| rule_id | module | status | severity | compliance | message | evidence | fix |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in report["results"]:
        compliance = ",".join(item.get("compliance") or [])
        lines.append(
            f"| {item['rule_id']} | {item['module']} | {item['status']} | {item['severity']} | {compliance} | "
            f"{item['message']} | {item['evidence']} | {item['recommendation']} |"
        )
    return "\n".join(lines) + "\n"


def _severity_to_sarif_level(severity: str) -> str:
    if severity == "high":
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _result_to_sarif_level(item: dict) -> str:
    status = item.get("status")
    if status == "error":
        return "error"
    if status == "warn":
        return "warning"
    return _severity_to_sarif_level(item.get("severity", "low"))


def _to_sarif(report: dict) -> dict:
    all_items = report["results"]
    findings = [item for item in all_items if item["status"] in {"fail", "warn", "error"}]
    unique_rules: dict[str, dict] = {}
    for item in all_items:
        if item["rule_id"] not in unique_rules:
            unique_rules[item["rule_id"]] = {
                "id": item["rule_id"],
                "name": item["name"],
                "shortDescription": {"text": item["name"]},
                "fullDescription": {"text": item["recommendation"] or item["name"]},
                "defaultConfiguration": {"level": _severity_to_sarif_level(item["severity"])},
                "properties": {
                    "module": item["module"],
                    "severity": item["severity"],
                    "compliance": item.get("compliance") or [],
                },
            }

    sarif_results = []
    for item in findings:
        sarif_results.append(
            {
                "ruleId": item["rule_id"],
                "level": _result_to_sarif_level(item),
                "message": {
                    "text": f"[{item['status']}] {item['message']} | evidence: {item['evidence']}",
                },
                "properties": {
                    "module": item["module"],
                    "severity": item["severity"],
                    "status": item["status"],
                    "compliance": item.get("compliance") or [],
                },
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecBaseline",
                        "version": report["meta"].get("generated_at", ""),
                        "rules": list(unique_rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_reports(report: dict, output_dir: Path, report_formats: set[str] | None = None) -> dict[str, Path]:
    written: dict[str, Path] = {}
    formats = report_formats or {"json", "md", "sarif"}
    if "json" in formats:
        json_path = output_dir / "report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        written["json"] = json_path
    if "md" in formats:
        md_path = output_dir / "report.md"
        md_path.write_text(_to_markdown(report), encoding="utf-8")
        written["md"] = md_path
    if "sarif" in formats:
        sarif_path = output_dir / "report.sarif"
        sarif_path.write_text(json.dumps(_to_sarif(report), ensure_ascii=False, indent=2), encoding="utf-8")
        written["sarif"] = sarif_path
    return written

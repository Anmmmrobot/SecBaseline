from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

STATUS_ORDER = ["error", "fail", "warn", "skipped", "pass"]
SEVERITY_WEIGHT = {"high": 5, "medium": 3, "low": 1}
STATUS_WEIGHT = {"error": 4, "fail": 3, "warn": 2, "skipped": 1, "pass": 0}
MODULES = ["linux", "ssh", "http"]


def _risk_score(report: dict) -> int:
    score = 0
    for item in report.get("results", []):
        sev = SEVERITY_WEIGHT.get(item.get("severity", "low"), 1)
        st = STATUS_WEIGHT.get(item.get("status", "pass"), 0)
        score += sev * st
    return score


def _parse_ts(value: str) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=UTC)


def _load_snapshot_reports(snapshots_dir: Path) -> list[dict]:
    if not snapshots_dir.exists():
        return []
    reports: list[dict] = []
    for path in sorted(snapshots_dir.glob("*.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            continue
    reports.sort(key=lambda item: _parse_ts(item.get("meta", {}).get("generated_at", "")))
    return reports


def _trend_points(current_report: dict, snapshots_dir: Path) -> list[dict]:
    points: list[dict] = []
    for item in _load_snapshot_reports(snapshots_dir):
        meta = item.get("meta", {})
        points.append(
            {
                "ts": meta.get("generated_at", ""),
                "risk_score": _risk_score(item),
                "total": item.get("summary", {}).get("total", 0),
            }
        )
    points.append(
        {
            "ts": current_report.get("meta", {}).get("generated_at", ""),
            "risk_score": _risk_score(current_report),
            "total": current_report.get("summary", {}).get("total", 0),
        }
    )
    return points


def _module_status_matrix(report: dict) -> dict[str, dict[str, int]]:
    matrix = {module: {status: 0 for status in STATUS_ORDER} for module in MODULES}
    for item in report.get("results", []):
        module = item.get("module")
        status = item.get("status")
        if module in matrix and status in matrix[module]:
            matrix[module][status] += 1
    return matrix


def _top_risks(report: dict, top_n: int = 10) -> list[dict]:
    results = [item for item in report.get("results", []) if item.get("status") in {"error", "fail", "warn"}]
    def score(item: dict) -> int:
        return SEVERITY_WEIGHT.get(item.get("severity", "low"), 1) * STATUS_WEIGHT.get(item.get("status", "pass"), 0)
    return sorted(results, key=score, reverse=True)[:top_n]


def _build_html(report: dict, trend: list[dict], matrix: dict[str, dict[str, int]], top_risks: list[dict]) -> str:
    trend_json = json.dumps(trend, ensure_ascii=False)
    matrix_rows = []
    for module in MODULES:
        row = [f"<td>{module}</td>"]
        for status in STATUS_ORDER:
            value = matrix[module][status]
            color = {
                "error": "#fde2e2",
                "fail": "#fdecc8",
                "warn": "#fff8cc",
                "skipped": "#eef1f5",
                "pass": "#daf4dc",
            }[status]
            row.append(f"<td style='background:{color};text-align:center'>{value}</td>")
        matrix_rows.append("<tr>" + "".join(row) + "</tr>")

    top_rows = []
    for item in top_risks:
        top_rows.append(
            "<tr>"
            f"<td>{item.get('rule_id')}</td>"
            f"<td>{item.get('module')}</td>"
            f"<td>{item.get('status')}</td>"
            f"<td>{item.get('severity')}</td>"
            f"<td>{item.get('message')}</td>"
            "</tr>"
        )

    summary = report.get("summary", {})
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>SecBaseline 监控面板</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2937; }}
    h1, h2 {{ margin: 0 0 12px 0; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; }}
    th {{ background: #f3f4f6; }}
    .muted {{ color: #6b7280; font-size: 12px; }}
    #trend {{ width: 100%; height: 220px; border: 1px solid #d1d5db; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>SecBaseline 监控面板</h1>
  <p class="muted">生成时间：{report.get("meta", {}).get("generated_at", "")}</p>

  <div class="card">
    <h2>当前风险总览</h2>
    <p>总检查项：{summary.get("total", 0)}</p>
    <p>状态统计：{summary.get("status", {})}</p>
    <p>严重级别统计：{summary.get("severity", {})}</p>
    <p>风险分：{_risk_score(report)}</p>
  </div>

  <div class="card">
    <h2>模块热力图</h2>
    <table>
      <thead>
        <tr><th>module</th><th>error</th><th>fail</th><th>warn</th><th>skipped</th><th>pass</th></tr>
      </thead>
      <tbody>
        {"".join(matrix_rows)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>高风险项 Top 列表</h2>
    <table>
      <thead>
        <tr><th>rule_id</th><th>module</th><th>status</th><th>severity</th><th>message</th></tr>
      </thead>
      <tbody>
        {"".join(top_rows) if top_rows else "<tr><td colspan='5'>当前没有风险项。</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>风险趋势</h2>
    <svg id="trend" viewBox="0 0 1000 220" preserveAspectRatio="none"></svg>
  </div>

  <script>
    const points = {trend_json};
    const svg = document.getElementById("trend");
    const width = 1000;
    const height = 220;
    const padding = 24;
    const values = points.map(p => p.risk_score || 0);
    const maxVal = Math.max(1, ...values);
    const minVal = Math.min(0, ...values);
    const span = Math.max(1, maxVal - minVal);
    function x(i) {{
      if (points.length <= 1) return width / 2;
      return padding + (i * (width - padding * 2) / (points.length - 1));
    }}
    function y(v) {{
      return height - padding - ((v - minVal) * (height - padding * 2) / span);
    }}
    const path = points.map((p, i) => `${{i===0 ? "M" : "L"}}${{x(i)}},${{y(p.risk_score||0)}}`).join(" ");
    const poly = document.createElementNS("http://www.w3.org/2000/svg", "path");
    poly.setAttribute("d", path);
    poly.setAttribute("stroke", "#2563eb");
    poly.setAttribute("fill", "none");
    poly.setAttribute("stroke-width", "2");
    svg.appendChild(poly);
    points.forEach((p, i) => {{
      const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      c.setAttribute("cx", x(i));
      c.setAttribute("cy", y(p.risk_score||0));
      c.setAttribute("r", "3.5");
      c.setAttribute("fill", "#1d4ed8");
      svg.appendChild(c);
    }});
  </script>
</body>
</html>"""


def write_dashboard(report: dict, workspace: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "dashboard.html"
    trend = _trend_points(report, workspace / "snapshots")
    matrix = _module_status_matrix(report)
    top_risks = _top_risks(report)
    html = _build_html(report, trend, matrix, top_risks)
    path.write_text(html, encoding="utf-8")
    return path

from __future__ import annotations

import argparse
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from collectors.http import collect_http_data
from collectors.linux import collect_linux_data
from collectors.remote import collect_remote_linux_data, collect_remote_ssh_data, probe_remote_connection
from collectors.ssh import collect_ssh_data
from core.dashboard import write_dashboard
from core.drift import build_drift_report, load_report_file, write_drift_reports
from core.engine import evaluate_rules, load_rules
from core.fixer import apply_safe_fixes, finalize_fix_summary
from core.models import CheckResult
from core.reporter import build_report, write_reports


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecBaseline Linux security baseline audit tool")
    parser.add_argument("--target", default="local", choices=["local", "remote"], help="Audit target mode")
    parser.add_argument("--host", help="Remote host for --target remote")
    parser.add_argument("--user", help="Remote SSH user for --target remote")
    parser.add_argument("--port", type=int, default=22, help="Remote SSH port for --target remote")
    parser.add_argument("--remote-timeout", type=float, default=10.0, help="Remote SSH command timeout in seconds")
    parser.add_argument("--url", help="Optional URL for HTTP header checks")
    parser.add_argument("--output-dir", help="Output directory under current workspace")
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds for --url checks",
    )
    parser.add_argument("--profile", choices=["basic", "strict"], default="basic", help="Rule profile to run")
    parser.add_argument(
        "--rule-pack",
        choices=["full", "host", "web"],
        default="full",
        help="Rule package: full(host+web), host(linux+ssh), web(http)",
    )
    parser.add_argument(
        "--format",
        dest="report_format",
        default="both",
        help="Report formats: both or comma-separated json,md,sarif",
    )
    parser.add_argument(
        "--ignore-file",
        default=".secbaseline-ignore",
        help="Ignore file with one rule_id per line (default: .secbaseline-ignore)",
    )
    parser.add_argument(
        "--save",
        "--save-snapshot",
        dest="save_snapshot",
        action="store_true",
        help="Save current report snapshot to snapshots/",
    )
    parser.add_argument(
        "--name",
        "--snapshot-name",
        dest="snapshot_name",
        help="Optional snapshot file name when --save is enabled (e.g. baseline_v1.json)",
    )
    parser.add_argument("--diff-from", help="Baseline snapshot file name under snapshots/ (e.g. 20260419T010203Z.json)")
    parser.add_argument("--diff-to", help="Target snapshot file name under snapshots/ (for diff-only mode)")
    parser.add_argument(
        "--diff-view",
        choices=["all", "changes", "regressions"],
        default="changes",
        help="Drift view: all rows, changed rows, or regressions only",
    )
    parser.add_argument(
        "--diff-module",
        help="Optional module filter for drift, comma-separated: linux,ssh,http",
    )
    parser.add_argument(
        "--diff-top",
        type=int,
        default=10,
        help="Top N regressions in drift report",
    )
    parser.add_argument(
        "--interval",
        "--monitor-interval",
        dest="monitor_interval",
        type=float,
        default=0.0,
        help="Enable continuous monitoring when > 0 (seconds between scans). Alias: --monitor-interval",
    )
    parser.add_argument(
        "--count",
        "--monitor-count",
        dest="monitor_count",
        type=int,
        default=1,
        help="Number of monitor iterations when interval > 0; 0 means infinite. Alias: --monitor-count",
    )
    parser.add_argument(
        "--alert",
        "--alert-regressions",
        dest="alert_regressions",
        type=int,
        default=1,
        help="Trigger alert when regressions count >= this value. Alias: --alert-regressions",
    )
    parser.add_argument(
        "--alert-file",
        default="alerts",
        help="Alert file name under fixed alerts/ dir; .jsonl suffix auto-appended",
    )
    parser.add_argument("--alert-webhook", help="Optional webhook URL for alert POST")
    parser.add_argument("--fix", action="store_true", help="Apply safe local auto-fixes for selected failed rules")
    parser.add_argument("--dashboard", action="store_true", help="Generate output dashboard.html")
    return parser.parse_args(argv)


def build_skipped_results(http_rules, reason: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    for rule in http_rules:
        results.append(
            CheckResult(
                rule_id=rule.rule_id,
                name=rule.name,
                module=rule.module,
                status="skipped",
                severity=rule.severity,
                message=reason,
                evidence="--url not provided",
                compliance=rule.compliance,
                recommendation=rule.recommendation,
            )
        )
    return results


def normalize_report_formats(format_arg: str) -> set[str]:
    allowed = {"both", "json", "md", "sarif"}
    tokens = [token.strip().lower() for token in format_arg.split(",") if token.strip()]
    if not tokens:
        raise ValueError("format is empty")
    unknown = [token for token in tokens if token not in allowed]
    if unknown:
        raise ValueError(f"unsupported format: {','.join(unknown)}")
    if "both" in tokens:
        return {"json", "md", "sarif"}
    selected = set(tokens)
    if selected == {"json", "md", "sarif"}:
        return {"json", "md", "sarif"}
    return selected


def normalize_diff_modules(module_arg: str | None) -> set[str] | None:
    if not module_arg:
        return None
    allowed = {"linux", "ssh", "http"}
    tokens = [token.strip().lower() for token in module_arg.split(",") if token.strip()]
    if not tokens:
        return None
    unknown = [token for token in tokens if token not in allowed]
    if unknown:
        raise ValueError(f"unsupported diff module: {','.join(unknown)}")
    return set(tokens)


def _resolve_in_workspace(path_str: str, workspace: Path) -> Path:
    raw = Path(path_str)
    resolved = raw.resolve() if raw.is_absolute() else (workspace / raw).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"Path must stay under workspace: {workspace}") from exc
    return resolved


def resolve_output_dir(output_dir_arg: str | None, url: str | None, workspace: Path, diff_only: bool = False) -> Path:
    if output_dir_arg:
        return _resolve_in_workspace(output_dir_arg, workspace)
    if diff_only:
        return (workspace / "output_diff").resolve()
    default_name = "output_url" if url else "output"
    return (workspace / default_name).resolve()


def resolve_ignore_file(ignore_file_arg: str, workspace: Path) -> Path:
    return _resolve_in_workspace(ignore_file_arg, workspace)


def load_ignore_rule_ids(ignore_file: Path) -> set[str]:
    if not ignore_file.exists():
        return set()
    ignored: set[str] = set()
    for line in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        ignored.add(text)
    return ignored


def apply_ignored_rules(results: list[CheckResult], ignored_ids: set[str], ignore_file: Path) -> list[CheckResult]:
    if not ignored_ids:
        return results
    patched: list[CheckResult] = []
    for result in results:
        if result.rule_id in ignored_ids:
            patched.append(
                CheckResult(
                    rule_id=result.rule_id,
                    name=result.name,
                    module=result.module,
                    status="skipped",
                    severity=result.severity,
                    message="Rule ignored by ignore file.",
                    evidence=f"ignore_file={ignore_file.name}",
                    compliance=result.compliance,
                    recommendation=result.recommendation,
                )
            )
        else:
            patched.append(result)
    return patched


def cleanup_stale_drift_files(output_dir: Path) -> None:
    for name in ("drift.json", "drift.md"):
        path = output_dir / name
        if path.exists():
            path.unlink()


def cleanup_stale_report_files(output_dir: Path) -> None:
    for name in ("report.json", "report.md", "report.sarif"):
        path = output_dir / name
        if path.exists():
            path.unlink()


def _sanitize_snapshot_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise ValueError("snapshot name is empty")
    if "/" in normalized or "\\" in normalized:
        raise ValueError("snapshot name must be file name only, no path separators")
    if normalized in {".", ".."}:
        raise ValueError("invalid snapshot name")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", normalized):
        raise ValueError("snapshot name contains invalid characters")
    if not normalized.endswith(".json"):
        normalized = f"{normalized}.json"
    return normalized


def _build_auto_snapshot_name(snapshots_dir: Path) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    file_name = f"{stamp}.json"
    index = 1
    while (snapshots_dir / file_name).exists():
        file_name = f"{stamp}_{index}.json"
        index += 1
    return file_name


def save_snapshot(report: dict, workspace: Path, snapshot_name: str | None) -> Path:
    snapshots_dir = workspace / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    if snapshot_name:
        file_name = _sanitize_snapshot_name(snapshot_name)
        path = snapshots_dir / file_name
        if path.exists():
            raise ValueError(f"snapshot already exists: {path.name}")
    else:
        file_name = _build_auto_snapshot_name(snapshots_dir)
        path = snapshots_dir / file_name
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def resolve_snapshot_ref(snapshot_ref: str, workspace: Path) -> Path:
    snapshots_dir = workspace / "snapshots"
    filename = _sanitize_snapshot_name(snapshot_ref)
    path = (snapshots_dir / filename).resolve()
    if not path.exists():
        raise ValueError(f"snapshot not found in snapshots/: {filename}")
    return path


def resolve_drift_output_dir(workspace: Path) -> Path:
    return (workspace / "output_diff").resolve()


def resolve_alert_file(alert_file_arg: str, workspace: Path) -> Path:
    name = (alert_file_arg or "").strip()
    if not name:
        raise ValueError("--alert-file cannot be empty")
    if "/" in name or "\\" in name:
        raise ValueError("--alert-file only accepts a file name, not a path")
    if name in {".", ".."}:
        raise ValueError("invalid --alert-file name")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("--alert-file contains invalid characters")
    if not name.endswith(".jsonl"):
        name = f"{name}.jsonl"
    return (workspace / "alerts" / name).resolve()


def _validate_runtime_args(args: argparse.Namespace, diff_only: bool) -> str | None:
    if args.diff_to and not args.diff_from:
        return "--diff-to requires --diff-from"
    if args.diff_top <= 0:
        return "--diff-top must be greater than 0"
    if args.port <= 0:
        return "--port must be greater than 0"
    if args.remote_timeout <= 0:
        return "--remote-timeout must be greater than 0"
    if args.monitor_interval < 0:
        return "--interval must be >= 0"
    if args.monitor_count < 0:
        return "--count must be >= 0"
    if args.alert_regressions <= 0:
        return "--alert must be > 0"
    if args.target == "remote" and (not args.host or not args.user):
        return "--target remote requires --host and --user"
    if args.monitor_interval > 0 and diff_only:
        return "monitor mode cannot run with diff-only mode"
    if args.fix and args.target != "local":
        return "--fix only supports --target local"
    if args.fix and diff_only:
        return "--fix cannot run with diff-only mode"
    if args.fix and args.monitor_interval > 0:
        return "--fix cannot run with monitor mode"
    if args.dashboard and diff_only:
        return "--dashboard cannot run with diff-only mode"
    return None


def _collect_host_data(args: argparse.Namespace, required_modules: set[str]) -> tuple[dict, dict]:
    linux_data: dict = {}
    ssh_data: dict = {}
    if args.target == "remote" and ({"linux", "ssh"} & required_modules):
        ok, message = probe_remote_connection(
            host=args.host,
            user=args.user,
            port=args.port,
            timeout=args.remote_timeout,
        )
        if not ok:
            remote_error = {"__error": message or "remote connectivity check failed"}
            if "linux" in required_modules:
                linux_data = remote_error.copy()
            if "ssh" in required_modules:
                ssh_data = remote_error.copy()
            return linux_data, ssh_data

    if "linux" in required_modules:
        if args.target == "local":
            linux_data = collect_linux_data()
        else:
            linux_data = collect_remote_linux_data(
                host=args.host,
                user=args.user,
                port=args.port,
                timeout=args.remote_timeout,
                check_connection=False,
            )
    if "ssh" in required_modules:
        if args.target == "local":
            ssh_data = collect_ssh_data()
        else:
            ssh_data = collect_remote_ssh_data(
                host=args.host,
                user=args.user,
                port=args.port,
                timeout=args.remote_timeout,
                check_connection=False,
            )
    return linux_data, ssh_data


def _run_scan_once(
    args: argparse.Namespace,
    output_dir: Path,
    ignore_file: Path,
    report_formats: set[str],
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    cleanup_stale_drift_files(output_dir)
    cleanup_stale_report_files(output_dir)

    all_rules = load_rules(Path("rules"), profile=args.profile, rule_pack=args.rule_pack)
    linux_rules = [r for r in all_rules if r.module == "linux"]
    ssh_rules = [r for r in all_rules if r.module == "ssh"]
    http_rules = [r for r in all_rules if r.module == "http"]

    required_modules = {rule.module for rule in all_rules}
    linux_data, ssh_data = _collect_host_data(args, required_modules)
    http_data: dict | None = None
    remote_error = linux_data.get("__error") or ssh_data.get("__error")
    if args.target == "remote" and remote_error:
        print(f"Remote scan warning: {remote_error}")

    results: list[CheckResult] = []
    if linux_rules:
        results.extend(evaluate_rules(linux_rules, linux_data))
    if ssh_rules:
        results.extend(evaluate_rules(ssh_rules, ssh_data))
        if ssh_data.get("match_ignored"):
            results.append(
                CheckResult(
                    rule_id="SSH-WARN-001",
                    name="Match block ignored notice",
                    module="ssh",
                    status="warn",
                    severity="low",
                    message="Match block found in sshd_config; this MVP ignores Match semantics.",
                    evidence="Found 'Match ' in sshd_config",
                    compliance=["CIS-SSH-1.0"],
                    recommendation="Manually review Match blocks for strict audit coverage.",
                )
            )

    if http_rules:
        if args.url:
            http_data = collect_http_data(args.url, timeout=args.http_timeout)
            results.extend(evaluate_rules(http_rules, http_data))
        else:
            results.extend(build_skipped_results(http_rules, "HTTP checks skipped because --url was not provided."))

    ignored_ids = load_ignore_rule_ids(ignore_file)
    results = apply_ignored_rules(results, ignored_ids, ignore_file)

    evidence_bundle = {
        "target_context": {
            "target": args.target,
            "host": args.host if args.target == "remote" else None,
            "user": args.user if args.target == "remote" else None,
            "port": args.port if args.target == "remote" else None,
            "rule_pack": args.rule_pack,
        },
        "modules": {
            "linux": linux_data if linux_rules else {},
            "ssh": ssh_data if ssh_rules else {},
            "http": http_data if http_rules and args.url else ({"skipped": True} if http_rules else {}),
        },
    }

    report = build_report(
        results=results,
        target=args.target,
        url=args.url,
        meta_extra={
            "profile": args.profile,
            "rule_pack": args.rule_pack,
            "http_timeout": args.http_timeout,
            "remote_timeout": args.remote_timeout,
            "format": args.report_format,
            "format_resolved": sorted(report_formats),
            "ignored_rule_count": len(ignored_ids),
            "ignore_file": ignore_file.name if ignore_file.exists() else None,
            "host": args.host if args.target == "remote" else None,
            "user": args.user if args.target == "remote" else None,
            "port": args.port if args.target == "remote" else None,
        },
        evidence_bundle=evidence_bundle,
    )
    written = write_reports(report=report, output_dir=output_dir, report_formats=report_formats)
    written_files = ", ".join([str(path.name) for path in written.values()])
    print(f"SecBaseline completed. Reports written to: {output_dir} ({written_files})")
    return report


def _emit_alert(alert_payload: dict, alert_file: Path, webhook: str | None) -> None:
    alert_file.parent.mkdir(parents=True, exist_ok=True)
    with alert_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(alert_payload, ensure_ascii=False) + "\n")

    if webhook:
        try:
            import requests

            host = (urlparse(webhook).hostname or "").lower()
            is_slack = "hooks.slack.com" in host
            payload = alert_payload
            if is_slack:
                text = (
                    "[SecBaseline] drift_regression "
                    f"regressions={alert_payload.get('regressions')} "
                    f"threshold={alert_payload.get('threshold')} "
                    f"target={alert_payload.get('target')} "
                    f"snapshot={alert_payload.get('current_snapshot')}"
                )
                payload = {"text": text}

            last_error: Exception | None = None
            last_response = None
            for _ in range(2):
                try:
                    response = requests.post(webhook, json=payload, timeout=10)
                    last_response = response
                    if 200 <= response.status_code < 300:
                        return
                except Exception as exc:
                    last_error = exc

            if last_response is not None:
                print(
                    "Alert webhook failed: "
                    f"status={last_response.status_code}, body={(last_response.text or '').strip()[:200]}"
                )
            elif last_error is not None:
                print(f"Alert webhook failed: {last_error}")
        except Exception as exc:
            print(f"Alert webhook failed: {exc}")


def _run_monitor_mode(
    args: argparse.Namespace,
    workspace: Path,
    output_dir: Path,
    ignore_file: Path,
    report_formats: set[str],
    diff_modules: set[str] | None,
    diff_formats: set[str],
    drift_output_dir: Path,
    diff_from_path: Path | None,
    alert_file: Path,
) -> int:
    if getattr(args, "dashboard", False):
        print("SecBaseline monitor notice: --dashboard is ignored in monitor mode.")
    previous_report: dict | None = load_report_file(diff_from_path) if diff_from_path else None
    previous_snapshot: str | None = diff_from_path.name if diff_from_path else None

    iteration = 0
    max_iterations = args.monitor_count
    try:
        while max_iterations == 0 or iteration < max_iterations:
            report = _run_scan_once(args, output_dir, ignore_file, report_formats)
            snapshot_path = save_snapshot(report, workspace, None)
            print(f"Snapshot saved: {snapshot_path}")

            if previous_report is not None:
                drift = build_drift_report(
                    previous_report,
                    report,
                    module_filter=diff_modules,
                    diff_view=args.diff_view,
                    top_n=args.diff_top,
                )
                drift_written = write_drift_reports(drift, drift_output_dir, drift_formats=diff_formats)
                print(
                    "SecBaseline drift completed. "
                    f"Reports written to: {drift_output_dir} ({', '.join([p.name for p in drift_written.values()])})"
                )
                regressions = drift.get("summary", {}).get("regressions", 0)
                if regressions >= args.alert_regressions:
                    alert_payload = {
                        "tool": "SecBaseline",
                        "generated_at": datetime.now(UTC).isoformat(),
                        "type": "drift_regression",
                        "threshold": args.alert_regressions,
                        "regressions": regressions,
                        "weighted_net_score": drift.get("summary", {}).get("weighted_net_score"),
                        "previous_snapshot": previous_snapshot,
                        "current_snapshot": snapshot_path.name,
                        "target": args.target,
                        "host": args.host if args.target == "remote" else None,
                    }
                    _emit_alert(alert_payload, alert_file, args.alert_webhook)
                    print(
                        "SecBaseline alert triggered. "
                        f"regressions={regressions}, threshold={args.alert_regressions}, alert_file={alert_file}"
                    )

            previous_report = report
            previous_snapshot = snapshot_path.name
            iteration += 1
            if max_iterations == 0 or iteration < max_iterations:
                print(f"SecBaseline monitor waiting {args.monitor_interval}s before next scan...")
                time.sleep(args.monitor_interval)
        return 0
    except KeyboardInterrupt:
        print("SecBaseline monitor interrupted by user (Ctrl+C).")
        return 130


def main() -> int:
    args = parse_args()
    workspace = Path.cwd().resolve()
    diff_only = bool(args.diff_from and args.diff_to)

    arg_error = _validate_runtime_args(args, diff_only)
    if arg_error:
        print(f"Argument error: {arg_error}")
        return 2

    try:
        output_dir = resolve_output_dir(args.output_dir, args.url, workspace, diff_only=diff_only)
        ignore_file = resolve_ignore_file(args.ignore_file, workspace)
        report_formats = normalize_report_formats(args.report_format)
        diff_modules = normalize_diff_modules(args.diff_module)
        diff_from_path = resolve_snapshot_ref(args.diff_from, workspace) if args.diff_from else None
        diff_to_path = resolve_snapshot_ref(args.diff_to, workspace) if args.diff_to else None
        alert_file = resolve_alert_file(args.alert_file, workspace)
    except ValueError as exc:
        print(f"Argument error: {exc}")
        return 2

    drift_output_dir = output_dir if diff_only else resolve_drift_output_dir(workspace)
    diff_formats = report_formats & {"json", "md"}

    if args.monitor_interval > 0:
        return _run_monitor_mode(
            args=args,
            workspace=workspace,
            output_dir=output_dir,
            ignore_file=ignore_file,
            report_formats=report_formats,
            diff_modules=diff_modules,
            diff_formats=diff_formats,
            drift_output_dir=drift_output_dir,
            diff_from_path=diff_from_path,
            alert_file=alert_file,
        )

    if diff_only and diff_from_path and diff_to_path:
        old_report = load_report_file(diff_from_path)
        new_report = load_report_file(diff_to_path)
        drift = build_drift_report(
            old_report,
            new_report,
            module_filter=diff_modules,
            diff_view=args.diff_view,
            top_n=args.diff_top,
        )
        written = write_drift_reports(drift, drift_output_dir, drift_formats=diff_formats)
        print(
            "SecBaseline drift completed. "
            f"Reports written to: {drift_output_dir} ({', '.join([p.name for p in written.values()])})"
        )
        return 0

    report = _run_scan_once(args, output_dir, ignore_file, report_formats)

    if args.fix:
        fix_summary = apply_safe_fixes(report, output_dir)
        if fix_summary.get("actions"):
            print("SecBaseline fix applied. Re-running scan for verification...")
            report_after_fix = _run_scan_once(args, output_dir, ignore_file, report_formats)
            final_summary = finalize_fix_summary(report, report_after_fix, fix_summary, output_dir)
            print(
                "SecBaseline fix summary: "
                f"improved={final_summary.get('improved_count', 0)}, "
                f"rollback={final_summary.get('rollback_script')}"
            )
            report = report_after_fix
        else:
            print("SecBaseline fix: no fixable failed rules found.")

    if args.save_snapshot:
        try:
            snapshot_path = save_snapshot(report, workspace, args.snapshot_name)
            print(f"Snapshot saved: {snapshot_path}")
        except ValueError as exc:
            print(f"Argument error: {exc}")
            return 2

    if diff_from_path:
        old_report = load_report_file(diff_from_path)
        drift = build_drift_report(
            old_report,
            report,
            module_filter=diff_modules,
            diff_view=args.diff_view,
            top_n=args.diff_top,
        )
        drift_written = write_drift_reports(drift, drift_output_dir, drift_formats=diff_formats)
        print(
            "SecBaseline drift completed. "
            f"Reports written to: {drift_output_dir} ({', '.join([p.name for p in drift_written.values()])})"
        )

    if args.dashboard:
        dashboard_path = write_dashboard(report, workspace=workspace, output_dir=output_dir)
        print(f"SecBaseline dashboard written: {dashboard_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

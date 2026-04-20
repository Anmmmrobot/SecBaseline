import json
import shutil
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from collectors.remote import probe_remote_connection
from main import _emit_alert, _run_monitor_mode, parse_args


class _WebhookHandler(BaseHTTPRequestHandler):
    received_body: str | None = None

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _WebhookHandler.received_body = self.rfile.read(length).decode("utf-8")
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003
        return


class TestMonitorAndRemote(unittest.TestCase):
    def setUp(self):
        self.workspace = (Path.cwd() / f".test_tmp_monitor_{uuid.uuid4().hex}").resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_short_alias_args(self):
        args = parse_args(["--interval", "5", "--count", "2", "--alert", "3"])
        self.assertEqual(args.monitor_interval, 5.0)
        self.assertEqual(args.monitor_count, 2)
        self.assertEqual(args.alert_regressions, 3)

    @patch("collectors.remote._run_ssh")
    def test_remote_probe_human_readable_error(self, mock_run_ssh):
        mock_run_ssh.return_value = "command_error:Connection timed out"
        ok, message = probe_remote_connection("10.0.0.12", "root", 22, timeout=3)
        self.assertFalse(ok)
        self.assertIn("远程主机不可达", message or "")
        self.assertIn("连接超时", message or "")

    def test_emit_alert_write_file_and_webhook(self):
        server = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            alert_file = self.workspace / "alerts" / "alerts.jsonl"
            payload = {"tool": "SecBaseline", "regressions": 2}
            _emit_alert(payload, alert_file, f"http://127.0.0.1:{port}/hook")

            self.assertTrue(alert_file.exists())
            file_data = alert_file.read_text(encoding="utf-8").strip()
            self.assertIn('"regressions": 2', file_data)

            self.assertIsNotNone(_WebhookHandler.received_body)
            posted = json.loads(_WebhookHandler.received_body or "{}")
            self.assertEqual(posted.get("regressions"), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @patch("requests.post")
    def test_emit_alert_slack_send_text_payload(self, mock_post: MagicMock):
        r1 = MagicMock()
        r1.status_code = 200
        r1.text = "ok"
        mock_post.return_value = r1

        alert_file = self.workspace / "alerts" / "alerts.jsonl"
        payload = {"tool": "SecBaseline", "regressions": 2, "threshold": 1, "target": "local", "current_snapshot": "x"}
        _emit_alert(payload, alert_file, "https://hooks.slack.com/services/T/A/B")

        self.assertEqual(mock_post.call_count, 1)
        first_call = mock_post.call_args_list[0]
        self.assertIn("text", first_call.kwargs["json"])

    @patch("main.time.sleep", side_effect=KeyboardInterrupt)
    @patch("main.save_snapshot")
    @patch("main._run_scan_once")
    def test_monitor_ctrl_c_graceful_exit(self, mock_scan_once, mock_save_snapshot, _mock_sleep):
        mock_scan_once.return_value = {"meta": {}, "summary": {}, "results": []}
        mock_save_snapshot.return_value = self.workspace / "snapshots" / "demo.json"
        args = SimpleNamespace(
            monitor_count=2,
            monitor_interval=1.0,
            diff_view="changes",
            diff_top=10,
            alert_regressions=1,
            alert_webhook=None,
            target="local",
            host=None,
        )
        rc = _run_monitor_mode(
            args=args,
            workspace=self.workspace,
            output_dir=self.workspace / "output",
            ignore_file=self.workspace / ".secbaseline-ignore",
            report_formats={"json"},
            diff_modules=None,
            diff_formats={"json"},
            drift_output_dir=self.workspace / "output_diff",
            diff_from_path=None,
            alert_file=self.workspace / "alerts" / "alerts.jsonl",
        )
        self.assertEqual(rc, 130)


if __name__ == "__main__":
    unittest.main()

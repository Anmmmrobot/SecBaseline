from __future__ import annotations

import re
import stat
import subprocess

from collectors.ssh import parse_sshd_config_text

REMOTE_ERROR_HINTS = [
    ("name or service not known", "主机名无法解析"),
    ("could not resolve hostname", "主机名无法解析"),
    ("timed out", "连接超时，主机不可达或端口被阻断"),
    ("connection timed out", "连接超时，主机不可达或端口被阻断"),
    ("operation timed out", "连接超时，主机不可达或端口被阻断"),
    ("no route to host", "网络不可达（No route to host）"),
    ("connection refused", "端口拒绝连接（Connection refused）"),
    ("permission denied", "认证失败（账号/密钥/密码）"),
    ("host key verification failed", "主机指纹校验失败"),
    ("network is unreachable", "网络不可达（Network is unreachable）"),
]


def _classify_remote_error(raw: str) -> str:
    text = (raw or "").lower()
    for key, hint in REMOTE_ERROR_HINTS:
        if key in text:
            return hint
    return "远程连接失败，请检查主机、端口、网络和认证配置"


def _format_remote_error(host: str, user: str, port: int, raw: str) -> str:
    hint = _classify_remote_error(raw)
    brief = (raw or "").strip().replace("\n", " ")
    if len(brief) > 220:
        brief = brief[:220] + "..."
    return f"远程主机不可达: {user}@{host}:{port}; 原因={hint}; 细节={brief}"


def _run_ssh(host: str, user: str, port: int, command: str, timeout: float = 10.0) -> str:
    target = f"{user}@{host}"
    connect_timeout = max(2, min(8, int(timeout)))
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "ConnectionAttempts=1",
        "-p",
        str(port),
        target,
        command,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        output = (completed.stdout or "") + (completed.stderr or "")
        if completed.returncode != 0:
            return f"command_error:rc={completed.returncode}:{output.strip()}"
        return output
    except Exception as exc:
        return f"command_error:{exc}"


def probe_remote_connection(host: str, user: str, port: int = 22, timeout: float = 10.0) -> tuple[bool, str | None]:
    output = _run_ssh(host, user, port, "echo __SECB_OK__", timeout=timeout)
    if output.startswith("command_error:"):
        return False, _format_remote_error(host, user, port, output)
    if "__SECB_OK__" not in output:
        return False, _format_remote_error(host, user, port, output)
    return True, None


def _parse_mode(mode_str: str) -> tuple[str | None, bool]:
    cleaned = (mode_str or "").strip()
    if not cleaned or not cleaned.isdigit():
        return None, False
    mode_int = int(cleaned, 8)
    world_writable = bool(mode_int & stat.S_IWOTH)
    return cleaned, world_writable


def _parse_shadow_restricted(mode_str: str) -> tuple[str | None, bool]:
    cleaned = (mode_str or "").strip()
    if not cleaned or not cleaned.isdigit():
        return None, False
    mode_int = int(cleaned, 8)
    group_write = bool(mode_int & stat.S_IWGRP)
    other_read = bool(mode_int & stat.S_IROTH)
    other_write = bool(mode_int & stat.S_IWOTH)
    restricted = not group_write and not other_read and not other_write
    return cleaned, restricted


def _parse_listening_ports(output: str) -> tuple[list[str], str]:
    if output.startswith("command_error:"):
        return [], output
    ports: list[str] = []
    for line in output.splitlines():
        if "LISTEN" not in line:
            continue
        matches = re.findall(r":(\d+)\s", line + " ")
        ports.extend(matches)
    ports = sorted(set(ports), key=int)
    return ports, ",".join(ports)


def _remote_firewall_status(host: str, user: str, port: int, timeout: float) -> str:
    output = _run_ssh(
        host,
        user,
        port,
        "if command -v ufw >/dev/null 2>&1; then ufw status; "
        "elif command -v nft >/dev/null 2>&1; then nft list ruleset; "
        "elif command -v iptables >/dev/null 2>&1; then iptables -L; "
        "else echo unknown; fi",
        timeout=timeout,
    )
    if output.startswith("command_error:"):
        return "unknown"
    if "Status: active" in output or "table " in output or "Chain " in output:
        return "active"
    if "Status: inactive" in output:
        return "inactive"
    if output.strip() == "unknown":
        return "unknown"
    return "inactive"


def _remote_sysctl_int(host: str, user: str, port: int, timeout: float, key: str) -> int | None:
    output = _run_ssh(host, user, port, f"sysctl -n {key} 2>/dev/null || true", timeout=timeout).strip()
    if output.startswith("command_error:") or not output:
        return None
    try:
        return int(output.splitlines()[0].strip())
    except ValueError:
        return None


def collect_remote_linux_data(
    host: str,
    user: str,
    port: int = 22,
    timeout: float = 10.0,
    check_connection: bool = True,
) -> dict:
    try:
        if check_connection:
            ok, message = probe_remote_connection(host, user, port, timeout=timeout)
            if not ok:
                return {"__error": message or "remote connectivity check failed"}

        passwd_exists_out = _run_ssh(host, user, port, "if [ -e /etc/passwd ]; then echo 1; else echo 0; fi", timeout=timeout)
        passwd_exists = passwd_exists_out.strip().startswith("1")

        passwd_mode_out = _run_ssh(host, user, port, "stat -c '%a' /etc/passwd 2>/dev/null || true", timeout=timeout)
        passwd_mode, passwd_world_writable = _parse_mode(passwd_mode_out.strip())

        shadow_mode_out = _run_ssh(host, user, port, "stat -c '%a' /etc/shadow 2>/dev/null || true", timeout=timeout)
        shadow_mode, shadow_restricted = _parse_shadow_restricted(shadow_mode_out.strip())

        uid0_out = _run_ssh(host, user, port, "awk -F: '$3==0{c++} END{print c+0}' /etc/passwd 2>/dev/null || echo 0", timeout=timeout)
        uid0_count = 0
        try:
            uid0_count = int(uid0_out.strip().splitlines()[0])
        except Exception:
            uid0_count = 0

        ports_out = _run_ssh(host, user, port, "ss -tuln 2>/dev/null || true", timeout=timeout)
        listening_ports_list, listening_ports_csv = _parse_listening_ports(ports_out)

        os_release = _run_ssh(
            host,
            user,
            port,
            "source /etc/os-release 2>/dev/null; echo \"${ID:-}\"; echo \"${VERSION_ID:-}\"",
            timeout=timeout,
        )
        os_lines = [line.strip() for line in os_release.splitlines() if line.strip()]
        os_id = os_lines[0] if os_lines else None
        os_version_id = os_lines[1] if len(os_lines) > 1 else None

        return {
            "passwd_exists": passwd_exists,
            "passwd_permission": passwd_mode,
            "passwd_world_writable": passwd_world_writable,
            "shadow_permission": shadow_mode,
            "shadow_restricted": shadow_restricted,
            "root_uid_exists": uid0_count > 0,
            "uid0_account_count": uid0_count,
            "listening_ports": listening_ports_csv,
            "listening_ports_list": listening_ports_list,
            "listening_port_count": len(listening_ports_list),
            "has_telnet_port": "23" in listening_ports_list,
            "has_ssh_port": "22" in listening_ports_list,
            "firewall_status": _remote_firewall_status(host, user, port, timeout),
            "os_id": os_id,
            "os_version_id": os_version_id,
            "kernel_ip_forward": _remote_sysctl_int(host, user, port, timeout, "net.ipv4.ip_forward"),
            "kernel_aslr": _remote_sysctl_int(host, user, port, timeout, "kernel.randomize_va_space"),
        }
    except Exception as exc:
        return {"__error": str(exc)}


def collect_remote_ssh_data(
    host: str,
    user: str,
    port: int = 22,
    timeout: float = 10.0,
    check_connection: bool = True,
) -> dict:
    try:
        if check_connection:
            ok, message = probe_remote_connection(host, user, port, timeout=timeout)
            if not ok:
                return {"__error": message or "remote connectivity check failed"}

        exists_out = _run_ssh(host, user, port, "if [ -f /etc/ssh/sshd_config ]; then echo 1; else echo 0; fi", timeout=timeout)
        exists = exists_out.strip().startswith("1")
        if not exists:
            return parse_sshd_config_text("", exists=False)
        content = _run_ssh(host, user, port, "cat /etc/ssh/sshd_config 2>/dev/null || true", timeout=timeout)
        if content.startswith("command_error:"):
            return {"__error": content}
        return parse_sshd_config_text(content, exists=True)
    except Exception as exc:
        return {"__error": str(exc)}

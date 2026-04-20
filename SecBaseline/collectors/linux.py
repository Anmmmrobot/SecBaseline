from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path


def _run_command(cmd: list[str]) -> str:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
        return (completed.stdout or "") + (completed.stderr or "")
    except Exception as exc:
        return f"command_error:{exc}"


def _file_mode_info(path_str: str) -> tuple[str | None, bool]:
    path = Path(path_str)
    if not path.exists():
        return None, False
    mode = stat.S_IMODE(path.stat().st_mode)
    mode_str = oct(mode)[2:]
    world_writable = bool(mode & stat.S_IWOTH)
    return mode_str, world_writable


def _get_shadow_permission() -> tuple[str | None, bool]:
    shadow_path = Path("/etc/shadow")
    if not shadow_path.exists():
        return None, False
    mode = stat.S_IMODE(shadow_path.stat().st_mode)
    mode_str = oct(mode)[2:]
    group_write = bool(mode & stat.S_IWGRP)
    other_read = bool(mode & stat.S_IROTH)
    other_write = bool(mode & stat.S_IWOTH)
    restricted = not group_write and not other_read and not other_write
    return mode_str, restricted


def _uid0_stats() -> tuple[bool, int]:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return False, 0
    count = 0
    for line in passwd.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            count += 1
    return count > 0, count


def _get_listening_ports() -> tuple[list[str], str]:
    output = _run_command(["ss", "-tuln"])
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


def _get_firewall_status() -> str:
    ufw = _run_command(["ufw", "status"])
    if not ufw.startswith("command_error:"):
        if "Status: active" in ufw:
            return "active"
        if "Status: inactive" in ufw:
            return "inactive"

    nft = _run_command(["nft", "list", "ruleset"])
    if not nft.startswith("command_error:"):
        if "table " in nft:
            return "active"
        return "inactive"

    iptables = _run_command(["iptables", "-L"])
    if not iptables.startswith("command_error:"):
        if "Chain " in iptables:
            return "active"
        return "inactive"

    return "unknown"


def _parse_os_release() -> tuple[str | None, str | None]:
    path = Path("/etc/os-release")
    if not path.exists():
        return None, None
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line or line.strip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values.get("ID"), values.get("VERSION_ID")


def _sysctl_int(param: str) -> int | None:
    output = _run_command(["sysctl", "-n", param]).strip()
    if output.startswith("command_error:"):
        return None
    try:
        return int(output)
    except ValueError:
        return None


def collect_linux_data() -> dict:
    try:
        passwd_mode, passwd_world_writable = _file_mode_info("/etc/passwd")
        shadow_mode, shadow_restricted = _get_shadow_permission()
        root_uid_exists, uid0_account_count = _uid0_stats()
        listening_ports_list, listening_ports_csv = _get_listening_ports()
        os_id, os_version_id = _parse_os_release()
        return {
            "passwd_exists": Path("/etc/passwd").exists(),
            "passwd_permission": passwd_mode,
            "passwd_world_writable": passwd_world_writable,
            "shadow_permission": shadow_mode,
            "shadow_restricted": shadow_restricted,
            "root_uid_exists": root_uid_exists,
            "uid0_account_count": uid0_account_count,
            "listening_ports": listening_ports_csv,
            "listening_ports_list": listening_ports_list,
            "listening_port_count": len(listening_ports_list),
            "has_telnet_port": "23" in listening_ports_list,
            "has_ssh_port": "22" in listening_ports_list,
            "firewall_status": _get_firewall_status(),
            "os_id": os_id,
            "os_version_id": os_version_id,
            "kernel_ip_forward": _sysctl_int("net.ipv4.ip_forward"),
            "kernel_aslr": _sysctl_int("kernel.randomize_va_space"),
        }
    except Exception as exc:
        return {"__error": str(exc)}

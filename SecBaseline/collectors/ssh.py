from __future__ import annotations

from pathlib import Path


def _empty_ssh_data() -> dict:
    return {
        "sshd_config_exists": False,
        "PermitRootLogin": None,
        "PasswordAuthentication": None,
        "Port": None,
        "MaxAuthTries": None,
        "ClientAliveInterval": None,
        "match_ignored": False,
    }


def parse_sshd_config_text(content: str, exists: bool = True) -> dict:
    data = _empty_ssh_data()
    data["sshd_config_exists"] = exists
    if not exists:
        return data

    try:
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("match "):
                data["match_ignored"] = True
                break
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0], parts[1].strip()
            if key in data:
                data[key] = value
        return data
    except Exception as exc:
        return {"__error": str(exc)}


def collect_ssh_data(config_path: str = "/etc/ssh/sshd_config") -> dict:
    path = Path(config_path)
    if not path.exists():
        return _empty_ssh_data()
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return parse_sshd_config_text(content, exists=True)
    except Exception as exc:
        return {"__error": str(exc)}

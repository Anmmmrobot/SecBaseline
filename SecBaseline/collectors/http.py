from __future__ import annotations

import requests


def collect_http_data(url: str, timeout: float = 5.0) -> dict:
    try:
        response = requests.get(url, timeout=timeout)
        headers = {k.lower(): v for k, v in response.headers.items()}
        server_value = headers.get("server", "")
        return {
            "url": url,
            "status_code": response.status_code,
            "has_hsts": "strict-transport-security" in headers,
            "has_csp": "content-security-policy" in headers,
            "has_x_frame_options": "x-frame-options" in headers,
            "has_x_content_type_options": "x-content-type-options" in headers,
            "server_exposed": bool(server_value.strip()),
            "server_header": server_value,
        }
    except Exception as exc:
        return {"__error": str(exc)}

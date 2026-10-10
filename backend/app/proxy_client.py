"""Internal control client for the allowlisting scanner egress proxy."""
from __future__ import annotations

import http.client
import json
from urllib.parse import urlsplit

from .config import settings


class ProxyControlError(RuntimeError):
    pass


class ProxyTargetRejected(ProxyControlError):
    pass


def proxy_control(path: str, payload: dict) -> dict:
    if not settings.proxy_url or not settings.proxy_key:
        raise ProxyControlError("The egress proxy is not configured")
    if not path.startswith("/__control/"):
        raise ProxyControlError("Invalid proxy control route")
    endpoint = urlsplit(settings.proxy_url)
    if endpoint.scheme != "http" or not endpoint.hostname or endpoint.port is None:
        raise ProxyControlError("The egress proxy endpoint is invalid")
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    conn = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Scanner-Proxy-Key": settings.proxy_key,
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        data = response.read(16 * 1024)
        if response.status == 400:
            raise ProxyTargetRejected("The egress proxy rejected the target")
        if response.status != 200:
            raise ProxyControlError("The egress proxy rejected a control request")
        result = json.loads(data.decode("utf-8"))
        if not isinstance(result, dict):
            raise ProxyControlError("The egress proxy returned an invalid response")
        return result
    except ProxyControlError:
        raise
    except (OSError, http.client.HTTPException, UnicodeError, json.JSONDecodeError):
        raise ProxyControlError("The egress proxy control service is unavailable") from None
    finally:
        conn.close()


def register_scan_policy(scan_id: str, hostname: str, path_scope: str) -> None:
    proxy_control("/__control/register", {"scan_id": scan_id, "hostname": hostname, "path_scope": path_scope})


def revoke_scan_policy(scan_id: str) -> None:
    try:
        proxy_control("/__control/revoke", {"scan_id": scan_id})
    except ProxyControlError:
        # Policies expire automatically. Never hide the result of a completed scan.
        pass


def validate_public_host(hostname: str, port: int) -> None:
    result = proxy_control("/__control/check-host", {"hostname": hostname, "port": port})
    if result.get("public") is not True:
        raise ProxyControlError("The hostname did not validate as public")


def check_dns_records(hostname: str) -> dict[str, bool | None]:
    result = proxy_control("/__control/dns-check", {"hostname": hostname})
    if result.get("available") is not True:
        raise ProxyControlError("DNS checks are unavailable")
    return {key: result.get(key) for key in ("dnssec_ds", "caa", "spf", "dmarc")}


def check_dns_txt(hostname: str, txt_name: str, expected_hash: str) -> bool:
    result = proxy_control("/__control/verify-txt", {"hostname": hostname, "txt_name": txt_name, "expected_hash": expected_hash})
    return result.get("verified") is True

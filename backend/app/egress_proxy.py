"""Small allowlisting egress proxy for isolated scanner workers.

The proxy is intentionally not exposed on the host. Workers can reach it on an
internal Docker network; only this container joins the outbound network. Every
new destination is resolved and pinned here, and each scan is restricted to its
registered hostname (plain HTTP paths are additionally checked here).
"""
from __future__ import annotations

import base64
import hmac
import hashlib
import json
import os
import re
import select
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .security import (
    TargetValidationError,
    is_path_in_scope,
    normalize_hostname,
    normalize_path_scope,
    resolve_public_addresses,
)

MAX_HEADERS = 16 * 1024
MAX_CONTROL_BODY = 16 * 1024
MAX_TUNNEL_BYTES = 8 * 1024 * 1024
MAX_CONNECTION_SECONDS = 40


@dataclass
class Policy:
    scan_id: str
    hostname: str
    path_scope: str
    expires_at: float
    request_count: int = 0
    last_request_at: float = 0.0


class PolicyManager:
    def __init__(self, key: str):
        self.key = key
        self._policies: dict[str, Policy] = {}
        self._lock = threading.Lock()

    def register(self, scan_id: str, hostname: str, path_scope: str) -> None:
        if not scan_id or len(scan_id) > 64 or any(c not in "0123456789abcdef-" for c in scan_id.lower()):
            raise ValueError("Invalid scan ID")
        hostname = normalize_hostname(hostname)
        path_scope = normalize_path_scope(path_scope)
        # Check before issuing a policy, then resolve and pin again on each connect.
        resolve_public_addresses(hostname, 443)
        with self._lock:
            self._purge_locked()
            if len(self._policies) >= 64:
                raise ValueError("The scanner proxy is at capacity")
            self._policies[scan_id] = Policy(scan_id, hostname, path_scope, time.monotonic() + 15 * 60)

    def revoke(self, scan_id: str) -> None:
        with self._lock:
            self._policies.pop(scan_id, None)

    def _purge_locked(self) -> None:
        now = time.monotonic()
        for key in [key for key, policy in self._policies.items() if policy.expires_at < now]:
            self._policies.pop(key, None)

    def authorize(self, scan_id: str, key: str, hostname: str, port: int) -> Policy:
        if not hmac.compare_digest((key or "").encode("utf-8"), self.key.encode("utf-8")):
            raise PermissionError("Proxy authorization failed")
        host = normalize_hostname(hostname)
        if port not in (80, 443):
            raise PermissionError("Only standard web ports are allowed")
        with self._lock:
            self._purge_locked()
            policy = self._policies.get(scan_id)
            if policy is None or policy.hostname != host:
                raise PermissionError("Destination is outside the active scan policy")
            now = time.monotonic()
            if policy.request_count >= 100:
                raise PermissionError("The scan connection budget is exhausted")
            if policy.last_request_at and now - policy.last_request_at < 0.20:
                raise BlockingIOError("The scan request rate is limited")
            policy.last_request_at = now
            policy.request_count += 1
            return policy


def _resolve_dns_records(hostname: str) -> dict[str, Any]:
    """Return DNS record-presence booleans only; never return DNS TXT values."""
    try:
        import dns.resolver
    except ImportError:
        return {"available": False, "dnssec_ds": None, "caa": None, "spf": None, "dmarc": None}

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 4

    def answer(name: str, record_type: str):
        try:
            result = resolver.resolve(name, record_type, raise_on_no_answer=False, lifetime=4)
            if result.rrset is None:
                return []
            return list(result)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            return []
        except Exception:
            return None

    ds = answer(hostname, "DS")
    caa = answer(hostname, "CAA")
    txt = answer(hostname, "TXT")
    dmarc = answer(f"_dmarc.{hostname}", "TXT")

    def values(records):
        if records is None:
            return None
        output: list[str] = []
        for record in records:
            chunks = getattr(record, "strings", None)
            if chunks:
                output.append(b"".join(chunks).decode("utf-8", "ignore").lower())
            else:
                output.append(str(record).strip('"').lower())
        return output

    txt_values = values(txt)
    dmarc_values = values(dmarc)
    return {
        "available": True,
        "dnssec_ds": None if ds is None else bool(ds),
        "caa": None if caa is None else bool(caa),
        "spf": None if txt_values is None else any(value.startswith("v=spf1") for value in txt_values),
        "dmarc": None if dmarc_values is None else any(value.startswith("v=dmarc1") for value in dmarc_values),
    }


def verify_dns_txt(hostname: str, txt_name: str, expected_hash: str) -> bool:
    try:
        import dns.resolver
    except ImportError:
        return False
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 4
    try:
        result = resolver.resolve(txt_name, "TXT", lifetime=4)
    except Exception:
        return False
    for record in result:
        chunks = getattr(record, "strings", ())
        value = b"".join(chunks) if chunks else str(record).strip('"').encode("utf-8")
        if hmac.compare_digest(hashlib.sha256(value).hexdigest(), expected_hash):
            return True
    return False


def _read_headers(client: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = client.recv(4096)
        if not chunk:
            raise ConnectionError("Client closed before headers were complete")
        data.extend(chunk)
        if len(data) > MAX_HEADERS:
            raise ValueError("Request headers are too large")
    boundary = data.index(b"\r\n\r\n") + 4
    return bytes(data[:boundary]), bytes(data[boundary:])


def _parse_request(header_bytes: bytes) -> tuple[str, str, str, dict[str, str]]:
    try:
        lines = header_bytes.decode("iso-8859-1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
    except (UnicodeError, ValueError, IndexError) as exc:
        raise ValueError("Malformed proxy request") from exc
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("Unsupported HTTP version")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError("Malformed request header")
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key or any(char.isspace() for char in key):
            raise ValueError("Malformed request header")
        headers[key] = value.strip()
    return method.upper(), target, version, headers


def _write_response(client: socket.socket, status: int, message: str, body: bytes = b"", *, blocked: bool = False) -> None:
    headers = [
        f"HTTP/1.1 {status} {message}\r\n",
        "Connection: close\r\n",
        f"Content-Length: {len(body)}\r\n",
        "Content-Type: application/json; charset=utf-8\r\n",
    ]
    if blocked:
        headers.append("X-Scanner-Policy-Block: true\r\n")
    headers.append("\r\n")
    try:
        client.sendall("".join(headers).encode("ascii") + body)
    except OSError:
        pass


def _json_response(client: socket.socket, status: int, payload: dict[str, Any]) -> None:
    _write_response(client, status, "OK" if status < 400 else "Forbidden", json.dumps(payload).encode("utf-8"))


def _socket_to_public_host(hostname: str, port: int) -> socket.socket:
    addresses = resolve_public_addresses(hostname, port)
    last_error: OSError | None = None
    for address in addresses:
        try:
            upstream = socket.create_connection((address, port), timeout=5)
            upstream.settimeout(5)
            return upstream
        except OSError as exc:
            last_error = exc
    raise OSError("Could not connect to a validated public address") from last_error


def _relay(client: socket.socket, upstream: socket.socket, initial_upstream: bytes = b"", initial_client: bytes = b"") -> None:
    if initial_upstream:
        client.sendall(initial_upstream)
    if initial_client:
        upstream.sendall(initial_client)
    client.setblocking(False)
    upstream.setblocking(False)
    started = time.monotonic()
    transferred = 0
    sockets = [client, upstream]
    while sockets and transferred < MAX_TUNNEL_BYTES and time.monotonic() - started < MAX_CONNECTION_SECONDS:
        readable, _writable, exceptional = select.select(sockets, [], sockets, 1.0)
        if exceptional:
            break
        for current in readable:
            peer = upstream if current is client else client
            try:
                data = current.recv(64 * 1024)
            except (BlockingIOError, OSError):
                continue
            if not data:
                try:
                    peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sockets.remove(current)
                continue
            transferred += len(data)
            try:
                peer.sendall(data)
            except OSError:
                return


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(8)
        upstream: socket.socket | None = None
        try:
            raw, remainder = _read_headers(client)
            method, target, _version, headers = _parse_request(raw)
            if method == "POST" and target.startswith("/__control/"):
                self._control(client, target, headers, remainder)
                return
            if method == "CONNECT":
                host, port = self._parse_authority(target)
                scan_id, key = self._credentials(headers)
                policy = self.server.manager.authorize(scan_id, key, host, port)
                upstream = _socket_to_public_host(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: safe-scanner\r\n\r\n")
                _relay(client, upstream, initial_client=remainder)
                return
            if method not in {"GET", "HEAD"}:
                _write_response(client, 405, "Method Not Allowed", b'{"error":"Only GET and HEAD are permitted"}', blocked=True)
                return
            if remainder:
                _write_response(client, 405, "Method Not Allowed", b'{"error":"Request bodies are not permitted"}', blocked=True)
                return
            self._http_request(client, method, target, headers, remainder)
        except BlockingIOError:
            _write_response(client, 429, "Too Many Requests", b'{"error":"The scan request rate is limited"}', blocked=True)
        except PermissionError:
            # A standards-compliant client can retry with Proxy-Authorization.
            try:
                client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"safe-scanner\"\r\nConnection: close\r\nContent-Length: 0\r\nX-Scanner-Policy-Block: true\r\n\r\n")
            except OSError:
                pass
        except (TargetValidationError, ValueError):
            _write_response(client, 403, "Forbidden", b'{"error":"Destination was blocked by scan policy"}', blocked=True)
        except (OSError, socket.timeout, ConnectionError):
            _write_response(client, 502, "Bad Gateway", b'{"error":"Validated destination was unavailable"}')
        except Exception:
            _write_response(client, 502, "Bad Gateway", b'{"error":"Proxy request failed safely"}')
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass

    @staticmethod
    def _parse_authority(value: str) -> tuple[str, int]:
        if "@" in value or "/" in value or "\\" in value:
            raise ValueError("Invalid CONNECT authority")
        parsed = urlsplit("//" + value)
        host = normalize_hostname(parsed.hostname or "")
        port = parsed.port
        if port is None:
            raise ValueError("CONNECT requires an explicit port")
        return host, port

    @staticmethod
    def _credentials(headers: dict[str, str]) -> tuple[str, str]:
        scan_id = headers.get("x-scanner-job-id", "")
        key = headers.get("x-scanner-proxy-key", "")
        authorization = headers.get("proxy-authorization", "")
        if authorization.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(authorization.split(None, 1)[1], validate=True).decode("utf-8")
                scan_id, key = decoded.split(":", 1)
            except (ValueError, UnicodeError):
                pass
        return scan_id, key

    def _control(self, client: socket.socket, path: str, headers: dict[str, str], initial: bytes) -> None:
        if not hmac.compare_digest(headers.get("x-scanner-proxy-key", "").encode("utf-8"), self.server.manager.key.encode("utf-8")):
            _json_response(client, 403, {"error": "not authorized"})
            return
        try:
            length = int(headers.get("content-length", "0"))
        except ValueError:
            _json_response(client, 400, {"error": "invalid request"})
            return
        if length < 0 or length > MAX_CONTROL_BODY:
            _json_response(client, 413, {"error": "request too large"})
            return
        body = bytearray(initial)
        while len(body) < length:
            chunk = client.recv(min(4096, length - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) != length:
            _json_response(client, 400, {"error": "invalid request"})
            return
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
            if path == "/__control/register":
                self.server.manager.register(str(payload["scan_id"]), str(payload["hostname"]), str(payload["path_scope"]))
                result = {"registered": True}
            elif path == "/__control/revoke":
                self.server.manager.revoke(str(payload["scan_id"]))
                result = {"revoked": True}
            elif path == "/__control/check-host":
                hostname = normalize_hostname(str(payload["hostname"]))
                port = int(payload.get("port", 443))
                if port not in (80, 443):
                    raise ValueError("invalid port")
                resolve_public_addresses(hostname, port)
                result = {"public": True}
            elif path == "/__control/dns-check":
                hostname = normalize_hostname(str(payload["hostname"]))
                if hostname != str(payload["hostname"]).lower().rstrip("."):
                    raise ValueError("invalid hostname")
                result = _resolve_dns_records(hostname)
            elif path == "/__control/verify-txt":
                hostname = normalize_hostname(str(payload["hostname"]))
                txt_name = normalize_hostname(str(payload["txt_name"]))
                expected_hash = str(payload["expected_hash"])
                if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                    raise ValueError("invalid challenge")
                result = {"verified": verify_dns_txt(hostname, txt_name, expected_hash)}
            else:
                _json_response(client, 404, {"error": "not found"})
                return
            _json_response(client, 200, result)
        except (KeyError, ValueError, TargetValidationError, json.JSONDecodeError):
            _json_response(client, 400, {"error": "invalid request"})
        except Exception:
            _json_response(client, 503, {"error": "DNS service is inconclusive"})

    def _http_request(self, client: socket.socket, method: str, absolute_url: str, headers: dict[str, str], remainder: bytes) -> None:
        try:
            parsed = urlsplit(absolute_url)
            host = normalize_hostname(parsed.hostname or "")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.scheme.lower() != "http" or parsed.query or parsed.fragment or parsed.username is not None:
                raise ValueError("Only clean HTTP URLs are permitted through this proxy")
            scan_id, key = self._credentials(headers)
            policy = self.server.manager.authorize(scan_id, key, host, port)
            if not is_path_in_scope(path, policy.path_scope):
                raise ValueError("Path is outside scope")
            if int(headers.get("content-length", "0") or 0) != 0 or "transfer-encoding" in headers:
                raise ValueError("Request bodies are not permitted")
        except (ValueError, TargetValidationError, PermissionError):
            raise
        upstream = _socket_to_public_host(host, port)
        try:
            rendered_host = f"[{host}]" if ":" in host else host
            host_header = rendered_host if port == 80 else f"{rendered_host}:{port}"
            request_lines = [f"{method} {path} HTTP/1.1\r\n", f"Host: {host_header}\r\n"]
            allowed_headers = {"user-agent", "accept", "accept-language"}
            for name in allowed_headers:
                value = headers.get(name)
                if value:
                    clean_value = value.replace("\r", "").replace("\n", "")[:1000]
                    request_lines.append(f"{name.title()}: {clean_value}\r\n")
            request_lines.extend(["Accept-Encoding: identity\r\n", "Connection: close\r\n", "\r\n"])
            upstream.sendall("".join(request_lines).encode("iso-8859-1"))
            _relay(client, upstream)
        finally:
            upstream.close()


class ThreadedProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, manager: PolicyManager):
        self.manager = manager
        super().__init__(address, ProxyHandler)


def main() -> None:
    key = os.getenv("SCANNER_PROXY_KEY", "")
    if len(key) < 24:
        raise RuntimeError("SCANNER_PROXY_KEY must contain at least 24 characters")
    host = os.getenv("SCANNER_PROXY_BIND", "0.0.0.0")
    port = int(os.getenv("SCANNER_PROXY_PORT", "3128"))
    server = ThreadedProxyServer((host, port), PolicyManager(key))
    print(f"Safe egress proxy listening on {host}:{port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

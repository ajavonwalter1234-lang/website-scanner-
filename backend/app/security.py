"""URL, address and path-scope validation for every outbound scan request."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, unquote, urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """The requested target is malformed or outside the scanner's safe boundary."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    hostname: str
    port: int
    scheme: str
    path: str
    path_scope: str


_FORBIDDEN_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa",
    ".test", ".invalid", ".example", ".onion",
)
_NUMERIC_HOST = re.compile(r"^(?:[0-9]+\.?)+$")
_HEX_INTEGER_HOST = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c|00)|%25(?:2e|2f|5c|00)", re.IGNORECASE)
_OPAQUE_PATH_VALUE = re.compile(r"^[A-Za-z0-9_-]{24,}$")
_SECRET_PATH_LABELS = {
    "token", "tokens", "access-token", "access_token", "reset", "reset-password",
    "password-reset", "invite", "invitation", "magic-link", "verify", "verification",
    "session", "sessions", "session-id", "session_id", "secret", "secrets",
    "key", "keys", "api-key", "api_key", "apikey", "credential", "credentials",
    "password", "passwd", "private-key", "private_key", "authorization", "bearer", "code",
    "auth-token", "auth_token", "csrf-token", "csrf_token",
}


def normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname:
        raise TargetValidationError("A hostname is required")
    if any(ord(char) < 33 or ord(char) == 127 for char in hostname) or "%" in hostname:
        raise TargetValidationError("The hostname is not valid")
    # A final dot is DNS-equivalent but frequently bypasses string scope checks.
    host = hostname.rstrip(".").lower()
    if not host or len(host) > 253:
        raise TargetValidationError("The hostname is not valid")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return address.compressed.lower()

    if host == "localhost" or any(host.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES):
        raise TargetValidationError("Local and reserved hostnames are not allowed")
    if "." not in host or _NUMERIC_HOST.fullmatch(host) or _HEX_INTEGER_HOST.fullmatch(host):
        raise TargetValidationError("A fully qualified public hostname is required")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("The hostname is not valid") from exc
    if len(ascii_host) > 253 or any(not label or len(label) > 63 for label in ascii_host.split(".")):
        raise TargetValidationError("The hostname is not valid")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in ascii_host.split(".")):
        raise TargetValidationError("The hostname is not valid")
    return ascii_host


def _normalize_path(path: str, *, label: str) -> tuple[str, str]:
    if not path:
        path = "/"
    if not path.startswith("/") or "\\" in path or _BAD_PERCENT.search(path) or _ENCODED_SEPARATOR.search(path):
        raise TargetValidationError(f"The {label} is not a safe path")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise TargetValidationError(f"The {label} is not a safe path")
    try:
        decoded = unquote(path, errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise TargetValidationError(f"The {label} is not a safe path") from exc
    if "\\" in decoded or any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        raise TargetValidationError(f"The {label} is not a safe path")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise TargetValidationError(f"Dot-segment paths are not allowed in the {label}")
    # Keep a stable ASCII request target while leaving reserved path characters intact.
    encoded = quote(path, safe="/%:@!$&'()*+,;=-._~%")
    return encoded, decoded


def _sensitive_path_indexes(decoded_path: str) -> set[int]:
    segments = decoded_path.split("/")
    indexes: set[int] = set()
    for index, segment in enumerate(segments):
        value = segment.lower()
        if index > 0 and segments[index - 1].lower() in _SECRET_PATH_LABELS and len(segment) >= 8:
            indexes.add(index)
            continue
        if len(segment) >= 24 and _OPAQUE_PATH_VALUE.fullmatch(segment):
            if sum(character.islower() for character in segment) and sum(character.isdigit() for character in segment):
                indexes.add(index)
    return indexes


def _reject_secret_like_path(decoded_path: str) -> None:
    if _sensitive_path_indexes(decoded_path):
        raise TargetValidationError("Paths that appear to contain secret tokens are not accepted")


def normalize_path_scope(path_scope: str | None) -> str:
    if path_scope is None or path_scope == "":
        return "/"
    if not isinstance(path_scope, str) or "?" in path_scope or "#" in path_scope:
        raise TargetValidationError("The path scope must be a path prefix without a query or fragment")
    encoded, decoded = _normalize_path(path_scope, label="path scope")
    _reject_secret_like_path(decoded)
    if encoded != "/":
        encoded = encoded.rstrip("/") or "/"
    return encoded


def is_path_in_scope(path: str, path_scope: str) -> bool:
    """Return true only for the configured prefix and its child path segments."""
    try:
        _safe_path, decoded_path = _normalize_path(path, label="request path")
        _safe_scope, decoded_scope = _normalize_path(path_scope, label="path scope")
        _reject_secret_like_path(decoded_path)
        _reject_secret_like_path(decoded_scope)
    except TargetValidationError:
        return False
    if decoded_scope == "/":
        return True
    prefix = decoded_scope.rstrip("/")
    return decoded_path == prefix or decoded_path.startswith(prefix + "/")


def is_public_ip(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        address = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    # is_global excludes private, loopback, link-local, multicast, reserved,
    # unspecified and documentation ranges on supported Python versions.
    return bool(address.is_global and not address.is_multicast and not address.is_reserved)


def resolve_public_addresses(hostname: str, port: int = 443, resolver: Callable | None = None) -> list[str]:
    """Resolve once, reject the entire answer set if any address is not public.

    Call this immediately before connecting. The safe worker and egress proxy both
    pin the actual connection to an address from this validated answer set.
    """
    host = normalize_hostname(hostname)
    try:
        ip = ipaddress.ip_address(host)
        addresses = [ip.compressed]
    except ValueError:
        try:
            getaddrinfo = resolver or socket.getaddrinfo
            records = getaddrinfo(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(record[4][0].split("%", 1)[0] for record in records))
        except (OSError, socket.gaierror, ValueError) as exc:
            raise TargetValidationError("The hostname could not be resolved safely") from exc
    if not addresses or any(not is_public_ip(address) for address in addresses):
        raise TargetValidationError("The hostname resolves to a prohibited network address")
    return addresses


def validate_target_url(
    url: str,
    path_scope: str | None = "/",
    *,
    resolve_dns: bool = False,
    resolver: Callable | None = None,
) -> ValidatedTarget:
    """Validate and canonicalize a target URL before it is persisted or fetched."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise TargetValidationError("Enter a URL between 1 and 2048 characters")
    if url != url.strip() or any(ord(char) < 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise TargetValidationError("The URL contains invalid whitespace or characters")
    if "?" in url or "#" in url:
        raise TargetValidationError("Query strings and fragments are not accepted; enter a clean page URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError("The URL is malformed") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("Only HTTP and HTTPS URLs are allowed")
    if not parts.netloc or parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise TargetValidationError("Credentials and empty hosts are not allowed in a target URL")
    if parts.query or parts.fragment:
        raise TargetValidationError("Query strings and fragments are not accepted")
    hostname = normalize_hostname(parts.hostname or "")
    if port is None:
        port = 443 if scheme == "https" else 80
    expected_port = 443 if scheme == "https" else 80
    if port != expected_port:
        raise TargetValidationError("Only the standard HTTP and HTTPS ports (80 and 443) are allowed")

    path_scope = normalize_path_scope(path_scope)
    request_path, decoded_path = _normalize_path(parts.path or "/", label="URL path")
    _reject_secret_like_path(decoded_path)
    if not is_path_in_scope(request_path, path_scope):
        raise TargetValidationError("The target URL is outside the configured path scope")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        rendered_host = hostname
    else:
        if not is_public_ip(hostname):
            raise TargetValidationError("Private, reserved and non-routable IP addresses are not allowed")
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname

    if resolve_dns:
        resolve_public_addresses(hostname, port, resolver=resolver)

    netloc = rendered_host
    if port != expected_port:
        netloc = f"{rendered_host}:{port}"
    canonical = urlunsplit((scheme, netloc, request_path, "", ""))
    return ValidatedTarget(
        url=canonical,
        hostname=hostname,
        port=port,
        scheme=scheme,
        path=request_path,
        path_scope=path_scope,
    )


def normalize_redirect_url(location: str, base_url: str, path_scope: str, hostname: str) -> ValidatedTarget:
    """Resolve a redirect and revalidate every origin and path boundary."""
    from urllib.parse import urljoin

    if not location or len(location) > 2048 or any(ord(char) < 32 for char in location):
        raise TargetValidationError("The redirect location is not safe")
    candidate = urljoin(base_url, location)
    target = validate_target_url(candidate, path_scope, resolve_dns=False)
    if target.hostname != hostname:
        raise TargetValidationError("A redirect outside the authorized host was blocked")
    base = urlsplit(base_url)
    if base.scheme.lower() == "https" and target.scheme != "https":
        raise TargetValidationError("A redirect that downgrades HTTPS was blocked")
    return target


def safe_report_url(url: str) -> str:
    """Return an origin and path only; redact queries and token-like path values."""
    try:
        parts = urlsplit(url)
        host = normalize_hostname(parts.hostname or "")
        display_host = f"[{host}]" if ":" in host else host
        scheme = parts.scheme.lower()
        port = parts.port
        expected = 443 if scheme == "https" else 80
        netloc = display_host if port in (None, expected) else f"{display_host}:{port}"
        path, decoded = _normalize_path(parts.path or "/", label="report URL path")
        secret_indexes = _sensitive_path_indexes(decoded)
        if secret_indexes:
            raw_segments = path.split("/")
            for index in secret_indexes:
                if index < len(raw_segments):
                    raw_segments[index] = "%5Bredacted%5D"
            path = "/".join(raw_segments)
        return urlunsplit((scheme, netloc, path, "", ""))
    except Exception:
        return "[redacted target URL]"

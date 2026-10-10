"""Bounded, unauthenticated, GET-only passive scanner."""
from __future__ import annotations

import hashlib
import html
import http.client
import re
import socket
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

from .config import settings
from .security import (
    TargetValidationError,
    ValidatedTarget,
    is_path_in_scope,
    normalize_redirect_url,
    resolve_public_addresses,
    safe_report_url,
    validate_target_url,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class SafeScanError(RuntimeError):
    """A scan could not proceed while preserving its safety boundary."""


class TLSVerificationError(SafeScanError):
    def __init__(self, target_url: str):
        super().__init__("TLS certificate validation failed")
        self.target_url = target_url


class ScopeViolation(SafeScanError):
    pass


class ScanCancelled(SafeScanError):
    pass


@dataclass
class FindingDraft:
    title: str
    category: str
    severity: str
    finding_status: str
    confidence: int
    affected_url: str
    evidence: str
    impact: str
    remediation: str
    fingerprint: str = ""


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool = False
    tls_version: str | None = None
    blocked_redirect: bool = False
    redirect_count: int = 0

    def get_all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def get(self, name: str, default: str = "") -> str:
        values = self.get_all(name)
        return values[-1] if values else default


@dataclass
class ScanResult:
    findings: list[FindingDraft] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tested_areas: list[str] = field(default_factory=list)
    pages_scanned: int = 0
    tls: dict[str, str | bool | None] = field(default_factory=dict)


class PageParser(HTMLParser):
    """Extract inert HTML references only; scripts, styles and downloads are never run."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.script_sources: list[str] = []
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs if value is not None}
        if tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"] or "")
        elif tag.lower() == "script" and values.get("src"):
            self.script_sources.append(values["src"] or "")
        elif tag.lower() == "meta" and values.get("name", "").lower() == "generator":
            if values.get("content"):
                self.generators.append(values["content"] or "")


@dataclass(frozen=True)
class ComponentAdvisory:
    name: str
    remediation: str
    reference: str


_COMPONENT_ADVISORIES = {
    "jquery": ComponentAdvisory(
        "jQuery", "Upgrade jQuery to a currently supported release and review vendor security advisories.", "CVE-2020-11022 / CVE-2020-11023"
    ),
    "bootstrap": ComponentAdvisory(
        "Bootstrap", "Upgrade Bootstrap to a currently supported release and review vendor security advisories.", "CVE-2019-8331"
    ),
}
_COMPONENT_VERSION_PATTERNS = {
    "jquery": re.compile(r"jquery(?:[-@/]|\.)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
    "bootstrap": re.compile(r"bootstrap(?:[-@/]|\.)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
}
_SENSITIVE_FILE_EXTENSIONS = (".bak", ".backup", ".old", ".sql", ".dump", ".env", ".zip", ".tar", ".tgz")
_SENSITIVE_VALUE = re.compile(
    r"(?i)(\b(?:authorization|bearer|api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret|client[_-]?secret|private[_-]?key|session[_-]?id|cookie)\b\s*[:=]\s*)([^\s,;]+)"
)
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")
_VERSION = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")


def redact_sensitive(value: str, limit: int = 500) -> str:
    text = _AUTH_VALUE.sub("[redacted credential]", value)
    text = _SENSITIVE_VALUE.sub(r"\1[redacted]", text)
    text = _JWT.sub("[redacted token]", text)
    text = "".join(character for character in text if character >= " " or character in "\t")
    return text[:limit].strip()


def classify_severity(category: str, riskcode: str | int | None = None) -> str:
    """Normalize custom-check and ZAP risk labels into one severity scale."""
    if riskcode is not None:
        try:
            numeric = int(riskcode)
        except (TypeError, ValueError):
            numeric = -1
        if numeric >= 4:
            return "critical"
        if numeric == 3:
            return "high"
        if numeric == 2:
            return "medium"
        if numeric == 1:
            return "low"
        if numeric == 0:
            return "info"
    category = category.lower()
    if category in {"directory-listing", "invalid-tls-certificate"}:
        return "high" if category == "invalid-tls-certificate" else "medium"
    if category in {"component-version", "clickjacking-protection", "content-security-policy", "https-transport"}:
        return "medium"
    if category in {"cookie-secure", "cookie-httponly", "cookie-samesite", "dnssec", "caa", "spf", "dmarc", "public-file-indicator"}:
        return "low" if category != "public-file-indicator" else "medium"
    if category.startswith("zap-"):
        return "low"
    return "low"


def _version_tuple(version: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return None


def _version_is_older(version: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    width = max(len(version), len(threshold))
    return version + (0,) * (width - len(version)) < threshold + (0,) * (width - len(threshold))


def _known_fixed_version(component: str, version: tuple[int, ...]) -> tuple[int, ...] | None:
    major = version[0] if version else 0
    if component == "jquery":
        if major < 3 or (major == 3 and _version_is_older(version, (3, 5, 0))):
            return (3, 5, 0)
        return None
    if component == "bootstrap":
        if major == 3 and _version_is_older(version, (3, 4, 1)):
            return (3, 4, 1)
        if major == 4 and _version_is_older(version, (4, 3, 1)):
            return (4, 3, 1)
    return None


def _valid_public_target(value: str, hostname: str, path_scope: str) -> ValidatedTarget | None:
    try:
        target = validate_target_url(value, path_scope, resolve_dns=False)
    except TargetValidationError:
        return None
    if target.hostname != hostname:
        return None
    return target


def _origin_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def _public_metadata_paths(start_url: str, path_scope: str) -> list[str]:
    # These are expected public metadata locations only; no backup/config paths
    # are probed. We do not download arbitrary files or execute any content.
    if path_scope != "/":
        return []
    origin = _origin_url(start_url)
    return [origin + "robots.txt", origin + "sitemap.xml", origin + ".well-known/security.txt"]


def _parse_dns_records(hostname: str) -> dict[str, bool | None]:
    try:
        import dns.resolver
    except ImportError:
        return {"dnssec_ds": None, "caa": None, "spf": None, "dmarc": None}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2
    resolver.lifetime = 4

    def records(name: str, kind: str):
        try:
            answer = resolver.resolve(name, kind, raise_on_no_answer=False, lifetime=4)
            return [] if answer.rrset is None else list(answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            return []
        except Exception:
            return None

    ds = records(hostname, "DS")
    caa = records(hostname, "CAA")
    txt = records(hostname, "TXT")
    dmarc = records(f"_dmarc.{hostname}", "TXT")

    def txt_values(answer):
        if answer is None:
            return None
        values = []
        for record in answer:
            chunks = getattr(record, "strings", ())
            values.append(b"".join(chunks).decode("utf-8", "ignore").lower() if chunks else str(record).strip('"').lower())
        return values

    t_values = txt_values(txt)
    d_values = txt_values(dmarc)
    return {
        "dnssec_ds": None if ds is None else bool(ds),
        "caa": None if caa is None else bool(caa),
        "spf": None if t_values is None else any(value.startswith("v=spf1") for value in t_values),
        "dmarc": None if d_values is None else any(value.startswith("v=dmarc1") for value in d_values),
    }


class SafeHttpClient:
    """HTTP client that disables automatic redirects and pins direct DNS answers."""

    def __init__(self, *, hostname: str, path_scope: str, scan_id: str, proxy_url: str | None, proxy_key: str | None, timeout: float = 5, max_bytes: int = 512 * 1024):
        self.hostname = hostname
        self.path_scope = path_scope
        self.scan_id = scan_id
        self.proxy_url = proxy_url
        self.proxy_key = proxy_key
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.started_at = time.monotonic()
        self.last_request_at = 0.0
        self.ssl_context = ssl.create_default_context()
        if hasattr(ssl, "TLSVersion"):
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.proxy = urlsplit(proxy_url) if proxy_url else None
        if self.proxy and (self.proxy.scheme != "http" or not self.proxy.hostname or self.proxy.port is None):
            raise SafeScanError("The scanner egress proxy is not configured safely")

    def _check_time(self) -> None:
        if time.monotonic() - self.started_at > settings.scan_timeout_seconds:
            raise SafeScanError("The scan time limit was reached")

    def _read_bounded(self, response) -> tuple[bytes, bool]:
        body = bytearray()
        deadline = min(time.monotonic() + 10, self.started_at + settings.scan_timeout_seconds)
        while len(body) <= self.max_bytes:
            self._check_time()
            if time.monotonic() >= deadline:
                raise SafeScanError("The response time limit was reached")
            remaining = self.max_bytes + 1 - len(body)
            if remaining <= 0:
                break
            try:
                has_incremental_reader = hasattr(response, "read1")
                chunk = response.read1(min(16 * 1024, remaining)) if has_incremental_reader else response.read(remaining)
            except (OSError, http.client.HTTPException, socket.timeout):
                raise SafeScanError("The target response could not be read safely") from None
            if not chunk:
                break
            body.extend(chunk)
            if not has_incremental_reader:
                break
        truncated = len(body) > self.max_bytes
        return bytes(body[: self.max_bytes]), truncated

    def fetch(self, url: str, *, max_redirects: int = 3) -> FetchResult:
        current = validate_target_url(url, self.path_scope, resolve_dns=False)
        if current.hostname != self.hostname:
            raise ScopeViolation("The target is outside the authorized host")
        seen: set[str] = set()
        redirect_count = 0
        while True:
            self._check_time()
            since_last = time.monotonic() - self.last_request_at
            if self.last_request_at and since_last < 0.75:
                time.sleep(0.75 - since_last)
                self._check_time()
            self.last_request_at = time.monotonic()
            if current.url in seen:
                return FetchResult(current.url, 0, [], b"", blocked_redirect=True, redirect_count=redirect_count)
            seen.add(current.url)
            response, tls_version, connection = self._single_get(current)
            try:
                location = next((value for key, value in response.getheaders() if key.lower() == "location"), None)
                if response.status in {301, 302, 303, 307, 308} and location:
                    if redirect_count >= max_redirects:
                        return FetchResult(current.url, response.status, [], b"", blocked_redirect=True, redirect_count=redirect_count)
                    try:
                        next_target = normalize_redirect_url(location, current.url, self.path_scope, self.hostname)
                    except TargetValidationError:
                        return FetchResult(current.url, response.status, [], b"", blocked_redirect=True, redirect_count=redirect_count)
                    # HTTPS -> HTTP is blocked by normalize_redirect_url.
                    current = next_target
                    redirect_count += 1
                    continue
                headers = response.getheaders()
                body, truncated = self._read_bounded(response)
                return FetchResult(current.url, response.status, headers, body, truncated, tls_version, False, redirect_count)
            finally:
                response.close()
                if connection is not None:
                    connection.close()

    def _single_get(self, target: ValidatedTarget):
        parts = urlsplit(target.url)
        origin_host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        headers = {
            "Host": origin_host,
            "User-Agent": "SafeWebsiteScanner/1.0 (+passive security checks)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.8,*/*;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        conn: http.client.HTTPConnection | None = None
        tls_version: str | None = None
        try:
            if self.proxy:
                proxy_host = self.proxy.hostname or ""
                proxy_port = self.proxy.port or 3128
                conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=self.timeout)
                if target.scheme == "https":
                    proxy_auth = "Basic " + __import__("base64").b64encode(f"{self.scan_id}:{self.proxy_key}".encode()).decode()
                    conn.set_tunnel(target.hostname, target.port, headers={"Proxy-Authorization": proxy_auth})
                    conn.connect()
                    if not conn.sock:
                        raise SafeScanError("The proxy tunnel could not be established")
                    conn.sock = self.ssl_context.wrap_socket(conn.sock, server_hostname=target.hostname)
                    tls_version = conn.sock.version()
                    conn.request("GET", parts.path or "/", headers=headers)
                else:
                    # HTTP proxies require an absolute-form request target.
                    headers["X-Scanner-Job-ID"] = self.scan_id
                    headers["X-Scanner-Proxy-Key"] = self.proxy_key or ""
                    conn.request("GET", target.url, headers=headers)
            else:
                addresses = resolve_public_addresses(target.hostname, target.port)
                last_error: OSError | None = None
                raw_sock = None
                for address in addresses:
                    try:
                        raw_sock = socket.create_connection((address, target.port), timeout=self.timeout)
                        break
                    except OSError as exc:
                        last_error = exc
                if raw_sock is None:
                    raise SafeScanError("The target could not be reached at a validated public address") from last_error
                raw_sock.settimeout(self.timeout)
                if target.scheme == "https":
                    conn = http.client.HTTPConnection(target.hostname, target.port, timeout=self.timeout)
                    conn.sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=target.hostname)
                    tls_version = conn.sock.version()
                else:
                    conn = http.client.HTTPConnection(target.hostname, target.port, timeout=self.timeout)
                    conn.sock = raw_sock
                conn.request("GET", parts.path or "/", headers=headers)
            response = conn.getresponse()
            if response.getheader("X-Scanner-Policy-Block", "").lower() == "true":
                response.close()
                raise ScopeViolation("The egress proxy blocked a request outside scan policy")
            return response, tls_version, conn
        except ssl.SSLCertVerificationError:
            if conn is not None:
                conn.close()
            raise TLSVerificationError(target.url) from None
        except ssl.SSLError:
            if conn is not None:
                conn.close()
            raise SafeScanError("The TLS handshake could not be completed") from None
        except ScopeViolation:
            if conn is not None:
                conn.close()
            raise
        except SafeScanError:
            if conn is not None:
                conn.close()
            raise
        except (OSError, http.client.HTTPException, socket.timeout, ValueError):
            if conn is not None:
                conn.close()
            raise SafeScanError("The target could not be reached safely") from None


class PassiveScanner:
    def __init__(
        self,
        *,
        scan_id: str,
        target: ValidatedTarget,
        max_pages: int,
        progress: Callable[[int, str], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
        dns_checker: Callable[[str], dict[str, bool | None]] | None = None,
        zap_runner: Callable[[str, str, str, str, str | None, str | None], tuple[list[FindingDraft], list[str]]] | None = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.hostname = target.hostname
        self.path_scope = target.path_scope
        self.max_pages = max_pages
        self.progress = progress or (lambda _percent, _message: None)
        self.cancelled = cancelled or (lambda: False)
        self.dns_checker = dns_checker or _parse_dns_records
        self.zap_runner = zap_runner
        self.client = SafeHttpClient(
            hostname=target.hostname,
            path_scope=target.path_scope,
            scan_id=scan_id,
            proxy_url=settings.proxy_url,
            proxy_key=settings.proxy_key,
            timeout=5,
            max_bytes=settings.max_response_bytes,
        )
        self.result = ScanResult()
        self._seen_findings: set[str] = set()

    def _add(
        self,
        *,
        title: str,
        category: str,
        severity: str | None = None,
        finding_status: str = "potential",
        confidence: int = 65,
        affected_url: str,
        evidence: str,
        impact: str,
        remediation: str,
    ) -> None:
        display_url = safe_report_url(affected_url)
        fingerprint = hashlib.sha256(f"{category}|{display_url}|{title}".encode("utf-8")).hexdigest()
        if fingerprint in self._seen_findings:
            return
        self._seen_findings.add(fingerprint)
        self.result.findings.append(FindingDraft(
            title=redact_sensitive(title, 240),
            category=category,
            severity=severity or classify_severity(category),
            finding_status=finding_status,
            confidence=max(0, min(100, int(confidence))),
            affected_url=display_url,
            evidence=redact_sensitive(evidence),
            impact=redact_sensitive(impact),
            remediation=redact_sensitive(remediation),
            fingerprint=fingerprint,
        ))

    def _check_headers_and_cookies(self, response: FetchResult) -> None:
        url = response.final_url
        https = urlsplit(url).scheme == "https"
        headers = {key.lower(): value for key, value in response.headers}
        csp = headers.get("content-security-policy", "")
        frame_protected = "frame-ancestors" in csp.lower() or "x-frame-options" in headers
        if https and not headers.get("strict-transport-security"):
            self._add(
                title="HTTP Strict Transport Security header not observed",
                category="security-header-hsts",
                severity="low",
                affected_url=url,
                evidence="The HTTPS response did not include a Strict-Transport-Security header.",
                impact="Browsers may not be instructed to prefer HTTPS on later visits.",
                remediation="Consider enabling HSTS after confirming that HTTPS is correctly configured for the full intended host scope.",
            )
        if not csp:
            self._add(
                title="Content Security Policy header not observed",
                category="content-security-policy",
                severity="medium",
                affected_url=url,
                evidence="The response did not include a Content-Security-Policy header.",
                impact="A policy can provide an additional browser-side defense against unintended content execution; its absence is not proof of a vulnerability.",
                remediation="Define and test a restrictive Content-Security-Policy suited to the site's resources and deployment.",
            )
        if not headers.get("x-content-type-options") or "nosniff" not in headers.get("x-content-type-options", "").lower():
            self._add(
                title="MIME-sniffing protection not observed",
                category="security-header-nosniff",
                severity="low",
                affected_url=url,
                evidence="The response did not set X-Content-Type-Options to nosniff.",
                impact="Some browsers may interpret content using a type different from the declared media type.",
                remediation="Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.",
            )
        if not headers.get("referrer-policy"):
            self._add(
                title="Referrer Policy header not observed",
                category="security-header-referrer",
                severity="low",
                affected_url=url,
                evidence="The response did not include a Referrer-Policy header.",
                impact="Navigations may disclose more referring URL information than intended, depending on browser defaults and destination.",
                remediation="Set a Referrer-Policy appropriate for the site's privacy requirements, such as strict-origin-when-cross-origin.",
            )
        if not headers.get("permissions-policy"):
            self._add(
                title="Permissions Policy header not observed",
                category="security-header-permissions",
                severity="info",
                affected_url=url,
                evidence="The response did not include a Permissions-Policy header.",
                impact="Browser features are not explicitly restricted by this response header.",
                remediation="Consider disabling browser features that the application does not use.",
            )
        if not frame_protected:
            self._add(
                title="Framing protections not observed",
                category="clickjacking-protection",
                severity="medium",
                affected_url=url,
                evidence="Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive was observed.",
                impact="If sensitive workflows can be framed, users may need additional protection against unintended framing.",
                remediation="Set an appropriate CSP frame-ancestors directive; use X-Frame-Options as a compatibility fallback where needed.",
            )

        hsts = headers.get("strict-transport-security", "")
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if https and max_age and int(max_age.group(1)) < 15_552_000:
            self._add(
                title="HSTS max-age is shorter than six months",
                category="security-header-hsts-weak",
                severity="low",
                affected_url=url,
                evidence="The HSTS max-age value is less than the commonly used six-month baseline.",
                impact="A short policy duration may reduce the time browsers remember the HTTPS-only setting.",
                remediation="Review the HSTS duration and increase it only after confirming HTTPS readiness for the intended host scope.",
            )

        for set_cookie in response.get_all("set-cookie"):
            pieces = [piece.strip() for piece in set_cookie.split(";")]
            attributes = {piece.split("=", 1)[0].strip().lower() for piece in pieces[1:] if piece}
            if "secure" not in attributes:
                self._add(
                    title="Cookie without Secure attribute observed",
                    category="cookie-secure",
                    severity="low",
                    affected_url=url,
                    evidence="A response cookie did not include the Secure attribute; cookie names and values are intentionally omitted.",
                    impact="A cookie may be sent over an unencrypted connection if an HTTP route is available.",
                    remediation="Set Secure on cookies that should only be transmitted over HTTPS.",
                )
            if "httponly" not in attributes:
                self._add(
                    title="Cookie without HttpOnly attribute observed",
                    category="cookie-httponly",
                    severity="low",
                    affected_url=url,
                    evidence="A response cookie did not include HttpOnly; cookie names and values are intentionally omitted.",
                    impact="Client-side scripts can access the cookie where the application exposes it to the browser.",
                    remediation="Set HttpOnly on cookies that do not need to be read by client-side scripts.",
                )
            if "samesite" not in attributes:
                self._add(
                    title="Cookie without SameSite attribute observed",
                    category="cookie-samesite",
                    severity="low",
                    affected_url=url,
                    evidence="A response cookie did not include SameSite; cookie names and values are intentionally omitted.",
                    impact="Cross-site cookie sending behavior may rely on browser defaults rather than an explicit policy.",
                    remediation="Set an appropriate SameSite policy for each cookie and confirm that required cross-site flows continue to work.",
                )

        for header_name in ("server", "x-powered-by"):
            value = headers.get(header_name, "")
            if value and _VERSION.search(value):
                version_text = _VERSION.search(value).group(0)
                self._add(
                    title="Software version banner disclosed",
                    category="information-disclosure-banner",
                    severity="info",
                    confidence=72,
                    affected_url=url,
                    evidence=f"The {header_name.title()} response header contains a software version pattern ({version_text}). The complete header value was not retained.",
                    impact="Version details can make technology identification easier but do not by themselves confirm an exploitable weakness.",
                    remediation="Consider suppressing unnecessary version detail and keep exposed components updated.",
                )

    def _check_component_versions(self, parser: PageParser, page_url: str) -> None:
        seen: set[tuple[str, str]] = set()
        for source in parser.script_sources:
            try:
                path = urlsplit(urljoin(page_url, source)).path
            except ValueError:
                continue
            path = html.unescape(path)
            for component, pattern in _COMPONENT_VERSION_PATTERNS.items():
                match = pattern.search(path)
                if not match:
                    continue
                version_text = match.group(1)
                version = _version_tuple(version_text)
                advisory = _COMPONENT_ADVISORIES[component]
                pair = (component, version_text)
                if pair in seen:
                    continue
                seen.add(pair)
                fixed_version = _known_fixed_version(component, version) if version is not None else None
                if fixed_version is None:
                    continue
                self._add(
                    title=f"Potentially vulnerable {advisory.name} version detected",
                    category="component-version",
                    severity="medium",
                    finding_status="potential",
                    confidence=72,
                    affected_url=page_url,
                    evidence=f"A script reference identifies {advisory.name} {version_text}, which predates the advisory fixed release {'.'.join(map(str, fixed_version))} ({advisory.reference}). The served asset was not downloaded or executed.",
                    impact="The observed version may include publicly documented security issues; a version string alone does not confirm the deployed code or patch state.",
                    remediation=advisory.remediation,
                )

    def _check_public_file_links(self, parser: PageParser, page_url: str) -> None:
        for href in parser.links:
            candidate = urljoin(page_url, html.unescape(href))
            target = _valid_public_target(candidate, self.hostname, self.path_scope)
            if target is None:
                continue
            path = urlsplit(target.url).path.lower()
            if path.endswith(_SENSITIVE_FILE_EXTENSIONS):
                self._add(
                    title="Public page references a backup or configuration-like file",
                    category="public-file-indicator",
                    severity="medium",
                    finding_status="potential",
                    confidence=60,
                    affected_url=page_url,
                    evidence="A public page contains a link whose filename extension is commonly used for backup, archive, database, or configuration files. The linked file was not requested.",
                    impact="If the linked resource is publicly accessible and contains operational data, it could disclose information.",
                    remediation="Confirm that production pages link only to intentionally public files; keep backups and configuration outside the web root or behind appropriate access controls.",
                )
                break

    @staticmethod
    def _looks_like_directory_listing(body: bytes) -> bool:
        sample = body[:64 * 1024].decode("utf-8", "ignore")
        return bool(re.search(r"<title>\s*Index of(?:\s|/|<)|<h1>\s*Index of(?:\s|/|<)", sample, re.IGNORECASE))

    def _check_dns(self) -> None:
        self.progress(78, "Checking public DNS security records")
        try:
            records = self.dns_checker(self.hostname)
        except Exception:
            records = {"dnssec_ds": None, "caa": None, "spf": None, "dmarc": None}
        labels = {
            "dnssec_ds": ("dnssec", "DNSSEC DS record not observed", "DNSSEC protection for the authoritative zone cannot be confirmed by a DS lookup at this exact hostname; a child name may inherit a signed parent zone.", "Verify DNSSEC signing and the DS chain at the authoritative zone apex and registrar.", "No DS record was observed directly at this hostname; this alone does not prove the parent zone is unsigned."),
            "caa": ("caa", "CAA record not observed", "Certificate issuance restrictions are not visible at this exact name; CAA may be inherited from a parent name.", "Review CAA policy at the authoritative domain and any relevant parent zone.", "No CAA record was observed directly at this hostname; parent policy inheritance was not assessed."),
            "spf": ("spf", "SPF record not observed", "Mail from the domain may have less explicit sender authorization.", "Review the domain's mail providers and publish an accurate SPF policy if the domain sends email.", "No SPF policy was observed in the domain's TXT records."),
            "dmarc": ("dmarc", "DMARC record not observed", "Receiving mail systems may have less explicit guidance for handling unauthenticated messages claiming this domain, though an organizational-domain policy may apply to this hostname.", "Review mail authentication requirements and publish a DMARC policy appropriate for the organizational domain, including subdomain policy.", "No DMARC policy was observed at the standard _dmarc hostname for this hostname."),
        }
        inconclusive = False
        for key, (category, title, impact, remediation, evidence) in labels.items():
            value = records.get(key)
            if value is None:
                inconclusive = True
            elif value is False:
                confidence = 50 if key in {"dnssec_ds", "caa", "dmarc"} else 70
                self._add(title=title, category=category, severity=classify_severity(category), finding_status="potential", confidence=confidence, affected_url=self.target.url, evidence=evidence, impact=impact, remediation=remediation)
        if inconclusive or not records.get("available", True):
            self.result.warnings.append("One or more DNS security record checks were inconclusive; confirm records with the authoritative DNS provider.")
        if any(records.get(key) is False for key in ("dnssec_ds", "caa", "dmarc")):
            self.result.warnings.append("DNSSEC, CAA and DMARC policy may be inherited or published at a parent zone; confirm organizational-domain records manually.")
        self.result.tested_areas.append("Public DNS record presence (DNSSEC DS, CAA, SPF and DMARC)")

    def _check_cancelled(self) -> None:
        if self.cancelled():
            raise ScanCancelled("Scan cancelled because its stored record was deleted")

    def run(self) -> ScanResult:
        self.result.tested_areas = [
            "Unauthenticated HTTP(S) responses using safe GET requests only",
            "TLS certificate validation and negotiated protocol where HTTPS was reached",
            "Security response headers and cookie attributes",
            "Public information-disclosure indicators",
            "Same-host, path-scoped HTML link crawl",
            "Safe public metadata locations (robots.txt, sitemap.xml and security.txt when in scope)",
            "Identifiable component versions in inert script references",
        ]
        queue: deque[tuple[str, int]] = deque([(self.target.url, 0)])
        queued = {self.target.url}
        for metadata_url in _public_metadata_paths(self.target.url, self.path_scope):
            target = _valid_public_target(metadata_url, self.hostname, self.path_scope)
            if target and target.url not in queued:
                queue.append((target.url, 0))
                queued.add(target.url)

        visited: set[str] = set()
        deadline = time.monotonic() + settings.scan_timeout_seconds
        while queue and len(visited) < self.max_pages and time.monotonic() < deadline:
            self._check_cancelled()
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue
            target = _valid_public_target(current_url, self.hostname, self.path_scope)
            if target is None:
                continue
            visited.add(target.url)
            percent = min(72, 12 + int(58 * len(visited) / max(1, self.max_pages)))
            self.progress(percent, f"Reviewing in-scope page {len(visited)} of up to {self.max_pages}")
            try:
                response = self.client.fetch(target.url)
            except TLSVerificationError as exc:
                self._add(
                    title="HTTPS certificate validation failed",
                    category="invalid-tls-certificate",
                    severity="high",
                    finding_status="confirmed",
                    confidence=95,
                    affected_url=exc.target_url,
                    evidence="The HTTPS endpoint did not pass the scanner's standard certificate validation.",
                    impact="Browsers may warn users or fail to establish an authenticated, confidential connection to this endpoint.",
                    remediation="Install a valid certificate for the host, serve the required intermediate chain, and correct certificate validity or name issues.",
                )
                self.result.warnings.append("HTTPS content was not crawled because certificate validation failed.")
                continue
            except ScopeViolation:
                self.result.warnings.append("A request was blocked by the egress policy because it was outside the authorized host or path scope.")
                continue
            except SafeScanError as exc:
                message = str(exc)
                if "time limit" in message:
                    self.result.warnings.append("The configured scan time limit was reached; remaining pages were not tested.")
                    break
                self.result.warnings.append("A page could not be fetched safely; related checks may be incomplete.")
                continue
            self._check_cancelled()
            self.result.pages_scanned += 1
            if response.blocked_redirect:
                self.result.warnings.append("A redirect outside the authorized host, path, HTTPS policy or redirect limit was blocked.")
            final_scheme = urlsplit(response.final_url).scheme
            if final_scheme == "https":
                self.result.tls = {"https_reached": True, "certificate_valid": True, "protocol": response.tls_version}
            elif not self.result.tls:
                self.result.tls = {"https_reached": False, "certificate_valid": None, "protocol": None}
            if self.target.scheme == "http" and target.url == self.target.url and final_scheme == "http":
                self._add(
                    title="The scanned entry point serves content over HTTP",
                    category="https-transport",
                    severity="medium",
                    finding_status="confirmed",
                    confidence=95,
                    affected_url=response.final_url,
                    evidence="The requested HTTP endpoint returned a response without redirecting to HTTPS.",
                    impact="Traffic to this entry point is not protected by TLS; on-path observers may be able to read or alter the connection.",
                    remediation="Redirect HTTP requests to HTTPS and configure TLS for the intended host before enabling a strict transport policy.",
                )
            content_type = response.get("content-type", "").lower()
            is_html = "text/html" in content_type or "application/xhtml" in content_type
            if is_html:
                self._check_headers_and_cookies(response)
            content_encoding = response.get("content-encoding", "").lower().strip()
            if content_encoding not in {"", "identity"}:
                self.result.warnings.append("A compressed response was not decompressed; content-based checks for that response are incomplete.")
                continue
            if self._looks_like_directory_listing(response.body):
                self._add(
                    title="Public directory listing observed",
                    category="directory-listing",
                    severity="medium",
                    finding_status="confirmed",
                    confidence=90,
                    affected_url=response.final_url,
                    evidence="The response contains a standard directory-index heading.",
                    impact="A directory index can reveal names of files and folders that were not intended as a navigable public index.",
                    remediation="Disable directory indexing and serve only explicitly intended public resources.",
                )
            if not is_html:
                continue
            if response.truncated:
                self.result.warnings.append("A page exceeded the response-size limit; only its bounded prefix was inspected.")
            parser = PageParser()
            try:
                parser.feed(response.body.decode("utf-8", "replace"))
            except Exception:
                self.result.warnings.append("One HTML page could not be parsed completely.")
                continue
            for generator in parser.generators:
                if _VERSION.search(generator):
                    generator_version = _VERSION.search(generator).group(0)
                    self._add(
                        title="Page generator version disclosed",
                        category="information-disclosure-generator",
                        severity="info",
                        confidence=70,
                        affected_url=response.final_url,
                        evidence=f"A public HTML meta tag contains a generator version pattern ({generator_version}). The full tag value was not retained.",
                        impact="Generator details can assist technology identification but do not by themselves confirm a vulnerability.",
                        remediation="Avoid publishing unnecessary version details and keep the underlying platform updated.",
                    )
            self._check_component_versions(parser, response.final_url)
            self._check_public_file_links(parser, response.final_url)
            if depth < 2:
                for href in parser.links:
                    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                        continue
                    try:
                        candidate = urljoin(response.final_url, html.unescape(href))
                        parsed = urlsplit(candidate)
                        # Query parameters are deliberately not followed or stored.
                        if parsed.query or parsed.fragment:
                            continue
                        next_target = validate_target_url(candidate, self.path_scope, resolve_dns=False)
                    except TargetValidationError as exc:
                        if "secret tokens" in str(exc):
                            self.result.warnings.append("A token-like path link was not followed to avoid transmitting or retaining possible secrets.")
                        continue
                    except ValueError:
                        continue
                    if next_target.hostname != self.hostname or next_target.url in queued or next_target.url in visited:
                        continue
                    if urlsplit(response.final_url).scheme == "https" and next_target.scheme != "https":
                        continue
                    if not is_path_in_scope(next_target.path, self.path_scope):
                        continue
                    queued.add(next_target.url)
                    queue.append((next_target.url, depth + 1))

        if queue and len(visited) >= self.max_pages:
            self.result.warnings.append("The configured page limit was reached; additional in-scope pages were not tested.")
        if time.monotonic() >= deadline:
            self.result.warnings.append("The configured scan time limit was reached; remaining checks were not tested.")
        if not self.result.pages_scanned:
            self.result.warnings.append("No in-scope page response could be inspected; findings may be incomplete.")

        self._check_cancelled()
        # If the user supplied an HTTP URL that did not upgrade via redirect,
        # make one bounded HTTPS request to assess whether the same path supports
        # verified TLS. This is a normal GET, with the same scope and rate limits.
        if self.target.scheme == "http" and not self.result.tls.get("https_reached"):
            parts = urlsplit(self.target.url)
            https_url = urlunsplit(("https", parts.netloc, parts.path or "/", "", ""))
            try:
                secure_response = self.client.fetch(https_url, max_redirects=2)
                if urlsplit(secure_response.final_url).scheme == "https":
                    self.result.tls = {"https_reached": True, "certificate_valid": True, "protocol": secure_response.tls_version}
                    secure_type = secure_response.get("content-type", "").lower()
                    if "text/html" in secure_type or "application/xhtml" in secure_type:
                        self._check_headers_and_cookies(secure_response)
                else:
                    self.result.warnings.append("HTTPS did not reach a verified in-scope endpoint; transport coverage is incomplete.")
            except TLSVerificationError as exc:
                self._add(
                    title="HTTPS certificate validation failed",
                    category="invalid-tls-certificate",
                    severity="high",
                    finding_status="confirmed",
                    confidence=95,
                    affected_url=exc.target_url,
                    evidence="The HTTPS endpoint did not pass the scanner's standard certificate validation.",
                    impact="Browsers may warn users or fail to establish an authenticated, confidential connection to this endpoint.",
                    remediation="Install a valid certificate for the host, serve the required intermediate chain, and correct certificate validity or name issues.",
                )
                self.result.warnings.append("HTTPS content was not crawled because certificate validation failed.")
            except SafeScanError:
                self.result.warnings.append("The HTTPS endpoint could not be reached safely; TLS settings are inconclusive.")

        if not self.result.tls.get("https_reached"):
            self.result.warnings.append("TLS configuration could not be assessed because no verified HTTPS response was observed.")
        self.progress(76, "Summarizing passive checks")
        self._check_cancelled()
        self._check_dns()

        self._check_cancelled()
        # OWASP ZAP Baseline is an optional passive-only augmentation. It runs only
        # for root scope, under the worker's hard timeout and egress allowlist.
        if settings.zap_enabled:
            if self.path_scope != "/":
                self.result.warnings.append("OWASP ZAP Baseline was not run because the configured non-root path scope cannot be represented safely by the current adapter.")
            elif self.zap_runner is None:
                self.result.warnings.append("OWASP ZAP Baseline is enabled but no isolated runner is configured; custom passive checks completed.")
            else:
                self.progress(88, "Running bounded OWASP ZAP Baseline passive checks")
                try:
                    zap_findings, zap_warnings = self.zap_runner(
                        self.scan_id, self.target.url, self.hostname, self.path_scope, settings.proxy_url, settings.proxy_key
                    )
                    for finding in zap_findings:
                        if not is_path_in_scope(urlsplit(finding.affected_url).path or "/", self.path_scope):
                            continue
                        if urlsplit(finding.affected_url).hostname != self.hostname:
                            continue
                        fingerprint = finding.fingerprint or hashlib.sha256(f"{finding.category}|{safe_report_url(finding.affected_url)}|{finding.title}".encode()).hexdigest()
                        if fingerprint in self._seen_findings:
                            continue
                        self._seen_findings.add(fingerprint)
                        self.result.findings.append(finding)
                    self.result.warnings.extend(zap_warnings)
                    if not zap_warnings:
                        self.result.tested_areas.append("OWASP ZAP Baseline passive rules (bounded)")
                except Exception:
                    self.result.warnings.append("OWASP ZAP Baseline did not complete; its checks are inconclusive.")
        self.progress(96, "Finalizing the report")
        # Keep deterministic, unique warnings and list sizes safe for persistence.
        self.result.warnings = list(dict.fromkeys(self.result.warnings))[:30]
        self.result.tested_areas = list(dict.fromkeys(self.result.tested_areas))[:20]
        return self.result

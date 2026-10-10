from __future__ import annotations

from urllib.parse import urlsplit

import pytest

import app.scanner as scanner_module
from app.security import TargetValidationError
from app.scanner import (
    FetchResult,
    PageParser,
    PassiveScanner,
    SafeHttpClient,
    classify_severity,
    _known_fixed_version,
)
from app.security import validate_target_url


class FakeResponse:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self._headers = headers or []
        self._body = body

    def getheaders(self):
        return self._headers

    def getheader(self, name, default=None):
        return next((value for key, value in self._headers if key.lower() == name.lower()), default)

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]

    def close(self):
        pass


def test_severity_classification_normalizes_custom_and_zap_risks():
    assert classify_severity("invalid-tls-certificate") == "high"
    assert classify_severity("directory-listing") == "medium"
    assert classify_severity("cookie-secure") == "low"
    assert classify_severity("zap-10020", 3) == "high"
    assert classify_severity("zap-10020", 0) == "info"


def test_bootstrap_advisory_uses_major_specific_fixed_versions():
    assert _known_fixed_version("bootstrap", (3, 3, 7)) == (3, 4, 1)
    assert _known_fixed_version("bootstrap", (3, 4, 1)) is None
    assert _known_fixed_version("bootstrap", (4, 3, 0)) == (4, 3, 1)
    assert _known_fixed_version("bootstrap", (5, 0, 0)) is None


def test_parser_extracts_inert_links_and_component_hints_without_execution():
    parser = PageParser()
    parser.feed('''<html><head><meta name="generator" content="CMS 4.2"></head>
      <body><a href="/app/page">Next</a><script src="https://cdn.example.com/jquery/3.4.1/jquery.min.js"></script></body></html>''')
    assert parser.links == ["/app/page"]
    assert parser.script_sources == ["https://cdn.example.com/jquery/3.4.1/jquery.min.js"]
    assert parser.generators == ["CMS 4.2"]


def test_client_blocks_off_host_redirects_and_follows_only_validated_same_host(monkeypatch):
    target = validate_target_url("https://example.com/app/start", "/app")
    client = SafeHttpClient(hostname="example.com", path_scope="/app", scan_id="scan-1", proxy_url=None, proxy_key=None)
    monkeypatch.setattr(scanner_module.time, "sleep", lambda _seconds: None)
    requested = []

    def fake_get(request_target):
        requested.append(request_target.url)
        if len(requested) == 1:
            return FakeResponse(302, [("Location", "https://other.example.net/app/home")]), None, None
        return FakeResponse(200, [("Content-Type", "text/html")], b"<html></html>"), "TLSv1.3", None

    monkeypatch.setattr(client, "_single_get", fake_get)
    result = client.fetch(target.url)
    assert result.blocked_redirect is True
    assert requested == ["https://example.com/app/start"]


def test_client_follows_same_host_redirect_but_rejects_path_escape(monkeypatch):
    target = validate_target_url("https://example.com/app/start", "/app")
    client = SafeHttpClient(hostname="example.com", path_scope="/app", scan_id="scan-2", proxy_url=None, proxy_key=None)
    monkeypatch.setattr(scanner_module.time, "sleep", lambda _seconds: None)
    requested = []

    def fake_get(request_target):
        requested.append(request_target.url)
        if len(requested) == 1:
            return FakeResponse(302, [("Location", "settings")]), None, None
        return FakeResponse(200, [("Content-Type", "text/html")], b"ok"), "TLSv1.3", None

    monkeypatch.setattr(client, "_single_get", fake_get)
    result = client.fetch(target.url)
    assert result.status_code == 200
    assert result.final_url == "https://example.com/app/settings"
    assert requested == ["https://example.com/app/start", "https://example.com/app/settings"]

    outside = SafeHttpClient(hostname="example.com", path_scope="/app", scan_id="scan-3", proxy_url=None, proxy_key=None)
    monkeypatch.setattr(outside, "_single_get", lambda _target: (FakeResponse(302, [("Location", "../../private")]), None, None))
    escaped = outside.fetch(target.url)
    assert escaped.blocked_redirect is True


def test_path_scope_enforced_before_any_http_request(monkeypatch):
    target = validate_target_url("https://example.com/app/start", "/app")
    client = SafeHttpClient(hostname="example.com", path_scope="/app", scan_id="scan-4", proxy_url=None, proxy_key=None)
    called = False

    def should_not_run(_target):
        nonlocal called
        called = True
        raise AssertionError("off-scope requests must not be sent")

    monkeypatch.setattr(client, "_single_get", should_not_run)
    with pytest.raises(TargetValidationError):
        client.fetch("https://example.com/application/private")
    assert not called


def test_detects_outdated_library_as_potential_not_confirmed(monkeypatch):
    target = validate_target_url("https://example.com/", "/")
    scanner = PassiveScanner(scan_id="scan-5", target=target, max_pages=2, dns_checker=lambda _host: {
        "dnssec_ds": True, "caa": True, "spf": True, "dmarc": True,
    })
    parser = PageParser()
    parser.feed('<script src="/assets/jquery-3.4.1.min.js"></script>')
    scanner._check_component_versions(parser, target.url)
    assert len(scanner.result.findings) == 1
    finding = scanner.result.findings[0]
    assert finding.finding_status == "potential"
    assert finding.severity == "medium"
    assert "3.4.1" in finding.evidence

from __future__ import annotations

import socket

import pytest

from app.security import (
    TargetValidationError,
    is_path_in_scope,
    is_public_ip,
    normalize_redirect_url,
    resolve_public_addresses,
    safe_report_url,
    validate_target_url,
)


def test_http_and_https_are_canonicalized_and_scoped():
    result = validate_target_url("HTTPS://Example.COM:443/app/home", "/app")
    assert result.url == "https://example.com/app/home"
    assert result.hostname == "example.com"
    assert result.path_scope == "/app"

    http = validate_target_url("http://example.com", "/")
    assert http.url == "http://example.com/"
    assert http.port == 80


@pytest.mark.parametrize("url", [
    "ftp://example.com/",
    "file:///etc/passwd",
    "https://user:pass@example.com/",
    "https://example.com/path?token=private",
    "https://example.com/path#fragment",
    "https://example.com:8443/",
    "https://localhost/",
    "http://127.0.0.1/",
    "http://10.0.0.7/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "https://public.example.com/%2e%2e/admin",
    "https://public.example.com/a%2fb",
])
def test_rejects_malformed_or_prohibited_target_urls(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, "/")


def test_public_ip_and_hostname_are_accepted_without_dangerous_dns_side_effects():
    assert validate_target_url("https://8.8.8.8/", "/").hostname == "8.8.8.8"
    assert is_public_ip("8.8.8.8")
    for address in ("127.0.0.1", "10.10.0.1", "169.254.1.1", "192.168.0.1", "224.0.0.1", "203.0.113.5"):
        assert not is_public_ip(address)


def test_dns_resolution_rejects_any_mixed_or_rebound_private_answer():
    def rebinding_resolver(host, port, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    with pytest.raises(TargetValidationError, match="prohibited"):
        resolve_public_addresses("public-site.example.com", 443, resolver=rebinding_resolver)


def test_secret_like_path_values_are_rejected_or_redacted():
    token_path = "https://example.com/reset-password/Abcdefghijklmnopqrstuvwxyz012345"
    with pytest.raises(TargetValidationError, match="secret tokens"):
        validate_target_url(token_path, "/")
    displayed = safe_report_url(token_path)
    assert "Abcdefghijklmnopqrstuvwxyz012345" not in displayed
    assert "redacted" in displayed


def test_dns_resolution_returns_only_validated_public_addresses():
    def resolver(host, port, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    assert resolve_public_addresses("public-site.example.com", 443, resolver=resolver) == ["8.8.8.8"]


def test_path_scope_uses_segment_boundaries_and_blocks_traversal():
    assert is_path_in_scope("/app", "/app")
    assert is_path_in_scope("/app/users/list", "/app")
    assert not is_path_in_scope("/application", "/app")
    assert not is_path_in_scope("/app/%2e%2e/admin", "/app")
    assert not is_path_in_scope("/private", "/app")

    with pytest.raises(TargetValidationError):
        validate_target_url("https://example.com/application", "/app")


def test_redirects_are_revalidated_for_host_scheme_and_path_scope():
    allowed = normalize_redirect_url("settings", "https://example.com/app/start", "/app", "example.com")
    assert allowed.url == "https://example.com/app/settings"

    with pytest.raises(TargetValidationError):
        normalize_redirect_url("../../admin", "https://example.com/app/start", "/app", "example.com")
    with pytest.raises(TargetValidationError):
        normalize_redirect_url("https://other.example.net/app", "https://example.com/app/start", "/app", "example.com")
    with pytest.raises(TargetValidationError):
        normalize_redirect_url("http://example.com/app/", "https://example.com/app/start", "/app", "example.com")
